//! Live session against a DEPLOYED tls-proxy — not a hermetic test.
//!
//! Ignored by default because it needs a reachable notary and real internet
//! egress. It exists so "does the deployed proxy actually relay a session of a
//! real website?" is answered by a command instead of an anecdote:
//!
//!   LIVE_NOTARY=101.200.178.251:8443 LIVE_SERVER=api-m.paypal.com \
//!     cargo test --test live -- --ignored --nocapture
//!
//! `LIVE_PATH` (default `/`) picks the request path. The notary authorises a
//! *host*, so the page is the prover's choice: point it at
//! `www.sandbox.paypal.com` with `LIVE_PATH=/checkoutnow` to attest that page
//! rather than the sandbox's bare origin.
//!
//! The prover is the same shape as `tests/session.rs`, minus the fixture: the
//! root store comes from the host bundle, so the relayed certificate has to
//! chain to a real public CA exactly as a browser's would.

use std::{future::IntoFuture, time::Duration};

use http_body_util::Empty;
use hyper::{body::Bytes, Request};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use tlsn::{
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::proxy::ProxyTlsConfig,
    },
    connection::{DnsName, ServerName},
    webpki::{CertificateDer, RootCertStore},
    Session,
};

/// Every certificate in a PEM bundle, as DER. The host bundle is the trust
/// anchor because the notary is deployed, not local: whatever chain the website
/// presents must verify against the real roots.
fn roots_from_bundle(path: &str) -> Result<Vec<CertificateDer>, Box<dyn std::error::Error>> {
    use base64::Engine as _;
    let pem = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for block in pem.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let body = block
            .split("-----END CERTIFICATE-----")
            .next()
            .unwrap_or_default()
            .lines()
            .map(str::trim)
            .collect::<String>();
        if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(body) {
            out.push(CertificateDer(der));
        }
    }
    Ok(out)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a deployed notary and real internet egress"]
async fn live_relay_of_a_real_website() -> Result<(), Box<dyn std::error::Error>> {
    let notary = std::env::var("LIVE_NOTARY").unwrap_or_else(|_| "101.200.178.251:8443".into());
    let server = std::env::var("LIVE_SERVER").unwrap_or_else(|_| "api-m.paypal.com".into());
    let ca_bundle = std::env::var("LIVE_CA_BUNDLE")
        .unwrap_or_else(|_| "/etc/ssl/certs/ca-certificates.crt".into());
    // A host is what the notary authorises; the page is the prover's choice.
    let path = std::env::var("LIVE_PATH").unwrap_or_else(|_| "/".into());
    let path = if path.starts_with('/') { path } else { format!("/{path}") };

    let roots = roots_from_bundle(&ca_bundle)?;
    assert!(!roots.is_empty(), "{ca_bundle} had no certificates");

    let socket = TcpStream::connect(&notary).await?;
    socket.set_nodelay(true)?;
    eprintln!("connected to notary {notary}; committing {server}");

    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            ProxyTlsConfig::builder()
                .server_name(DnsName::try_from(server.as_str())?)
                .build()?,
        )
        .await?;
    eprintln!("commit accepted — the notary is relaying TLS to {server}");

    let (tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(server.as_str().try_into()?))
            .root_store(RootCertStore { roots })
            .build()?,
    )?;
    eprintln!("relayed TLS handshake started");

    let tls_connection = TokioIo::new(tls_connection.compat());
    let prover_task = tokio::spawn(prover.into_future());

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;
    tokio::spawn(connection);

    let request = Request::builder()
        .uri(format!("https://{server}{path}"))
        .header("Host", server.as_str())
        .header("Connection", "close")
        .method("GET")
        .body(Empty::<Bytes>::new())?;
    let response = tokio::time::timeout(Duration::from_secs(120), request_sender.send_request(request))
        .await??;
    eprintln!("relayed response status: {}", response.status());

    let mut prover = prover_task.await??;
    let sent = prover.transcript().sent().len();
    let received = prover.transcript().received().len();
    eprintln!("transcript: sent {sent} B, received {received} B");
    let head = prover.transcript().received();
    eprintln!(
        "response head: {}",
        String::from_utf8_lossy(&head[..head.len().min(160)]).replace("\r\n", " | ")
    );

    let mut builder = ProveConfig::builder(prover.transcript());
    builder.server_identity();
    builder.reveal_sent(&(0..sent))?;
    builder.reveal_recv(&(0..received))?;
    let config = builder.build()?;
    prover.prove(&config).await?;
    prover.close().await?;
    handle.close();
    driver_task.await??;
    eprintln!("prover finished: presentation complete");
    Ok(())
}
