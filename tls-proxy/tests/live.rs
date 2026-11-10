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
//! `LIVE_PUBLIC` (e.g. `login.airma.de`) makes the harness walk the public
//! attestation list, discover which id this session's digests unlock, and print
//! the full download URL — no hand-built query string, and no need to compute the
//! digests yourself.
//!
//! `LIVE_ATTEMPTS` (default 3) retries a session that ends before a verdict.
//! That is insurance, not the expected path: a real site's edge will sometimes
//! close while the relayed TLS handshake is still in flight, because every MPC
//! round costs a prover↔notary round trip. The 33 KB
//! `www.sandbox.paypal.com/signin` page was once measured at 2 failures in 3
//! runs, but the current figure is **6 of 6 first-attempt passes** (2026-11-09,
//! 11.4–15.3 s; HANDOVER §0.31), so a retry here means something changed at
//! the edge — read the reported attempt number rather than assuming flakiness.
//!
//! On success the harness prints the digest pair the record signs over
//! (`sent_sha256`, `received_sha256`) — that pair is the capability a prover
//! presents to `GET https://<domain>/proxy/attestations/<id>?sent_sha256=…&\
//! received_sha256=…` to fetch their own attestation from a machine that is not
//! the VM (v222). The notary itself only ever sees the digests.
//!
//! The prover is the same shape as `tests/session.rs`, minus the fixture: the
//! root store comes from the host bundle, so the relayed certificate has to
//! chain to a real public CA exactly as a browser's would.

use std::{
    future::IntoFuture,
    time::{Duration, Instant},
};

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

/// One attempt: a fresh session to the notary, one request, one proof.
///
/// Everything that can be left behind by a failed attempt — the session
/// driver, the relayed socket — is created inside this function, so a retry
/// starts from a clean slate instead of sharing a half-closed session.
async fn one_session(
    notary: &str,
    server: &str,
    path: &str,
    roots: Vec<CertificateDer>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    // Timings, because where a session spends its ~1 minute decides whether an
    // edge-side close is a race we can win or a wall: commit is one exchange,
    // the handshake is many, the proof is pure compute.
    let t0 = Instant::now();
    let lap = |what: &str| eprintln!("[{:>6.1}s] {what}", t0.elapsed().as_secs_f64());

    let socket = TcpStream::connect(notary).await?;
    socket.set_nodelay(true)?;
    lap(&format!("connected to notary {notary}; committing {server}"));

    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            ProxyTlsConfig::builder()
                .server_name(DnsName::try_from(server)?)
                .build()?,
        )
        .await?;
    lap(&format!("commit accepted — the notary is relaying TLS to {server}"));

    let (tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(server.try_into()?))
            .root_store(RootCertStore { roots })
            .build()?,
    )?;
    lap("relayed TLS handshake started");

    let tls_connection = TokioIo::new(tls_connection.compat());
    let prover_task = tokio::spawn(prover.into_future());

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;
    tokio::spawn(connection);

    let request = Request::builder()
        .uri(format!("https://{server}{path}"))
        .header("Host", server)
        .header("Connection", "close")
        .method("GET")
        .body(Empty::<Bytes>::new())?;
    let response = tokio::time::timeout(Duration::from_secs(120), request_sender.send_request(request))
        .await??;
    lap(&format!("relayed response status: {}", response.status()));

    let mut prover = prover_task.await??;
    let sent_bytes = prover.transcript().sent().to_vec();
    let received_bytes = prover.transcript().received().to_vec();
    let sent = sent_bytes.len();
    let received = received_bytes.len();
    lap(&format!("transcript: sent {sent} B, received {received} B"));
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
    driver_task.await??;    // The record is fetched from outside the box by whoever holds the revealed
    // transcript; these are the two digests it signs over, so print them here —
    // the prover is the only party that can compute them, and this harness just
    // proved it is one.
    let (sent_digest, received_digest) = {
        use sha2::{Digest, Sha256};
        let hex = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
        let pair = (hex(&sent_bytes), hex(&received_bytes));
        eprintln!(
            "    capability: sent_sha256={} received_sha256={}",
            pair.0, pair.1
        );
        pair
    };
    lap("prover finished: presentation complete");

    Ok((sent_digest, received_digest))
}

/// Ask the deployed origin which of its ids these digests unlock, and hand back
/// the clickable download URL.
///
/// The notary cannot tell a prover their id: the list is public and the record is
/// keyed by a capability only the prover holds. So the prover does the obvious
/// thing — walk the list and try its own pair, which succeeds for exactly one
/// session. Best effort on purpose: this test exists to prove the relay, and an
/// origin that is unreachable should say so rather than fail the session it just
/// notarised.
async fn public_fetch_url(
    origin: &str,
    sent: &str,
    received: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Accept either form: `LIVE_PUBLIC=login.airma.de` and
    // `LIVE_PUBLIC=https://login.airma.de` both mean the same origin. Before
    // v236 a full URL became `https://https//…` and the harness reported a
    // nonsense connect error instead of printing the download link.
    let origin = origin.trim_end_matches('/');
    let base = if origin.contains("://") {
        origin.to_string()
    } else {
        format!("https://{origin}")
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let list: serde_json::Value = client
        .get(format!("{base}/proxy/attestations"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let ids: Vec<String> = list["sessions"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|r| r["session_id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    for id in ids.iter().rev() {
        let url = format!(
            "{base}/proxy/attestations/{id}?sent_sha256={sent}&received_sha256={received}"
        );
        if client.get(&url).send().await?.status() == reqwest::StatusCode::OK {
            return Ok(url);
        }
    }
    Err(format!(
        "no session on {base} accepts this transcript ({} listed)",
        ids.len()
    )
    .into())
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
    let attempts: u32 = std::env::var("LIVE_ATTEMPTS")
        .ok()
        .and_then(|n| n.parse().ok())
        .filter(|n: &u32| *n > 0)
        .unwrap_or(3);

    let roots = roots_from_bundle(&ca_bundle)?;
    assert!(!roots.is_empty(), "{ca_bundle} had no certificates");

    for attempt in 1..=attempts {
        eprintln!("--- attempt {attempt}/{attempts}: {server}{path}");
        match one_session(&notary, &server, &path, roots.clone()).await {
            Ok((sent, received)) => {
                if attempt > 1 {
                    eprintln!("--- passed on attempt {attempt}/{attempts}");
                }
                if let Ok(origin) = std::env::var("LIVE_PUBLIC") {
                    match public_fetch_url(&origin, &sent, &received).await {
                        Ok(url) => eprintln!("    fetch your record: {url}"),
                        Err(e) => eprintln!("    fetch url unavailable: {e}"),
                    }
                } else {
                    eprintln!(
                        "    set LIVE_PUBLIC=<domain> to have this harness print the \
                         ready-to-open download URL"
                    );
                }
                return Ok(());
            }
            Err(e) => {
                // The expected shape: the site's edge closes mid-handshake or
                // mid-response, and the notary logs "failed to receive proxy
                // finished message". A refusal of OURS (an over-8-MiB
                // transcript, a non-proxy commit) fails the same way, so the
                // message is kept verbatim in the report.
                eprintln!("--- attempt {attempt}/{attempts} failed: {e}");
                if attempt == attempts {
                    return Err(format!(
                        "no verdict in {attempts} attempt(s); last error: {e}"
                    )
                    .into());
                }
                // Let the notary reap the abandoned session before the next
                // one, so the retry is not refused as a concurrent session.
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    unreachable!("the loop returns on the final attempt")
}
