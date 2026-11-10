//! End-to-end test: a real TLSNotary prover against the real `tls-proxy` binary.
//!
//! Nothing here is mocked except the website: tlsn's fixture HTTPS server serves
//! `test-server.io` with its own CA, the test spawns the compiled binary exactly
//! as PID 1 would, and the prover speaks the TLSNotary wire protocol over TCP.
//! What is asserted is what the service is for:
//!
//!   * a proxy-mode session completes and the website's bytes come back;
//!   * the enclave records an attestation naming `test-server.io`;
//!   * the enclave signature verifies over the signed fields (RSA-2048/SHA-256)
//!     with the public key in the response — i.e. an auditor can rebuild the
//!     signed bytes and check them without any shared secret.

use std::{
    future::IntoFuture,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use tls_server_fixture::{bind_test_server_hyper, CA_CERT_DER, SERVER_DOMAIN};
use tlsn::{
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::{MpcTlsConfig, NetworkSetting},
        tls_commit::proxy::ProxyTlsConfig,
    },
    connection::{DnsName, ServerName},
    webpki::{CertificateDer, RootCertStore},
    Session,
};

/// The ten fields the proxy signs, in the order it signs them. Deserializing the
/// attestation into this struct and re-serializing reproduces the exact signed
/// bytes (serde keeps declaration order), which is how an auditor checks it.
#[derive(Debug, Serialize, Deserialize)]
struct SignedBody {
    version: String,
    session_id: String,
    server_name: String,
    notarized_at: u64,
    sent_len: usize,
    received_len: usize,
    sent_sha256: String,
    received_sha256: String,
    sent_b64: String,
    received_b64: String,
    truncated: bool,
}

/// Kills the spawned proxy even when an assertion fails mid-test.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a probe port");
    l.local_addr().expect("probe address").port()
}

fn der_to_pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// A bare HTTP/1.1 GET with `Connection: close`, read to EOF. The API is
/// loopback-only and returns small JSON, so a client library would be noise.
async fn http_get(port: u16, path: &str) -> Result<(u16, String), Box<dyn std::error::Error>> {
    http_send("GET", port, path).await
}

/// `POST` with no body: the drain endpoint takes no arguments, and a body would
/// only give the axum extractor something to reject.
async fn http_post(port: u16, path: &str) -> Result<(u16, String), Box<dyn std::error::Error>> {
    http_send("POST", port, path).await
}

async fn http_send(
    method: &str,
    port: u16,
    path: &str,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    let text = String::from_utf8_lossy(&raw).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Ok((status, body))
}

/// The proxy's tracing writer is stdout, so both streams go to the captured
/// log; a readiness probe must not touch the session port, because every
/// accepted TCP connection is counted as a session.
async fn wait_for_api(port: u16) {
    for _ in 0..100 {
        if http_get(port, "/health").await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the proxy never answered /health on {port}");
}

/// These tests each spawn a proxy and pick ports by bind-and-drop, so they must
/// not run concurrently in one process: two tests can otherwise be handed the
/// same port and the loser silently talks to the winner's proxy.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn wait_for_port(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the proxy never started listening on {port}");
}

/// tlsn's fixture HTTPS server on a loopback port, for tests that need a real
/// TLS session to relay.
async fn start_fixture() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind the fixture");
    let port = listener.local_addr().expect("fixture address").port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = bind_test_server_hyper(stream.compat()).await;
            });
        }
    });
    port
}

/// A proxy started exactly as PID 1 starts it, with stderr captured so a test
/// can assert *why* a session was refused and not merely that it was. Killed and
/// cleaned up on drop.
struct Proxy {
    _child: ChildGuard,
    ca_path: PathBuf,
    log_path: PathBuf,
    session_port: u16,
    api_port: u16,
}

impl Proxy {
    async fn start(extra: &[(&str, &str)]) -> Self {
        let ca_path = std::env::temp_dir().join(format!(
            "tls-proxy-test-ca-{}-{}.pem",
            std::process::id(),
            free_port()
        ));
        std::fs::write(&ca_path, der_to_pem(CA_CERT_DER)).expect("write the CA bundle");
        let log_path = std::env::temp_dir().join(format!(
            "tls-proxy-test-log-{}-{}.log",
            std::process::id(),
            free_port()
        ));
        let log = std::fs::File::create(&log_path).expect("create the proxy log");
        let log_copy = log.try_clone().expect("clone the log handle");

        let session_port = free_port();
        let api_port = free_port();
        let mut command = Command::new(env!("CARGO_BIN_EXE_tls-proxy"));
        command
            .env("TLS_PROXY_LISTEN", format!("127.0.0.1:{session_port}"))
            .env("TLS_PROXY_HTTP_LISTEN", format!("127.0.0.1:{api_port}"))
            .env("TLS_PROXY_CA_BUNDLE", &ca_path)
            .env("TLS_PROXY_SESSION_TIMEOUT", "60")
            // Dial pacing is a property of one edge's burst tolerance and is
            // measured against the live notary; tests would only pay its
            // latency. The tests that are ABOUT pacing set it explicitly.
            .env("TLS_PROXY_DIAL_SPACING_MS", "0")
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_copy));
        // Later calls win, so a test can override any default above.
        for (key, value) in extra {
            command.env(key, value);
        }

        let proxy = Self {
            _child: ChildGuard(command.spawn().expect("spawn the proxy")),
            ca_path,
            log_path,
            session_port,
            api_port,
        };
        wait_for_api(proxy.api_port).await;
        proxy
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }

    async fn health(&self) -> serde_json::Value {
        let (status, body) = http_get(self.api_port, "/health")
            .await
            .expect("health request");
        assert_eq!(status, 200, "health: {body}");
        serde_json::from_str(&body).expect("health is JSON")
    }

    /// The refusal log the operator reads: newest last, with the reason.
    async fn refusals(&self) -> serde_json::Value {
        let (status, body) = http_get(self.api_port, "/refusals")
            .await
            .expect("refusals request");
        assert_eq!(status, 200, "refusals: {body}");
        serde_json::from_str(&body).expect("refusals is JSON")
    }

    /// Waits for the failed-session counter to reach `want`, so a test never
    /// races the session task that is still unwinding.
    async fn wait_for_failed(&self, want: u64) -> serde_json::Value {
        let mut health = self.health().await;
        for _ in 0..100 {
            if health["sessions_failed"].as_u64().unwrap_or(0) >= want {
                return health;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
            health = self.health().await;
        }
        panic!(
            "sessions_failed never reached {want}: {health}\nproxy log:\n{}",
            self.logs()
        );
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.ca_path);
        let _ = std::fs::remove_file(&self.log_path);
    }
}

/// The prover half, mirroring tlsn's proxy example: commit to a proxy-mode
/// session, do the HTTP request through the relayed TLS connection, then prove
/// with the server identity and the whole transcript revealed.
async fn prover(socket: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            ProxyTlsConfig::builder()
                .server_name(DnsName::try_from(SERVER_DOMAIN)?)
                .build()?,
        )
        .await?;

    let (tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(SERVER_DOMAIN.try_into()?))
            .root_store(RootCertStore {
                roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
            })
            .build()?,
    )?;
    let tls_connection = TokioIo::new(tls_connection.compat());
    let prover_task = tokio::spawn(prover.into_future());

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;
    tokio::spawn(connection);

    let request = Request::builder()
        .uri(format!("https://{SERVER_DOMAIN}/"))
        .header("Host", SERVER_DOMAIN)
        .header("Connection", "close")
        .method("GET")
        .body(Empty::<Bytes>::new())?;
    let response = request_sender.send_request(request).await?;
    assert_eq!(response.status(), StatusCode::OK, "fixture server response");

    let mut prover = prover_task.await??;
    let mut builder = ProveConfig::builder(prover.transcript());
    builder.server_identity();
    let sent = prover.transcript().sent().len();
    let received = prover.transcript().received().len();
    builder.reveal_sent(&(0..sent))?;
    builder.reveal_recv(&(0..received))?;
    let config = builder.build()?;

    prover.prove(&config).await?;
    prover.close().await?;
    handle.close();
    driver_task.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attests_a_real_tls_session_end_to_end() -> Result<(), Box<dyn std::error::Error>> {
    let _serial = SERIAL.lock().await;

    // 1. The website: tlsn's fixture HTTPS server, certificate for test-server.io.
    let fixture_port = start_fixture().await;

    // 2. Trust anchor for the proxy: the fixture CA as a PEM bundle, since the
    //    proxy validates whatever host the commit names (production: the distro
    //    bundle; here: this one root).
    let ca_path =
        std::env::temp_dir().join(format!("tls-proxy-test-ca-{}.pem", std::process::id()));
    std::fs::write(&ca_path, der_to_pem(CA_CERT_DER))?;

    // 3. The service under test: the compiled binary, started the way PID 1
    //    starts it (env only, no args).
    let session_port = free_port();
    let api_port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_tls-proxy"))
        .env("TLS_PROXY_LISTEN", format!("127.0.0.1:{session_port}"))
        .env("TLS_PROXY_HTTP_LISTEN", format!("127.0.0.1:{api_port}"))
        .env("TLS_PROXY_CA_BUNDLE", &ca_path)
        // Test-only pin: the fixture cert says test-server.io but nothing
        // resolves that to loopback in this sandbox.
        .env("TLS_PROXY_TARGET_ADDR", format!("127.0.0.1:{fixture_port}"))
        .env("TLS_PROXY_SESSION_TIMEOUT", "60")
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    let _guard = ChildGuard(child);
    wait_for_port(session_port).await;

    // 4. Health is up and no attestation exists yet.
    let (status, body) = http_get(api_port, "/health").await?;
    assert_eq!(status, 200, "health: {body}");
    let health: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(health["service"], "tls-proxy");
    assert_eq!(health["attestations"], 0);
    let (status, _) = http_get(api_port, "/attestations/does-not-exist").await?;
    assert_eq!(status, 404, "an unknown session id must not invent evidence");

    // 5. A real session.
    let socket = TcpStream::connect(("127.0.0.1", session_port)).await?;
    prover(socket).await?;

    // 6. The attestation exists, names the site, and its signature verifies.
    let mut attestation = None;
    for _ in 0..100 {
        let (_, body) = http_get(api_port, "/attestations").await?;
        let list: serde_json::Value = serde_json::from_str(&body)?;
        if list["count"].as_u64().unwrap_or(0) > 0 {
            let id = list["sessions"][0]["session_id"]
                .as_str()
                .expect("session_id")
                .to_string();
            let (status, one) = http_get(api_port, &format!("/attestations/{id}")).await?;
            assert_eq!(status, 200);
            // v221: the SERVED TEXT must carry the signed fields in the SIGNED
            // order. The auditor page rebuilds the signed bytes from exactly
            // this text, so a proxy that serves them re-serialised through
            // `serde_json::Value` (alphabetical) makes every real attestation
            // unverifiable — which is what shipped until this was fixed. This
            // check deliberately reads bytes, not a parsed struct: parsing into
            // the typed body restores the order and hides the defect.
            const SIGNED_ORDER: [&str; 14] = [
                "\"version\"", "\"session_id\"", "\"server_name\"", "\"notarized_at\"",
                "\"sent_len\"", "\"received_len\"", "\"sent_sha256\"", "\"received_sha256\"",
                "\"sent_b64\"", "\"received_b64\"", "\"truncated\"", "\"enclave_pubkey_pem\"",
                "\"signature_alg\"", "\"signature_b64\"",
            ];
            let mut cursor = 0usize;
            for field in SIGNED_ORDER {
                let at = one[cursor..]
                    .find(field)
                    .map(|p| p + cursor)
                    .unwrap_or_else(|| panic!("{field} missing from the served attestation"));
                cursor = at + field.len();
            }
            // And the signature must verify over the byte range the page will
            // cut out of that same text: the body, up to the envelope.
            let envelope_at = one.find(",\"enclave_pubkey_pem\"").expect("flattened envelope");
            let mut served_signed = one[..envelope_at].to_string();
            served_signed.push('}');
            let served: serde_json::Value = serde_json::from_str(&one)?;
            let served_pubkey = openssl::pkey::PKey::public_key_from_pem(
                served["enclave_pubkey_pem"].as_str().expect("pubkey").as_bytes(),
            )?;
            let mut served_verifier =
                openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &served_pubkey)?;
            served_verifier.update(served_signed.as_bytes())?;
            let served_sig = base64::engine::general_purpose::STANDARD
                .decode(served["signature_b64"].as_str().expect("signature"))?;
            assert!(
                served_verifier.verify(&served_sig)?,
                "the signature must verify over the bytes the API actually serves"
            );
            attestation = Some(served);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let attestation = attestation.expect("the proxy should have stored an attestation");

    assert_eq!(attestation["server_name"], SERVER_DOMAIN);
    assert_eq!(attestation["version"], "tls-proxy/1");
    assert!(
        attestation["sent_len"].as_u64().unwrap_or(0) > 0,
        "the request bytes should be in the transcript"
    );
    assert!(
        attestation["received_len"].as_u64().unwrap_or(0) > 0,
        "the response bytes should be in the transcript"
    );
    assert_eq!(
        attestation["received_sha256"].as_str().unwrap_or("").len(),
        64
    );

    let signed: SignedBody = serde_json::from_value(attestation.clone())?;
    let signed_bytes = serde_json::to_vec(&signed)?;
    let pubkey = openssl::pkey::PKey::public_key_from_pem(
        attestation["enclave_pubkey_pem"]
            .as_str()
            .expect("pubkey")
            .as_bytes(),
    )?;
    let mut verifier = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &pubkey)?;
    verifier.update(&signed_bytes)?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(attestation["signature_b64"].as_str().expect("signature"))?;
    assert!(
        verifier.verify(&signature)?,
        "the enclave signature must verify over the ten signed fields"
    );

    // 6b. The key that signed this record is the one `/pubkey` names, and the
    // fingerprint it advertises is the SHA-256 of the SPKI DER — the value the
    // enclave recomputes and publishes inside its quoted report, and the value
    // `verify-proxy.html` derives from `enclave_pubkey_pem`. All three must be
    // the same number, or the record's key is not the one the quote covers.
    let (status, pub_body) = http_get(api_port, "/pubkey").await?;
    assert_eq!(status, 200, "pubkey: {pub_body}");
    let pubkey_doc: serde_json::Value = serde_json::from_str(&pub_body)?;
    assert_eq!(pubkey_doc["service"], "tls-proxy");
    assert_eq!(
        pubkey_doc["pubkey_pem"].as_str().unwrap_or(""),
        attestation["enclave_pubkey_pem"].as_str().unwrap_or("<none>"),
        "/pubkey must name the exact key that signs records"
    );
    use sha2::Digest as _;
    let der = pubkey.public_key_to_der()?;
    let expected_fp: String = sha2::Sha256::digest(&der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        pubkey_doc["pubkey_sha256"].as_str().unwrap_or(""),
        expected_fp,
        "the advertised fingerprint must be SHA-256 over the SPKI DER"
    );

    // 7. Tampering is detectable: one changed byte must break that signature.
    let mut tampered = signed_bytes.clone();
    tampered[0] ^= 0x01;
    let mut verifier = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &pubkey)?;
    verifier.update(&tampered)?;
    assert!(!verifier.verify(&signature)?, "a mutated body must not verify");

    let _ = std::fs::remove_file(&ca_path);
    Ok(())
}

/// The prover half of an MPC commit — the mode this notary refuses. No fixture
/// website is involved: the refusal happens at commit time, before any TLS.
async fn mpc_prover(socket: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let prover = handle.new_prover(ProverConfig::builder().build()?)?;
    let commit = tokio::time::timeout(
        Duration::from_secs(10),
        // MPC mode has no server name to commit: the mode cannot say which
        // site the session is about, which is exactly why it is refused. The
        // data limits are part of a well-formed MPC config, so this is a
        // request the notary could in principle accept did it implement MPC.
        prover.commit(
            MpcTlsConfig::builder()
                .network(NetworkSetting::Latency)
                .max_sent_data(4096)
                .max_recv_data(4096)
                .build()?,
        ),
    )
    .await
    .map_err(|_| "the proxy never answered the MPC commit")?;

    handle.close();
    let _ = tokio::time::timeout(Duration::from_secs(5), driver_task).await;

    commit?;
    Err("the proxy accepted an MPC commit; it must refuse MPC mode".into())
}

/// MPC is refused rather than silently notarised: the enclave does not run the
/// 2PC that mode needs, so it must answer with a rejection and record nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuses_an_mpc_commit() -> Result<(), Box<dyn std::error::Error>> {
    let _serial = SERIAL.lock().await;
    let proxy = Proxy::start(&[]).await;
    let socket = TcpStream::connect(("127.0.0.1", proxy.session_port)).await?;

    let outcome = mpc_prover(socket).await;
    let refusal = match &outcome {
        Err(e) => e.to_string(),
        Ok(()) => String::new(),
    };
    assert!(
        outcome.is_err(),
        "an MPC commit must be rejected, not accepted by the verifier"
    );
    let health = proxy.wait_for_failed(1).await;
    assert_eq!(health["sessions_ok"].as_u64(), Some(0), "nothing was verified");
    assert_eq!(
        health["attestations"].as_u64(),
        Some(0),
        "a refused session must leave no attestation behind"
    );

    let logs = proxy.logs();
    assert!(
        logs.contains("MPC mode"),
        "the refusal must be logged as the MPC refusal (prover saw: {refusal}), got: {logs}"
    );

    // And the operator can read the same reason without the boot log.
    let refusals = proxy.refusals().await;
    assert_eq!(refusals["count"].as_u64(), Some(1));
    assert_eq!(refusals["refusals"][0]["kind"], "rejected");
    assert!(
        refusals["refusals"][0]["reason"]
            .as_str()
            .unwrap_or("")
            .contains("MPC mode"),
        "the API must carry the reason, got: {refusals}"
    );
    Ok(())
}

/// The prover half of a commit to a host this notary will not relay: proxy
/// mode, a well-formed name, nothing in the boot-time `relay_targets` for it.
async fn unreachable_prover(socket: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let prover = handle.new_prover(ProverConfig::builder().build()?)?;
    let commit = tokio::time::timeout(
        Duration::from_secs(15),
        prover.commit(
            ProxyTlsConfig::builder()
                // `.invalid` is reserved by RFC 2606 and never resolves, so this
                // is exactly the shape of a name outside relay_targets on the
                // real guest, where the resolver is closed after boot.
                .server_name(DnsName::try_from("not-a-relay-target.invalid")?)
                .build()?,
        ),
    )
    .await
    .map_err(|_| "the proxy never answered the commit")?;

    handle.close();
    let _ = tokio::time::timeout(Duration::from_secs(5), driver_task).await;

    commit?;
    Err("the proxy accepted a commit it cannot relay".into())
}

/// v236: a commit this notary cannot relay is answered **in band** with the
/// reason, instead of dropping the connection. The live symptom this fixes was
/// observed on the deployed notary: committing `example.com` gave the prover
/// only `commitment protocol failed to receive response caused by: unexpected
/// end of file`, while the reason existed only in the operator-facing ring.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuses_an_unreachable_commit_with_a_reason() -> Result<(), Box<dyn std::error::Error>> {
    let _serial = SERIAL.lock().await;
    let proxy = Proxy::start(&[]).await;
    let socket = TcpStream::connect(("127.0.0.1", proxy.session_port)).await?;

    let outcome = unreachable_prover(socket).await;
    let refusal = match &outcome {
        Err(e) => e.to_string(),
        Ok(()) => String::new(),
    };
    assert!(
        outcome.is_err(),
        "a host the notary cannot relay must be refused, not accepted"
    );
    assert!(
        refusal.contains("rejected by verifier"),
        "the refusal must travel over the commitment protocol, not be a bare 
         disconnect; the prover saw: {refusal}"
    );
    assert!(
        refusal.contains("relay_targets"),
        "the in-band reason must say what to fix, the prover saw: {refusal}"
    );

    let health = proxy.wait_for_failed(1).await;
    assert_eq!(health["sessions_ok"].as_u64(), Some(0), "nothing was verified");
    assert_eq!(
        health["attestations"].as_u64(),
        Some(0),
        "a refused session must leave no attestation behind"
    );

    // The operator-facing ring carries the same verdict.
    let refusals = proxy.refusals().await;
    assert_eq!(refusals["count"].as_u64(), Some(1));
    assert!(
        refusals["refusals"][0]["reason"]
            .as_str()
            .unwrap_or("")
            .contains("relay_targets"),
        "the API must carry the reason, got: {refusals}"
    );
    Ok(())
}

/// v236: a target whose pinned address never answers is refused in band, and
/// promptly. Before the bounded connect, the session sat until the whole 120 s
/// session timeout and the prover saw only "connection closed before message
/// completed" — observed live against `sandbox.paypal.com` (whose address is
/// whatever the boot resolved for it).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuses_a_commit_whose_target_never_answers() -> Result<(), Box<dyn std::error::Error>> {
    let _serial = SERIAL.lock().await;
    // TEST-NET-1 (RFC 5737) is never routable; whichever way the kernel fails
    // (refused, unreachable, or a blackhole the bounded connect cuts off), the
    // verdict has to reach the prover.
    let proxy = Proxy::start(&[("TLS_PROXY_TARGET_ADDR", "192.0.2.1:443")]).await;
    let socket = TcpStream::connect(("127.0.0.1", proxy.session_port)).await?;

    let started = std::time::Instant::now();
    let outcome = unreachable_prover(socket).await;
    let elapsed = started.elapsed();
    let refusal = match &outcome {
        Err(e) => e.to_string(),
        Ok(()) => String::new(),
    };
    assert!(outcome.is_err(), "a dead target must be refused");
    assert!(
        refusal.contains("rejected by verifier"),
        "the refusal must travel over the commitment protocol, the prover saw: {refusal}"
    );
    assert!(
        elapsed < Duration::from_secs(30),
        "a dead target must be refused promptly, took {elapsed:?}: {refusal}"
    );

    let health = proxy.wait_for_failed(1).await;
    assert_eq!(health["sessions_ok"].as_u64(), Some(0), "nothing was verified");
    assert_eq!(
        health["attestations"].as_u64(),
        Some(0),
        "a refused session must leave no attestation behind"
    );
    Ok(())
}

/// An honest session whose transcript exceeds the bound is still refused
/// before signing: the bound exists so one prover cannot size the guest's RAM.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_transcript_over_the_size_bound() -> Result<(), Box<dyn std::error::Error>> {
    let _serial = SERIAL.lock().await;
    let fixture_port = start_fixture().await;
    let target = format!("127.0.0.1:{fixture_port}");
    // 64 bytes is below any real request+response, so the bound must fire.
    let proxy = Proxy::start(&[
        ("TLS_PROXY_TARGET_ADDR", target.as_str()),
        ("TLS_PROXY_MAX_TRANSCRIPT_BYTES", "64"),
    ])
    .await;

    let socket = TcpStream::connect(("127.0.0.1", proxy.session_port)).await?;
    // Whether the prover sees the refusal or the closed session is not the
    // claim under test; the proxy's verdict and counters are.
    let _ = prover(socket).await;

    let health = proxy.wait_for_failed(1).await;
    assert_eq!(
        health["sessions_ok"].as_u64(),
        Some(0),
        "an oversized transcript must not count as a verified session"
    );
    assert_eq!(
        health["attestations"].as_u64(),
        Some(0),
        "nothing may be signed when the transcript is refused"
    );

    let logs = proxy.logs();
    assert!(
        logs.contains("over the 64-byte bound"),
        "the refusal must name the bound that fired, got: {logs}"
    );

    let refusals = proxy.refusals().await;
    assert_eq!(refusals["refusals"][0]["kind"], "rejected");
    assert!(
        refusals["refusals"][0]["reason"]
            .as_str()
            .unwrap_or("")
            .contains("over the 64-byte bound"),
        "the API must name the bound, got: {refusals}"
    );
    Ok(())
}

/// A peer that opens a session and says nothing must be closed at the timeout,
/// with the attempt counted as failed rather than left in flight forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closes_a_session_that_never_speaks() -> Result<(), Box<dyn std::error::Error>> {
    let _serial = SERIAL.lock().await;
    let proxy = Proxy::start(&[("TLS_PROXY_SESSION_TIMEOUT", "1")]).await;
    let mut socket = TcpStream::connect(("127.0.0.1", proxy.session_port)).await?;

    // Closing the session sends a TLSNotary close message before the socket
    // goes away, so read until EOF (or reset) rather than expecting one read.
    let started = Instant::now();
    let drained = tokio::time::timeout(Duration::from_secs(10), async {
        let mut buf = [0u8; 256];
        loop {
            match socket.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
    })
    .await;
    drained.expect("the proxy held an idle session open past its timeout");
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "closed at {:?}, before the 1 s timeout could have fired",
        started.elapsed()
    );

    let health = proxy.wait_for_failed(1).await;
    assert_eq!(health["sessions_total"].as_u64(), Some(1));
    assert_eq!(health["sessions_ok"].as_u64(), Some(0));
    assert_eq!(health["attestations"].as_u64(), Some(0));

    let logs = proxy.logs();
    assert!(
        logs.contains("no verdict within"),
        "the timeout must be logged, got: {logs}"
    );

    let refusals = proxy.refusals().await;
    assert_eq!(refusals["count"].as_u64(), Some(1));
    assert_eq!(
        refusals["refusals"][0]["kind"], "timeout",
        "an idle peer is a timeout, not a rejected presentation: {refusals}"
    );
    // v237: the timeout names where the session had got to, because "no verdict"
    // alone cannot be told apart from a slow prover, and the address it was
    // relaying to is not re-derivable after the boot-time pin is gone.
    let reason = refusals["refusals"][0]["reason"].as_str().unwrap_or("");
    assert!(
        reason.contains("last progress: before the commitment handshake"),
        "a peer that never committed must be reported at that phase, got: {reason}"
    );
    Ok(())
}

/// The operator's list must name the host a recorded session was about.
///
/// v217 shipped a `list` that read `server_name` from a `body` object which
/// `#[serde(flatten)]` never creates: over HTTP every row was
/// `"server_name": null` while `/attestations/{id}` still carried the host,
/// and the enclave's `/proxy/attestations` — which fingerprints exactly the
/// string this route returns — therefore published no host at all. Unit tests
/// on the projection did not exist, so only a session driven through the real
/// binary over the real API pins this down.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn list_over_http_names_the_host_of_a_recorded_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let _serial = SERIAL.lock().await;
    let fixture_port = start_fixture().await;
    let target = format!("127.0.0.1:{fixture_port}");
    let proxy = Proxy::start(&[("TLS_PROXY_TARGET_ADDR", target.as_str())]).await;

    // Before any session there is nothing to project, and the empty answer is
    // still the documented shape (not `null`).
    let (status, body) = http_get(proxy.api_port, "/attestations").await?;
    assert_eq!(status, 200, "{body}");
    let empty: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(empty["count"], 0, "{body}");
    assert_eq!(empty["sessions"], serde_json::json!([]), "{body}");

    let socket = TcpStream::connect(("127.0.0.1", proxy.session_port)).await?;
    prover(socket).await?;

    let mut row = None;
    for _ in 0..100 {
        let (_, body) = http_get(proxy.api_port, "/attestations").await?;
        let list: serde_json::Value = serde_json::from_str(&body)?;
        if let Some(first) = list["sessions"].as_array().and_then(|s| s.first()) {
            row = Some(first.clone());
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let row = row.expect("the recorded session should be listed");

    // The regression, exactly: a null here is what the operator saw on the
    // live origin, and it is what the enclave would fingerprint into nothing.
    assert_eq!(
        row["server_name"], SERVER_DOMAIN,
        "the list must name the host the session was made against, got: {row}"
    );
    assert!(
        row.get("body").is_none(),
        "the signed body is flattened into the envelope; a nested `body` key is \
         the bug that produced null hosts: {row}"
    );
    let mut keys: Vec<&str> = row
        .as_object()
        .expect("a row is an object")
        .keys()
        .map(|k| k.as_str())
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["notarized_at", "server_name", "session_id"],
        "the list projects three fields and withholds the transcript: {row}"
    );
    assert!(
        row["notarized_at"].as_u64().unwrap_or(0) > 0,
        "an operator needs a time to line the session up with the log: {row}"
    );

    // The list and the detail must agree about the host; v217's symptom was
    // that they disagreed, one null and one named.
    let id = row["session_id"].as_str().expect("session_id");
    let (status, one) = http_get(proxy.api_port, &format!("/attestations/{id}")).await?;
    assert_eq!(status, 200, "{one}");
    let detail: serde_json::Value = serde_json::from_str(&one)?;
    assert_eq!(detail["server_name"], row["server_name"], "{detail}");
    assert_eq!(detail["session_id"], id);

    // The prover's way back in from a machine that is not this VM: the record
    // signs over a digest pair, and presenting that pair is the capability.
    // Asserted against a session recorded by the real binary, because the
    // matcher compares text the store actually holds.
    let sent = detail["sent_sha256"].as_str().expect("sent digest");
    let received = detail["received_sha256"].as_str().expect("received digest");
    let gated = format!("/attestations/{id}?sent_sha256={sent}&received_sha256={received}");
    let (status, same) = http_get(proxy.api_port, &gated).await?;
    assert_eq!(status, 200, "{same}");
    assert_eq!(
        same, one,
        "the gated read must serve the signed bytes verbatim, not a re-encoding"
    );

    // A wrong digest must be indistinguishable from an unknown id: otherwise
    // the endpoint answers "this transcript exists" to anyone guessing.
    let wrong = format!(
        "/attestations/{id}?sent_sha256={sent}&received_sha256={}",
        "0".repeat(64)
    );
    let (status, body) = http_get(proxy.api_port, &wrong).await?;
    assert_eq!(status, 404, "{body}");
    let (status_missing, missing) = http_get(proxy.api_port, "/attestations/does-not-exist").await?;
    assert_eq!(status_missing, status);
    // Same error, same fields: only the id the caller itself supplied differs,
    // so a wrong guess learns nothing it did not already know.
    let guessed: serde_json::Value = serde_json::from_str(&body)?;
    let absent: serde_json::Value = serde_json::from_str(&missing)?;
    assert_eq!(guessed["error"], absent["error"], "{guessed} vs {absent}");
    let keys = |v: &serde_json::Value| {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort_unstable();
        k
    };
    assert_eq!(keys(&guessed), keys(&absent), "the answers must have one shape");
    assert_eq!(guessed["session_id"], id);

    // Half a pair is a client bug, not a capability, and junk is not a digest.
    let (status, body) = http_get(
        proxy.api_port,
        &format!("/attestations/{id}?sent_sha256={sent}"),
    )
    .await?;
    assert_eq!(status, 400, "{body}");
    let (status, _) = http_get(
        proxy.api_port,
        &format!("/attestations/{id}?sent_sha256=zz&received_sha256=zz"),
    )
    .await?;
    assert_eq!(status, 404, "junk must not be treated as a matching digest");
    Ok(())
}

/// Eight sessions at once must all be served: the notary's own concurrency is
/// not the limit, and the live burst failures are the target edge's (see
/// `DEFAULT_DIAL_SPACING_MS`). Pinned locally so a future change that serialises
/// sessions — a shared lock, a single-threaded relay, a global mutex across an
/// await — fails here instead of only on the deployed notary.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn serves_eight_simultaneous_sessions() -> Result<(), Box<dyn std::error::Error>> {
    let _serial = SERIAL.lock().await;
    let fixture_port = start_fixture().await;
    let target = format!("127.0.0.1:{fixture_port}");
    let proxy = Proxy::start(&[("TLS_PROXY_TARGET_ADDR", target.as_str())]).await;

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let socket = TcpStream::connect(("127.0.0.1", proxy.session_port)).await?;
        // The error type is not `Send`; a spawned task only needs the verdict.
        tasks.push(tokio::spawn(async move {
            prover(socket).await.map_err(|e| e.to_string())
        }));
    }
    for (i, task) in tasks.into_iter().enumerate() {
        task.await?
            .map_err(|e| format!("session {i} of 8 failed: {e}"))?;
    }

    let health = proxy.health().await;
    assert_eq!(health["sessions_ok"].as_u64(), Some(8), "{health}");
    assert_eq!(health["sessions_failed"].as_u64(), Some(0), "{health}");
    assert_eq!(health["attestations"].as_u64(), Some(8), "{health}");
    assert_eq!(health["active_sessions"].as_u64(), Some(0), "{health}");
    Ok(())
}

/// Dial pacing must not delay a target other than the one that was just dialled,
/// and must space two sessions to the same address — asserted on the real binary
/// (its log carries the queueing) rather than only on the arithmetic.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paces_repeated_dials_to_the_same_target(
) -> Result<(), Box<dyn std::error::Error>> {
    let _serial = SERIAL.lock().await;
    let fixture_port = start_fixture().await;
    let target = format!("127.0.0.1:{fixture_port}");
    let proxy = Proxy::start(&[
        ("TLS_PROXY_TARGET_ADDR", target.as_str()),
        ("TLS_PROXY_DIAL_SPACING_MS", "700"),
    ])
    .await;

    // Started together, so the second dial falls inside the first one's
    // spacing window. Run one after the other and the slot is already free —
    // which would make this test pass on a pacer that does nothing.
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let socket = TcpStream::connect(("127.0.0.1", proxy.session_port)).await?;
        tasks.push(tokio::spawn(async move {
            prover(socket).await.map_err(|e| e.to_string())
        }));
    }
    for task in tasks {
        task.await??;
    }

    let logs = proxy.logs();
    assert!(
        logs.contains("queued ") && logs.contains("for a dial slot to"),
        "the second simultaneous dial to one address must be logged as queued, got: {logs}"
    );
    let health = proxy.health().await;
    assert_eq!(health["sessions_ok"].as_u64(), Some(2), "{health}");
    Ok(())
}

/// A target that accepts the TCP connection and then never answers is the live
/// stall shape (the edge in front of `api-m.paypal.com` does exactly this to a
/// burst from one address). Before the stall bound the session sat until the
/// 120 s session timeout, holding its slot; now it is refused in about the
/// bound, and the record says to retry rather than that the presenting party did
/// anything wrong.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_relayed_session_that_never_answers(
) -> Result<(), Box<dyn std::error::Error>> {
    let _serial = SERIAL.lock().await;
    // Accepts, reads nothing, answers nothing — and holds the socket open.
    let blackhole = TcpListener::bind("127.0.0.1:0").await?;
    let blackhole_port = blackhole.local_addr()?.port();
    let held = tokio::spawn(async move {
        let mut sockets = Vec::new();
        while let Ok((stream, _)) = blackhole.accept().await {
            sockets.push(stream);
        }
    });

    let target = format!("127.0.0.1:{blackhole_port}");
    let proxy = Proxy::start(&[
        ("TLS_PROXY_TARGET_ADDR", target.as_str()),
        ("TLS_PROXY_STALL_TIMEOUT", "2"),
    ])
    .await;

    let socket = TcpStream::connect(("127.0.0.1", proxy.session_port)).await?;
    let started = Instant::now();
    let prover_task = tokio::spawn(async move {
        prover(socket).await.map_err(|e| e.to_string())
    });
    let health = proxy.wait_for_failed(1).await;
    let elapsed = started.elapsed();
    let _ = prover_task.await;

    assert_eq!(health["sessions_ok"].as_u64(), Some(0), "{health}");
    assert_eq!(health["attestations"].as_u64(), Some(0), "{health}");
    assert!(
        elapsed < Duration::from_secs(20),
        "a silent target must be refused near the 2 s bound, took {elapsed:?}"
    );

    let refusals = proxy.refusals().await;
    let last = refusals["refusals"]
        .as_array()
        .and_then(|r| r.last())
        .cloned()
        .expect("a refusal should be recorded");
    assert_eq!(
        last["kind"], "stalled",
        "a silent relay is a stall, not a timeout or a refusal of the prover: {refusals}"
    );
    let reason = last["reason"].as_str().unwrap_or("");
    assert!(
        reason.contains("moved no byte for 2s"),
        "the reason must name the silence: {reason}"
    );
    assert!(
        reason.contains("retry"),
        "the reason must tell the prover to retry: {reason}"
    );
    assert!(
        reason.contains("last progress: relayed TLS handshake"),
        "the reason must say which phase stalled: {reason}"
    );
    held.abort();
    Ok(())
}

/// A proxy with no trust anchor must refuse to start rather than attest
/// sessions it cannot validate.
#[test]
fn refuses_to_start_without_a_ca_bundle() {
    let out = Command::new(env!("CARGO_BIN_EXE_tls-proxy"))
        .env("TLS_PROXY_CA_BUNDLE", "/nonexistent/ca-bundle.pem")
        .env("TLS_PROXY_LISTEN", format!("127.0.0.1:{}", free_port()))
        .env("TLS_PROXY_HTTP_LISTEN", format!("127.0.0.1:{}", free_port()))
        .output()
        .expect("run the binary");
    assert!(
        !out.status.success(),
        "a proxy that cannot validate sessions must not start"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot read the CA bundle"),
        "the failure must name the missing bundle, got: {stderr}"
    );
}

/// A shutdown must take no new work but must not throw away the record.
///
/// Powering off with a notarisation in flight destroys the prover's transcript
/// mid-handshake, and nothing tells them why. So the drain does two things at
/// once: refuse new sessions (so the count can actually reach zero) and leave
/// the sessions already recorded untouched (so a stop does not look like a
/// notary that forgot what it proved). This drives the real binary: the flag
/// only exists behind the loopback API, and the refusal is only observable on
/// the session port.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drain_refuses_new_sessions_and_keeps_the_record(
) -> Result<(), Box<dyn std::error::Error>> {
    let _serial = SERIAL.lock().await;
    let fixture_port = start_fixture().await;
    let target = format!("127.0.0.1:{fixture_port}");
    let proxy = Proxy::start(&[("TLS_PROXY_TARGET_ADDR", target.as_str())]).await;

    // One completed session first: this is the work a drain must preserve.
    let socket = TcpStream::connect(("127.0.0.1", proxy.session_port)).await?;
    prover(socket).await?;
    let mut recorded = 0;
    for _ in 0..100 {
        let (_, body) = http_get(proxy.api_port, "/attestations").await?;
        let list: serde_json::Value = serde_json::from_str(&body)?;
        recorded = list["count"].as_u64().unwrap_or(0);
        if recorded == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(recorded, 1, "the session should be recorded before draining");

    // Idle drain: accepted, and it says nothing is in flight — the number the
    // enclave waits on before it powers the machine off.
    let (status, body) = http_post(proxy.api_port, "/drain").await?;
    assert_eq!(status, 200, "{body}");
    let drained: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(drained["draining"], true, "{body}");
    assert_eq!(drained["active_sessions"], 0, "{body}");

    // Repeating it is harmless: a second power-button press must not undo the
    // drain or resurrect work.
    let (status, body) = http_post(proxy.api_port, "/drain").await?;
    assert_eq!(status, 200, "{body}");

    // A late prover gets the connection closed instead of a notarisation.
    let mut late = TcpStream::connect(("127.0.0.1", proxy.session_port)).await?;
    let mut buf = [0u8; 32];
    match tokio::time::timeout(Duration::from_secs(5), late.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("a drained proxy must close a new session, got {other:?}"),
    }

    // The refusal is on the ring, so an operator can see why their session
    // never started.
    let refusals = proxy.refusals().await;
    let last = refusals["refusals"]
        .as_array()
        .and_then(|r| r.last())
        .cloned()
        .expect("a refusal should be recorded");
    assert_eq!(last["kind"], "draining", "{refusals}");
    assert!(
        last["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("shutdown requested"),
        "{refusals}"
    );

    // And the earlier attestation survived the drain: the record is the point.
    let health = proxy.health().await;
    assert_eq!(health["draining"], true, "{health}");
    assert_eq!(health["active_sessions"], 0, "{health}");
    assert_eq!(health["sessions_ok"], 1, "{health}");
    let (status, body) = http_get(proxy.api_port, "/attestations").await?;
    assert_eq!(status, 200, "{body}");
    let list: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(list["count"], 1, "a drain must not discard the record: {body}");
    Ok(())
}
