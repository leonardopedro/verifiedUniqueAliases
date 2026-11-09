//! tls-proxy — a TLSNotary proxy-mode verifier for the confidential VM.
//!
//! This is the second webservice of the enclave (`docs/tls-proxy.md`). Where
//! the PayPal flow proves *one* thing about *one* provider, this service proves
//! the same kind of statement about an arbitrary HTTPS website: a prover (e.g.
//! the TLSNotary browser extension) commits to a TLS session with any host, and
//! this process — running inside the TDX guest, measured with `/init` — relays
//! that handshake, verifies the revealed presentation, and signs the result
//! with a key that never leaves the VM.
//!
//! Why proxy mode and not MPC: proxy mode is the only variant where the
//! verifier sees the cleartext TLS bytes it forwards, so a single Rust service
//! with no extra MPC machinery can attest arbitrary hosts. The prover still
//! chooses the target and which bytes to reveal; the verifier refuses a
//! presentation that does not reveal the server identity, so "which site" is
//! always part of what gets signed.
//!
//! What the signature means, stated plainly: the signature covers the transcript
//! the verifier ACCEPTED — server name, byte counts and SHA-256 digests — and
//! says "this enclave, whose identity is bound to its hardware quote, verified a
//! TLS session with <server_name> whose revealed bytes hash to <digest>". It
//! does not make the website's content true, and it does not prove anything
//! about bytes the prover chose to redact.
//!
//! Endpoints
//!   TCP  TLS_PROXY_LISTEN        (default 0.0.0.0:8443) one TLSNotary session
//!                                per accepted connection
//!   HTTP TLS_PROXY_HTTP_LISTEN   (default 127.0.0.1:8081, loopback only)
//!        GET  /health            counters, in-flight sessions, drain state
//!        POST /drain             stop accepting sessions; let running ones finish
//!        GET /attestations       ids, server names, timestamps
//!        GET /attestations/{id}  the signed attestation
//!        GET /refusals           why recent sessions were refused (bounded)
//!
//! Environment
//!   TLS_PROXY_LISTEN, TLS_PROXY_HTTP_LISTEN, TLS_PROXY_SESSION_TIMEOUT (secs),
//!   TLS_PROXY_CA_BUNDLE (default /etc/ssl/certs/ca-certificates.crt),
//!   TLS_PROXY_SIGNING_KEY_PEM (absent = fresh per-boot RSA-2048 key),
//!   TLS_PROXY_MAX_TRANSCRIPT_BYTES (default 8 MiB; the refusal bound),
//!   TLS_PROXY_TARGET_ADDR (test-only: pin the relay target instead of
//!   resolving the committed name on :443 — `tests/session.rs` needs it)
//!
//! Exit codes: 0 on a clean shutdown, non-zero otherwise (a configuration error
//! such as a missing CA bundle or an unusable key, or a listener failure).

use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::Engine as _;
use openssl::{hash::MessageDigest, pkey::PKey, rsa::Rsa, sign::Signer, x509::X509};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use tlsn::{
    config::verifier::VerifierConfig,
    connection::ServerName,
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::{CertificateDer, RootCertStore},
    Session,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A single site page easily exceeds this (a 2 MB JSON API response plus its
/// headers), and the whole transcript is held in RAM in the guest, so refuse
/// rather than let one prover size the enclave's memory. The default ships as
/// written; `TLS_PROXY_MAX_TRANSCRIPT_BYTES` lowers it in tests, which cannot
/// make the fixture website answer with 9 MiB.
const MAX_TRANSCRIPT_BYTES: usize = 8 * 1024 * 1024;
/// Bounded retention: attestations are re-fetchable only while this process
/// lives, which is exactly the lifetime of the hardware attestation they
/// belong to.
const MAX_STORED_ATTESTATIONS: usize = 256;
/// Recent refusals are kept only to answer "why was that session rejected?"
/// while an operator is looking; a ring, because they are diagnostic, not
/// evidence, and a peer can produce them at will.
const MAX_STORED_REFUSALS: usize = 32;
/// A refusal reason quotes the prover's own commit (the site name it chose), so
/// it is capped before it is stored.
const MAX_REFUSAL_REASON_CHARS: usize = 400;
/// Proxy mode relays a TLS session to the host named in the commit; HTTPS is
/// the only port this service will ever dial, so it cannot be used as an
/// arbitrary TCP relay.
const TARGET_PORT: u16 = 443;

// ---------------------------------------------------------------------------
// Signed statement
// ---------------------------------------------------------------------------

/// The exact bytes the signature covers. Field order is the JSON order
/// (serde keeps declaration order), so a verifier can rebuild these bytes from
/// the response and check the signature without a canonicalisation library.
#[derive(Debug, Clone, Serialize)]
struct AttestedBody {
    version: &'static str,
    session_id: String,
    server_name: String,
    notarized_at: u64,
    sent_len: usize,
    received_len: usize,
    sent_sha256: String,
    received_sha256: String,
    /// Revealed request bytes, base64. Redacted ranges appear as omitted bytes
    /// only because the prover never revealed them.
    sent_b64: String,
    received_b64: String,
    /// True when the transcript had to be truncated for the 8 MiB bound.
    truncated: bool,
}

#[derive(Serialize)]
struct Attestation {
    #[serde(flatten)]
    body: AttestedBody,
    enclave_pubkey_pem: String,
    signature_alg: &'static str,
    signature_b64: String,
}

/// One refused session, as an operator sees it. Never signed and never
/// presented as evidence: the reason is text this process generated from a
/// peer's input, useful for diagnosis only.
#[derive(Debug, Serialize)]
struct RefusalRecord {
    at: u64,
    /// "rejected" (a verdict was reached and refused) or "timeout".
    kind: &'static str,
    reason: String,
}

struct SigningKey {
    key: PKey<openssl::pkey::Private>,
    pubkey_pem: String,
}

impl SigningKey {
    fn from_pem(pem: &str) -> Result<Self, BoxError> {
        let key = PKey::private_key_from_pem(pem.as_bytes())
            .map_err(|e| format!("TLS_PROXY_SIGNING_KEY_PEM is not a usable private key: {e}"))?;
        let pubkey_pem = String::from_utf8(key.public_key_to_pem()?)?;
        Ok(Self { key, pubkey_pem })
    }

    /// Per-boot ephemeral key: nothing is written to disk, and the key dies
    /// with the VM, exactly like the enclave's PayPal attestation key.
    fn ephemeral() -> Result<Self, BoxError> {
        let key = PKey::from_rsa(Rsa::generate(2048)?)?;
        let pubkey_pem = String::from_utf8(key.public_key_to_pem()?)?;
        Ok(Self { key, pubkey_pem })
    }

    fn sign(&self, body: &AttestedBody) -> Result<String, BoxError> {
        let data = serde_json::to_vec(body)?;
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key)?;
        signer.update(&data)?;
        Ok(base64::engine::general_purpose::STANDARD.encode(signer.sign_to_vec()?))
    }
}

// ---------------------------------------------------------------------------
// Service state
// ---------------------------------------------------------------------------

struct ProxyState {
    signer: SigningKey,
    /// DER roots, one per certificate in the bundle. Kept as DER so each
    /// session builds its own `RootCertStore` without cloning a tlsn type.
    roots: Vec<Vec<u8>>,
    session_timeout: Duration,
    /// Refusal bound for `sent + received`; see [`MAX_TRANSCRIPT_BYTES`].
    max_transcript_bytes: usize,
    started_at: u64,
    sessions_total: AtomicU64,
    sessions_ok: AtomicU64,
    sessions_failed: AtomicU64,
    /// Sessions accepted and not yet finished. A shutdown waits for this to
    /// reach zero before powering off, so this counter is the difference
    /// between a drain and a cut.
    active_sessions: AtomicU64,
    /// Set by `POST /drain`. New sessions are refused; running ones are not
    /// touched. The process keeps serving its record while draining.
    draining: AtomicBool,
    /// Newest last; bounded by MAX_STORED_ATTESTATIONS.
    /// Stored as the exact JSON text that was signed plus its envelope, NOT as a
    /// `serde_json::Value`.
    ///
    /// v221 (live auditor finding, 2026-11-09): `Value` round-trips through a
    /// BTreeMap, so `Json(value)` served keys in ALPHABETICAL order while the
    /// signature covers the struct's declaration order. The auditor page
    /// reconstructs the signed bytes from the text it is given, so every real
    /// attestation failed with "unexpected shape — top-level order:
    /// enclave_pubkey_pem, notarized_at, …". The hermetic test missed it because
    /// it re-parsed into a typed struct before verifying, which restores the
    /// order the signature needs. Keeping the text is the only way what we serve
    /// is what we signed.
    attestations: Mutex<VecDeque<(String, String)>>,
    /// Newest last; bounded by MAX_STORED_REFUSALS.
    refusals: Mutex<VecDeque<RefusalRecord>>,
}

impl ProxyState {
    fn root_store(&self) -> RootCertStore {
        RootCertStore {
            roots: self.roots.iter().cloned().map(CertificateDer).collect(),
        }
    }

    fn remember(&self, id: String, json: String) {
        let mut store = self.attestations.lock().unwrap();
        while store.len() >= MAX_STORED_ATTESTATIONS {
            store.pop_front();
        }
        store.push_back((id, json));
    }

    fn remember_refusal(&self, kind: &'static str, reason: String) {
        // Count characters, not bytes: the reason can carry a UTF-8 site name.
        let reason = if reason.chars().count() > MAX_REFUSAL_REASON_CHARS {
            reason.chars().take(MAX_REFUSAL_REASON_CHARS).collect::<String>() + "…"
        } else {
            reason
        };
        let mut store = self.refusals.lock().unwrap();
        while store.len() >= MAX_STORED_REFUSALS {
            store.pop_front();
        }
        store.push_back(RefusalRecord {
            at: now_unix(),
            kind,
            reason,
        });
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn new_session_id() -> Result<String, BoxError> {
    let mut buf = [0u8; 16];
    openssl::rand::rand_bytes(&mut buf)?;
    Ok(hex::encode(buf))
}

// ---------------------------------------------------------------------------
// One TLSNotary session
// ---------------------------------------------------------------------------

struct Verified {
    server_name: String,
    sent: Vec<u8>,
    received: Vec<u8>,
}

/// How a session ended. The timeout is a variant rather than an outer
/// `timeout()` around this whole function because the cleanup below MUST run:
/// abandoning the future would leave the session driver — and the peer's
/// socket — alive forever.
enum SessionOutcome {
    Verified(Verified),
    Rejected(BoxError),
    TimedOut,
}

async fn handle_session(stream: TcpStream, peer: SocketAddr, st: Arc<ProxyState>) {
    st.sessions_total.fetch_add(1, Ordering::Relaxed);
    info!("session from {peer}: accepted");

    match run_session(stream, peer, &st).await {
        SessionOutcome::Verified(verified) => {
            st.sessions_ok.fetch_add(1, Ordering::Relaxed);
            match record_attestation(&st, verified) {
                Ok(id) => info!("session from {peer}: verified, attestation {id}"),
                Err(e) => warn!("session from {peer}: verified but could not be recorded: {e}"),
            }
        }
        SessionOutcome::Rejected(e) => {
            let reason = e.to_string();
            st.remember_refusal("rejected", reason.clone());
            // The counter moves last, so a reader that sees it move can also
            // see the reason it belongs to.
            st.sessions_failed.fetch_add(1, Ordering::Relaxed);
            warn!("session from {peer}: rejected: {reason}");
        }
        SessionOutcome::TimedOut => {
            let reason = format!("no verdict within {:?}", st.session_timeout);
            st.remember_refusal("timeout", reason.clone());
            st.sessions_failed.fetch_add(1, Ordering::Relaxed);
            warn!("session from {peer}: {reason} — closed");
        }
    }
}

async fn run_session(stream: TcpStream, peer: SocketAddr, st: &ProxyState) -> SessionOutcome {
    stream.set_nodelay(true).ok();

    let session = Session::new(stream.compat());
    let (driver, mut handle) = session.split();
    let mut driver_task = tokio::spawn(driver);

    // The whole protocol lives in one block so that every early return still
    // reaches the `handle.close()` + driver reaping below, and so the timeout is
    // a verdict on that block rather than an abandonment of this function.
    let protocol = async {
        let verifier = handle
            .new_verifier(VerifierConfig::builder().root_store(st.root_store()).build()?)
            .map_err(|e| format!("cannot start the verifier: {e}"))?;

        let verifier = match verifier.commit().await? {
            VerifierCommitStart::Proxy(verifier) => verifier,
            VerifierCommitStart::Mpc(verifier) => {
                // MPC would put the notarisation inside a 2PC the enclave does
                // not implement; refusing is honest, and does not pretend to
                // have notarised anything.
                let _ = verifier
                    .reject(Some("this notary accepts proxy-mode sessions only"))
                    .await;
                return Err("prover requested MPC mode; proxy mode only".into());
            }
        };

        // The target is taken from the COMMIT, never from a caller-supplied
        // address: the prover picks the site, the enclave resolves it itself.
        let server_name = verifier.config().server_name().as_str().to_string();
        if server_name.is_empty() {
            return Err("commit carried an empty server name".into());
        }
        // `TLS_PROXY_TARGET_ADDR` pins the connection target for local tests:
        // the fixture server listens on 127.0.0.1 while its certificate says
        // test-server.io, and /etc/hosts is not ours to edit. Unset — the
        // shipped configuration — the proxy resolves the committed name itself.
        let addr: SocketAddr = match std::env::var("TLS_PROXY_TARGET_ADDR") {
            Ok(pinned) if !pinned.trim().is_empty() => pinned
                .parse()
                .map_err(|e| format!("TLS_PROXY_TARGET_ADDR is not a socket address: {e}"))?,
            _ => tokio::net::lookup_host((server_name.as_str(), TARGET_PORT))
                .await?
                .next()
                .ok_or_else(|| format!("{server_name} did not resolve"))?,
        };

        let client = TcpStream::connect(addr).await?;
        client.set_nodelay(true).ok();
        info!("session from {peer}: relaying TLS to {server_name} ({addr})");

        let verifier = verifier.accept().await?;
        let verifier = verifier.run(client.compat()).await?;
        let verifier = verifier.verify().await?;

        // Without the server identity the attestation would not say which site
        // it is about, which is the entire point of the service.
        if !verifier.request().server_identity() {
            let _ = verifier
                .reject(Some("the server identity must be revealed"))
                .await;
            return Err("presentation did not reveal the server name".into());
        }

        let (
            VerifierOutput {
                server_name: revealed,
                transcript,
                ..
            },
            verifier,
        ) = verifier.accept().await?;
        verifier.close().await?;

        let revealed = match revealed {
            // `ServerName` has a single variant today; matching it explicitly
            // (rather than a catch-all) makes a new variant a compile error
            // here instead of a silently unattested name.
            Some(ServerName::Dns(dns)) => dns.as_str().to_string(),
            None => return Err("verifier accepted without a server name".into()),
        };
        if revealed != server_name {
            return Err(format!(
                "revealed server name {revealed} does not match the committed {server_name}"
            )
            .into());
        }
        let transcript = transcript.ok_or("verifier accepted without a transcript")?;

        let sent = transcript
            .sent_unsafe(transcript.len_sent())
            .unwrap_or_default();
        let received = transcript
            .received_unsafe(transcript.len_received())
            .unwrap_or_default();
        if sent.len() + received.len() > st.max_transcript_bytes {
            return Err(format!(
                "transcript is {} bytes, over the {}-byte bound",
                sent.len() + received.len(),
                st.max_transcript_bytes
            )
            .into());
        }

        Ok(Verified {
            server_name,
            sent,
            received,
        })
    };
    let outcome = match tokio::time::timeout(st.session_timeout, protocol).await {
        Ok(Ok(verified)) => SessionOutcome::Verified(verified),
        Ok(Err(e)) => SessionOutcome::Rejected(e),
        Err(_) => SessionOutcome::TimedOut,
    };

    handle.close();
    // The driver has the session's last word; give it a moment, then abort it.
    // Waiting without aborting is not enough: a peer that stopped reading can
    // park the driver in a write, and an abandoned driver keeps the socket (and
    // its buffers) alive for as long as the process runs.
    if tokio::time::timeout(Duration::from_secs(5), &mut driver_task)
        .await
        .is_err()
    {
        driver_task.abort();
    }

    outcome
}

fn record_attestation(st: &ProxyState, verified: Verified) -> Result<String, BoxError> {
    let body = AttestedBody {
        version: "tls-proxy/1",
        session_id: new_session_id()?,
        server_name: verified.server_name,
        notarized_at: now_unix(),
        sent_len: verified.sent.len(),
        received_len: verified.received.len(),
        sent_sha256: sha256_hex(&verified.sent),
        received_sha256: sha256_hex(&verified.received),
        sent_b64: base64::engine::general_purpose::STANDARD.encode(&verified.sent),
        received_b64: base64::engine::general_purpose::STANDARD.encode(&verified.received),
        truncated: false,
    };
    let signature_b64 = st.signer.sign(&body)?;
    let attestation = Attestation {
        body,
        enclave_pubkey_pem: st.signer.pubkey_pem.clone(),
        signature_alg: "RSA-PKCS1-v1_5-SHA256",
        signature_b64,
    };
    let id = attestation.body.session_id.clone();
    st.remember(id.clone(), serde_json::to_string(&attestation)?);
    Ok(id)
}

// ---------------------------------------------------------------------------
// HTTP API (loopback only)
// ---------------------------------------------------------------------------

async fn health(State(st): State<Arc<ProxyState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "service": "tls-proxy",
        "version": "tls-proxy/1",
        "uptime_secs": now_unix().saturating_sub(st.started_at),
        "sessions_total": st.sessions_total.load(Ordering::Relaxed),
        "sessions_ok": st.sessions_ok.load(Ordering::Relaxed),
        "sessions_failed": st.sessions_failed.load(Ordering::Relaxed),
        "active_sessions": st.active_sessions.load(Ordering::Relaxed),
        "draining": st.draining.load(Ordering::Relaxed),
        "attestations": st.attestations.lock().unwrap().len(),
        "refusals": st.refusals.lock().unwrap().len(),
    }))
}

/// `POST /drain` — begin a graceful stop.
///
/// New sessions are refused from here on; sessions already accepted keep
/// running and their attestations are still recorded. Nothing in this handler
/// aborts a notarisation: a session in flight holds the prover's transcript and
/// their proof that the bytes came from the host, which is not recoverable if
/// it is cut mid-handshake.
///
/// The answer carries the current in-flight count, which is what the caller
/// waits on. Repeating the call is harmless and returns the current count.
async fn drain(State(st): State<Arc<ProxyState>>) -> Json<serde_json::Value> {
    st.draining.store(true, Ordering::SeqCst);
    let active = st.active_sessions.load(Ordering::SeqCst);
    info!("drain: refusing new sessions, {active} in flight");
    Json(serde_json::json!({
        "draining": true,
        "active_sessions": active,
    }))
}

/// Project a stored attestation down to the three fields an operator needs.
///
/// The signed body is **flattened** into the envelope (`Attestation` carries
/// `#[serde(flatten)] body`), so `server_name` and `notarized_at` live at the
/// top level of the document — the same place `GET /attestations/{id}`
/// serves them from. Reading them under a `body` key instead lists every
/// session with a null host, which is the one field an operator is looking
/// for (v217).
///
/// The stored form is text (see `ProxyState::attestations`), so this parses a
/// copy: reading fields for a listing does not need — and must not rewrite — the
/// byte layout the signature covers.
fn summarize_session(id: &str, json: &str) -> serde_json::Value {
    let value: serde_json::Value = serde_json::from_str(json).unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "session_id": id,
        "server_name": value.get("server_name"),
        "notarized_at": value.get("notarized_at"),
    })
}

async fn list(State(st): State<Arc<ProxyState>>) -> Json<serde_json::Value> {
    let store = st.attestations.lock().unwrap();
    let sessions: Vec<serde_json::Value> = store
        .iter()
        .map(|(id, json)| summarize_session(id, json))
        .collect();
    Json(serde_json::json!({
        "count": sessions.len(),
        "sessions": sessions,
    }))
}

/// Why the recent sessions were refused, newest last — the same text the log
/// carries, for an operator who cannot read the boot log (or is watching a
/// machine that has one).
async fn refusals(State(st): State<Arc<ProxyState>>) -> Json<serde_json::Value> {
    let store = st.refusals.lock().unwrap();
    Json(serde_json::json!({
        "count": store.len(),
        "refusals": store.iter().collect::<Vec<_>>(),
    }))
}

/// Serve the attestation as **the text that was signed**, verbatim.
///
/// Not `Json(value)`: that would re-serialize through `serde_json::Value` and
/// emit the signed fields in alphabetical order, which the auditor page cannot
/// verify (v221). The bytes on the wire are the bytes the enclave hashed.
async fn get_one(
    State(st): State<Arc<ProxyState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let store = st.attestations.lock().unwrap();
    match store.iter().find(|(sid, _)| sid == &id) {
        Some((_, json)) => Ok((
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            json.clone(),
        )
            .into_response()),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "no such attestation in this boot",
                "session_id": id,
            })),
        )),
    }
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_ansi(false)
        .init();

    let session_addr: SocketAddr = env_or("TLS_PROXY_LISTEN", "0.0.0.0:8443")
        .parse()
        .map_err(|e| format!("TLS_PROXY_LISTEN is not a socket address: {e}"))?;
    let http_addr: SocketAddr = env_or("TLS_PROXY_HTTP_LISTEN", "127.0.0.1:8081")
        .parse()
        .map_err(|e| format!("TLS_PROXY_HTTP_LISTEN is not a socket address: {e}"))?;
    let session_timeout_secs: u64 = env_or("TLS_PROXY_SESSION_TIMEOUT", "120")
        .parse()
        .map_err(|e| format!("TLS_PROXY_SESSION_TIMEOUT is not a number of seconds: {e}"))?;
    let ca_bundle = env_or("TLS_PROXY_CA_BUNDLE", "/etc/ssl/certs/ca-certificates.crt");
    let max_transcript_bytes: usize =
        env_or("TLS_PROXY_MAX_TRANSCRIPT_BYTES", &MAX_TRANSCRIPT_BYTES.to_string())
            .parse()
            .map_err(|e| format!("TLS_PROXY_MAX_TRANSCRIPT_BYTES is not a byte count: {e}"))?;

    // Roots: the verifier must be able to validate ANY public host, so this is
    // the distribution CA bundle rather than a pinned pin set. The target is
    // flexible on purpose; the attestation is about what happened, not about a
    // pre-approved list.
    let pem = std::fs::read(&ca_bundle)
        .map_err(|e| format!("cannot read the CA bundle {ca_bundle}: {e}"))?;
    let certs = X509::stack_from_pem(&pem).map_err(|e| format!("{ca_bundle} is not a PEM bundle: {e}"))?;
    if certs.is_empty() {
        return Err(format!("{ca_bundle} contained no certificates").into());
    }
    let roots: Vec<Vec<u8>> = certs
        .iter()
        .map(|c| c.to_der().map_err(|e| format!("cannot re-encode a root: {e}")))
        .collect::<Result<_, _>>()?;

    let signer = match std::env::var("TLS_PROXY_SIGNING_KEY_PEM") {
        Ok(pem) if !pem.trim().is_empty() => SigningKey::from_pem(&pem)?,
        _ => {
            info!("no TLS_PROXY_SIGNING_KEY_PEM: generating a per-boot ephemeral key");
            SigningKey::ephemeral()?
        }
    };

    let state = Arc::new(ProxyState {
        signer,
        roots,
        session_timeout: Duration::from_secs(session_timeout_secs),
        max_transcript_bytes,
        started_at: now_unix(),
        sessions_total: AtomicU64::new(0),
        sessions_ok: AtomicU64::new(0),
        sessions_failed: AtomicU64::new(0),
        active_sessions: AtomicU64::new(0),
        draining: AtomicBool::new(false),
        attestations: Mutex::new(VecDeque::new()),
        refusals: Mutex::new(VecDeque::new()),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/drain", post(drain))
        .route("/attestations", get(list))
        .route("/attestations/{id}", get(get_one))
        .route("/refusals", get(refusals))
        .with_state(state.clone());

    let http_listener = TcpListener::bind(http_addr)
        .await
        .map_err(|e| format!("cannot bind the attestation API on {http_addr}: {e}"))?;
    let http_task = tokio::spawn(async move {
        if let Err(e) = axum::serve(http_listener, app).await {
            error!("attestation API stopped: {e}");
        }
    });

    let listener = TcpListener::bind(session_addr)
        .await
        .map_err(|e| format!("cannot bind sessions on {session_addr}: {e}"))?;
    info!(
        "tls-proxy ready: TLSNotary sessions on {session_addr}, attestation API on {http_addr} \
         (roots: {}, timeout: {session_timeout_secs}s)",
        certs.len()
    );

    let mut in_flight = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let st = state.clone();
                // After a drain request the listener stays bound (the record is
                // still served) but takes no new work: the prover sees the
                // connection close before any handshake bytes are spent, and
                // the reason is on the loopback refusal ring.
                if st.draining.load(Ordering::SeqCst) {
                    st.remember_refusal("draining", "shutdown requested: new session refused".into());
                    drop(stream);
                    continue;
                }
                // Counted before the spawn and decremented by the task itself,
                // so the count never misses a session that is between accept
                // and spawn.
                st.active_sessions.fetch_add(1, Ordering::SeqCst);
                in_flight.spawn(async move {
                    handle_session(stream, peer, st.clone()).await;
                    st.active_sessions.fetch_sub(1, Ordering::SeqCst);
                });
            }
            // Reap finished sessions so the set does not grow with uptime.
            Some(_) = in_flight.join_next(), if !in_flight.is_empty() => {}
            _ = tokio::signal::ctrl_c() => {
                info!("signal: shutting down");
                break;
            }
        }
    }
    http_task.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The envelope `record_attestation` stores and `GET /attestations/{id}`
    /// serves: signed fields flattened to the top level beside the signature.
    ///
    /// Returned as text, because the store holds text: `serde_json::json!`
    /// builds a `Map` (a BTreeMap without `preserve_order`), which is precisely
    /// the alphabetical re-ordering that made served attestations unverifiable
    /// (v221). A fixture that sorted itself could never catch that.
    fn stored_envelope(server_name: &str) -> String {
        format!(
            concat!(
                "{{\"version\":\"tls-proxy/1\",\"session_id\":\"aa\",\"server_name\":\"{}\",",
                "\"notarized_at\":{},\"sent_len\":107,\"received_len\":3429,",
                "\"sent_sha256\":\"00\",\"received_sha256\":\"00\",\"sent_b64\":\"\",\"received_b64\":\"\",",
                "\"truncated\":false,\"enclave_pubkey_pem\":\"pem\",",
                "\"signature_alg\":\"RSA-PKCS1-v1_5-SHA256\",\"signature_b64\":\"sig\"}}"
            ),
            server_name,
            1_790_000_000u64
        )
    }

    #[test]
    fn list_projection_reports_the_committed_host() {
        let row = summarize_session("aa", &stored_envelope("www.sandbox.paypal.com"));
        assert_eq!(row["session_id"], "aa");
        assert_eq!(row["server_name"], "www.sandbox.paypal.com");
        assert_eq!(row["notarized_at"], 1_790_000_000u64);
        // The projection is the operator's index, not evidence: no transcript
        // bytes, no signature, no key.
        assert_eq!(row.as_object().unwrap().len(), 3);
    }

    #[test]
    fn list_projection_tolerates_a_record_without_a_host() {
        let envelope = stored_envelope("").replace("\"server_name\":\"\",", "");
        let row = summarize_session("bb", &envelope);
        assert_eq!(row["session_id"], "bb");
        assert!(row["server_name"].is_null());
        assert_eq!(row["notarized_at"], 1_790_000_000u64);
    }
}
