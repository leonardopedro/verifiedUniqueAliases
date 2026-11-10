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
//!        GET  /pubkey            the attestation signing key + its SPKI-DER
//!                                SHA-256, so the enclave's quoted report can
//!                                name the key that signs records
//!        POST /drain             stop accepting sessions; let running ones finish
//!        GET /attestations       ids, server names, timestamps
//!        GET /attestations/{id}  the signed attestation
//!             ?sent_sha256=&received_sha256=  same, for someone who is not on
//!                                this box: served only when both digests match
//!                                the stored record, i.e. when the caller holds
//!                                the revealed transcript (see docs §"Who may
//!                                download a transcript")
//!        GET /refusals           why recent sessions were refused (bounded)
//!
//! Environment
//!   TLS_PROXY_LISTEN, TLS_PROXY_HTTP_LISTEN, TLS_PROXY_SESSION_TIMEOUT (secs),
//!   TLS_PROXY_STALL_TIMEOUT (secs, default 20: a relayed session that moves no
//!   byte for this long is refused instead of sitting until the session
//!   timeout), TLS_PROXY_DIAL_SPACING_MS (default 1500: minimum spacing between
//!   outbound dials to ONE target address — see `DialPacer`),
//!   TLS_PROXY_CA_BUNDLE (default /etc/ssl/certs/ca-certificates.crt),
//!   TLS_PROXY_SIGNING_KEY_PEM (absent = fresh per-boot RSA-2048 key),
//!   TLS_PROXY_MAX_TRANSCRIPT_BYTES (default 8 MiB; the refusal bound),
//!   TLS_PROXY_TARGET_ADDR (test-only: pin the relay target instead of
//!   resolving the committed name on :443 — `tests/session.rs` needs it)
//!
//! Exit codes: 0 on a clean shutdown, non-zero otherwise (a configuration error
//! such as a missing CA bundle or an unusable key, or a listener failure).

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{Path as AxumPath, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::Engine as _;
use openssl::{hash::MessageDigest, pkey::PKey, rsa::Rsa, sign::Signer, x509::X509};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
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
/// How long a relayed connection may take to open. Generous for a real network,
/// short enough that a target whose boot-time address no longer answers is
/// refused while the prover is still watching (before v236 the session simply
/// sat until the 120 s session timeout).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Minimum spacing between the notary's outbound DIALS to one target address.
///
/// Measured on the deployed notary (2026-11-10, one boot, same 2 vCPU, same
/// EIP), all against `api-m.paypal.com` = Cloudflare `104.16.124.74`:
///
/// | wave                                  | result |
/// |---------------------------------------|--------|
/// | 4 simultaneous (3 waves)              | 12/12  |
/// | 6 simultaneous                        | 5/6    |
/// | 8 simultaneous                        | 3/8, 5/8 |
/// | 8 simultaneous, 0.4 s apart           | 3/8    |
/// | 8 simultaneous, 1.5 s apart           | 8/8    |
/// | 8 simultaneous to Fastly (`api-m.sandbox`, 146.75.123.1) | 8/8 |
/// | 8 simultaneous to `104.16.124.74` spread over 3 edges | 6/8, all failures on Cloudflare |
///
/// The failing sessions are indistinguishable from healthy ones up to the
/// relayed handshake: TCP connects, then the edge never sends a ServerHello and
/// nothing moves again until the session timeout. Sequential sessions on the
/// same address never fail, and the notary serves eight simultaneous sessions
/// to a different edge, so this is the edge's tolerance for near-simultaneous
/// TLS handshakes from one source address — not CPU, not the 5 Mbps line, and
/// not the transcript size.
///
/// The fix that stays inside the design is to space the dials: the notary's
/// ClientHellos then reach the edge spaced instead of together. A session that
/// waits here is waiting before its handshake starts, which is the state the
/// prover is already in during the commit.
const DEFAULT_DIAL_SPACING_MS: u64 = 1_500;

/// How long a relayed session may move NO byte before it is refused.
///
/// A stalled handshake (the edge accepting and then withholding its ServerHello)
/// never recovers: the 120 s session timeout was the only thing that ended it,
/// and that is 100 s of a slot held for nothing. Every real session to this
/// notary's targets moves bytes within seconds — the measured passing sessions
/// finish the whole relayed phase in 1.4–1.6 s — so silence for 20 s is a stall,
/// not slowness. Bounded below the session timeout on purpose, and settable so a
/// genuinely slow target can be given more.
const DEFAULT_STALL_TIMEOUT: Duration = Duration::from_secs(20);

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
    /// SHA-256 of the SubjectPublicKeyInfo DER — the same value
    /// `pubkey_fingerprint()` computes in the enclave and `verify-proxy.html`
    /// recomputes from `enclave_pubkey_pem`. Not the hash of the PEM text: a
    /// verifier that re-encodes the key must land on the same bytes.
    pubkey_der_sha256: String,
}

impl SigningKey {
    fn from_pem(pem: &str) -> Result<Self, BoxError> {
        let key = PKey::private_key_from_pem(pem.as_bytes())
            .map_err(|e| format!("TLS_PROXY_SIGNING_KEY_PEM is not a usable private key: {e}"))?;
        let pubkey_pem = String::from_utf8(key.public_key_to_pem()?)?;
        let pubkey_der_sha256 = sha256_hex(&key.public_key_to_der()?);
        Ok(Self { key, pubkey_pem, pubkey_der_sha256 })
    }

    /// Per-boot ephemeral key: nothing is written to disk, and the key dies
    /// with the VM, exactly like the enclave's PayPal attestation key.
    fn ephemeral() -> Result<Self, BoxError> {
        let key = PKey::from_rsa(Rsa::generate(2048)?)?;
        let pubkey_pem = String::from_utf8(key.public_key_to_pem()?)?;
        let pubkey_der_sha256 = sha256_hex(&key.public_key_to_der()?);
        Ok(Self { key, pubkey_pem, pubkey_der_sha256 })
    }

    fn sign(&self, body: &AttestedBody) -> Result<String, BoxError> {
        let data = serde_json::to_vec(body)?;
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key)?;
        signer.update(&data)?;
        Ok(base64::engine::general_purpose::STANDARD.encode(signer.sign_to_vec()?))
    }
}

// ---------------------------------------------------------------------------
// Outbound dial pacing, and stall detection on the relayed connection
// ---------------------------------------------------------------------------

/// Spaces the notary's outbound dials per target address (see
/// [`DEFAULT_DIAL_SPACING_MS`] for the measurement this is based on).
///
/// Keyed by ADDRESS, not by host name: the edge's tolerance is about how many
/// handshakes arrive from one source address at the same target address at once,
/// and two names that resolve to the same address share it.
struct DialPacer {
    spacing: Duration,
    /// When the next dial to this address may leave. Only ever written by the
    /// task that claimed the slot, so a claim is a reservation, not a race.
    next_free: Mutex<HashMap<IpAddr, Instant>>,
}

impl DialPacer {
    fn new(spacing: Duration) -> Self {
        Self {
            spacing,
            next_free: Mutex::new(HashMap::new()),
        }
    }

    /// Waits for this address's slot and claims it, returning how long the wait
    /// was so the log and the progress text can say the session was queued
    /// rather than stalled.
    async fn claim(&self, addr: IpAddr) -> Duration {
        if self.spacing.is_zero() {
            return Duration::ZERO;
        }
        let start = Instant::now();
        loop {
            // The guard is dropped before the sleep: holding a std mutex across
            // an await would stall every other session's dial.
            let wait = {
                let mut map = self.next_free.lock().unwrap();
                let now = Instant::now();
                let slot = map.entry(addr).or_insert(now);
                if *slot <= now {
                    *slot = now + self.spacing;
                    return start.elapsed();
                }
                *slot - now
            };
            tokio::time::sleep(wait).await;
        }
    }
}

/// Byte activity of the relayed connection, so "no verdict yet" can be told
/// apart from "the edge accepted the TCP connection and then said nothing".
///
/// Armed once the target connection is established (before that there is no
/// relayed stream to watch), stamped by every byte the relayed stream carries in
/// either direction, and polled by [`RelayActivity::stalled`].
struct RelayActivity {
    origin: Instant,
    /// Milliseconds since `origin` of the last byte; 0 while unarmed.
    last_millis: AtomicU64,
    armed: AtomicBool,
    stall: Duration,
}

impl RelayActivity {
    fn new(stall: Duration) -> Arc<Self> {
        Arc::new(Self {
            origin: Instant::now(),
            last_millis: AtomicU64::new(0),
            armed: AtomicBool::new(false),
            stall,
        })
    }

    fn arm(&self) {
        self.stamp();
        self.armed.store(true, Ordering::SeqCst);
    }

    fn stamp(&self) {
        self.last_millis
            .store(self.origin.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    /// How long the relayed connection has been silent, or `None` when it has
    /// not started yet.
    fn idle(&self) -> Option<Duration> {
        if !self.armed.load(Ordering::SeqCst) {
            return None;
        }
        let last = self.last_millis.load(Ordering::Relaxed);
        Some(self.origin.elapsed().saturating_sub(Duration::from_millis(last)))
    }

    /// Resolves once the relayed connection has been silent for `stall`.
    /// Never resolves when the stall bound is disabled (0).
    async fn stalled(self: Arc<Self>) {
        if self.stall.is_zero() {
            std::future::pending::<()>().await;
        }
        loop {
            match self.idle() {
                Some(idle) if idle >= self.stall => return,
                Some(idle) => {
                    let rest = self.stall - idle;
                    tokio::time::sleep(rest.min(Duration::from_millis(200))).await;
                }
                // Not armed yet: the target connection is still being made, and
                // `CONNECT_TIMEOUT` is what bounds that.
                None => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    }
}

/// The relayed target connection, stamped on every byte it carries.
struct Stamped<S> {
    inner: S,
    activity: Arc<RelayActivity>,
}

impl<S> Stamped<S> {
    fn new(inner: S, activity: Arc<RelayActivity>) -> Self {
        Self { inner, activity }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Stamped<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        let filled_before = buf.filled().len();
        let poll = Pin::new(&mut me.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            if buf.filled().len() > filled_before {
                me.activity.stamp();
            }
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Stamped<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        let poll = Pin::new(&mut me.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll {
            if *n > 0 {
                me.activity.stamp();
            }
        }
        poll
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        let poll = Pin::new(&mut me.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = &poll {
            if *n > 0 {
                me.activity.stamp();
            }
        }
        poll
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
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
    /// Silence bound on a relayed connection; see [`DEFAULT_STALL_TIMEOUT`].
    stall_timeout: Duration,
    /// Spaces outbound dials per target address; see [`DEFAULT_DIAL_SPACING_MS`].
    pacer: DialPacer,
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
    /// The session hit `session_timeout`; the string is where it had got to,
    /// so the verdict says whether the relayed connection or the prover stalled.
    TimedOut(String),
    /// The relayed connection went silent for `stall_timeout` — the edge
    /// accepted the TCP connection and then moved no byte. Distinct from a
    /// timeout because it is not a slow prover and not a slow answer: nothing at
    /// all is happening, and it will not resolve itself (measured: 120 s of
    /// silence, then the session timeout).
    Stalled(String),
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
        SessionOutcome::TimedOut(where_at) => {
            let reason = format!(
                "no verdict within {:?} — last progress: {where_at}",
                st.session_timeout
            );
            st.remember_refusal("timeout", reason.clone());
            st.sessions_failed.fetch_add(1, Ordering::Relaxed);
            warn!("session from {peer}: {reason} — closed");
        }
        SessionOutcome::Stalled(where_at) => {
            let reason = format!(
                "relayed session moved no byte for {:?} — last progress: {where_at}; retry this session (a burst of sessions from one address can be stalled by the target's edge before its handshake starts)",
                st.stall_timeout
            );
            st.remember_refusal("stalled", reason.clone());
            st.sessions_failed.fetch_add(1, Ordering::Relaxed);
            warn!("session from {peer}: {reason} — closed");
        }
    }
}

async fn run_session(stream: TcpStream, peer: SocketAddr, st: &ProxyState) -> SessionOutcome {
    stream.set_nodelay(true).ok();

    // Where the session got to. A stall with no verdict is otherwise
    // indistinguishable from a slow prover, and the address the notary was
    // dialling is the one fact an operator needs: it comes from the boot-time
    // pin in /etc/hosts, not from a lookup, so it cannot be re-derived later.
    let progress = std::sync::Arc::new(std::sync::Mutex::new(String::from(
        "before the commitment handshake",
    )));
    let phase = progress.clone();
    // Set when the stall watchdog — not the protocol — ended the session.
    let stalled = Arc::new(AtomicBool::new(false));

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
            // v236: say why, in band. A prover that is simply dropped reads
            // "unexpected end of file" and has no way to learn that the commit
            // itself was the problem — the only explanation used to be the
            // operator-facing /proxy/refusals ring, which a remote prover
            // cannot line up with their own attempt.
            let reason = "the commit carried an empty server name";
            let _ = verifier.reject(Some(reason)).await;
            return Err(reason.into());
        }
        // `TLS_PROXY_TARGET_ADDR` pins the connection target for local tests:
        // the fixture server listens on 127.0.0.1 while its certificate says
        // test-server.io, and /etc/hosts is not ours to edit. Unset — the
        // shipped configuration — the proxy resolves the committed name itself.
        let addr: SocketAddr = match resolve_target(&server_name).await {
            Ok(addr) => addr,
            Err(reason) => {
                // Not in the boot-time relay_targets (the resolver is closed
                // after boot), or its pinned address is stale: either way the
                // prover gets the reason instead of a bare disconnect.
                let _ = verifier.reject(Some(reason.as_str())).await;
                return Err(reason.into());
            }
        };

        // Space this dial from the previous one to the SAME address: a burst of
        // simultaneous sessions makes the edge in front of `api-m.paypal.com`
        // accept the TCP connections and then withhold every ServerHello from
        // the fifth one on (see [`DEFAULT_DIAL_SPACING_MS`]). Paced here, the
        // handshakes reach the edge spaced instead of together, which is the
        // difference between 3/8 and 8/8 on the deployed notary.
        let waited = st.pacer.claim(addr.ip()).await;
        if waited >= Duration::from_millis(100) {
            info!(
                "session from {peer}: queued {:.1}s for a dial slot to {server_name} ({addr})",
                waited.as_secs_f64()
            );
            *phase.lock().unwrap() = format!(
                "queued {:.1}s for a dial slot to {server_name} ({addr})",
                waited.as_secs_f64()
            );
        }

        // v236: a target whose pinned address blackholes (a stale CDN address
        // after the boot-time resolution) used to hold the session until the
        // whole session timeout — 120 s of nothing, then a prover-side
        // "connection closed", with the reason only in the operator's ring.
        // Bounded here so the answer is prompt and names the cause.
        let client = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => {
                let reason = format!(
                    "cannot connect to {server_name} ({addr}): {e} — the address comes from the boot-time relay_targets list, so a reboot re-resolves it"
                );
                let _ = verifier.reject(Some(reason.as_str())).await;
                return Err(reason.into());
            }
            Err(_) => {
                let reason = format!(
                    "connecting to {server_name} ({addr}) timed out after {}s — that address is what this boot resolved for the host, so it may be stale; a reboot re-resolves relay_targets",
                    CONNECT_TIMEOUT.as_secs()
                );
                let _ = verifier.reject(Some(reason.as_str())).await;
                return Err(reason.into());
            }
        };
        client.set_nodelay(true).ok();
        info!("session from {peer}: relaying TLS to {server_name} ({addr})");
        *phase.lock().unwrap() = format!("relaying TLS to {server_name} ({addr})");

        // Watch the relayed connection for silence, from the moment the target
        // connection exists. Two measured shapes end here, and both used to hold
        // the session until the 120 s session timeout:
        //   * the edge accepts the TCP connection, the ClientHello goes out and
        //     no ServerHello ever comes back (measured: 5 of 8 simultaneous
        //     sessions against `api-m.paypal.com`'s edge, HANDOVER §0.55);
        //   * the prover dies in tlsn's preprocessing and never sends the
        //     session it committed to (`preprocessing proxy-tls failed …
        //     connection is closed`), which leaves the notary waiting in
        //     `accept()` forever — observed live in a v238 wave.
        // Every measured healthy session moves bytes within 2 s of the dial, so
        // `stall_timeout` of silence is a verdict, not slowness.
        let activity = RelayActivity::new(st.stall_timeout);
        activity.arm();
        let verifier = tokio::select! {
            accepted = verifier.accept() => accepted?,
            _ = activity.clone().stalled() => {
                stalled.store(true, Ordering::SeqCst);
                return Err(format!(
                    "the prover sent nothing for {:?} after the target connection to {server_name} ({addr}) was established",
                    st.stall_timeout
                )
                .into());
            }
        };
        let relayed = Stamped::new(client, activity.clone());
        *phase.lock().unwrap() = format!("relayed TLS handshake to {server_name} ({addr})");
        let verifier = tokio::select! {
            outcome = verifier.run(relayed.compat()) => outcome?,
            _ = activity.clone().stalled() => {
                // Recorded rather than typed into an error: the outcome has to
                // say "stalled" ("retry this"), not "refused" ("don't bother"),
                // and the flag outlives this block's error.
                stalled.store(true, Ordering::SeqCst);
                return Err(format!(
                    "the relayed connection to {server_name} ({addr}) moved no byte for {:?}",
                    st.stall_timeout
                )
                .into());
            }
        };
        *phase.lock().unwrap() = format!("proof exchange after relaying to {server_name} ({addr})");
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
        // A stall is its own verdict, not a refusal: the presentation was never
        // judged, and the same commit would very likely pass on a retry.
        Ok(Err(e)) => {
            if stalled.load(Ordering::SeqCst) {
                SessionOutcome::Stalled(progress.lock().unwrap().clone())
            } else {
                SessionOutcome::Rejected(e)
            }
        }
        Err(_) => SessionOutcome::TimedOut(progress.lock().unwrap().clone()),
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

/// Resolves the commit's server name to the one address this session will dial.
///
/// The error is a *prover-facing* string, not a log line: it is sent back over
/// the commitment protocol (v236), so it stays short, names no internal path,
/// and tells the caller what to fix — the name has to be one of the boot-time
/// `relay_targets`, because the resolver is closed after boot by design.
async fn resolve_target(server_name: &str) -> Result<SocketAddr, String> {
    if let Ok(pinned) = std::env::var("TLS_PROXY_TARGET_ADDR") {
        if !pinned.trim().is_empty() {
            return pinned
                .parse()
                .map_err(|e| format!("TLS_PROXY_TARGET_ADDR is not a socket address: {e}"));
        }
    }
    match tokio::net::lookup_host((server_name, TARGET_PORT)).await {
        Ok(mut addrs) => addrs.next().ok_or_else(|| {
            format!("{server_name} resolves to no address; only the boot-time relay_targets list is reachable")
        }),
        Err(e) => Err(format!(
            "{server_name} is not in this notary's boot-time relay_targets (lookup failed: {e}); the resolver is closed after boot by design, so add the host to the configuration and reboot"
        )),
    }
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

/// `GET /pubkey` — the key that signs attestations, named by fingerprint so the
/// enclave's hardware-attested report can commit to it.
///
/// This route exists because the record alone cannot say whose key signed it:
/// `enclave_pubkey_pem` is per-boot and self-asserted. The PayPal service mints
/// a TDX quote over its own identity plus the measured disk, and it fetches this
/// endpoint while building that report, so the report names this key. A verifier
/// then has two independent things — a signed record, and a quoted report that
/// names the key — instead of one self-signed claim.
///
/// The fingerprint is over the SubjectPublicKeyInfo DER, so a verifier that
/// re-encodes the PEM lands on the same bytes (`verify-proxy.html` does exactly
/// that with WebCrypto). `pubkey_pem` is the exact string a record carries as
/// `enclave_pubkey_pem`.
async fn pubkey(State(st): State<Arc<ProxyState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "service": "tls-proxy",
        "version": "tls-proxy/1",
        "algorithm": "RSA-2048",
        "signature_alg": "RSA-PKCS1-v1_5-SHA256",
        "pubkey_pem": st.signer.pubkey_pem,
        "pubkey_sha256": st.signer.pubkey_der_sha256,
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

/// A caller may prove it is the prover instead of being on this machine: the
/// digest pair the record signs over.
#[derive(Debug, Deserialize)]
struct DownloadProof {
    sent_sha256: Option<String>,
    received_sha256: Option<String>,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// True when the caller holds the revealed transcript.
///
/// TLSNotary gives the prover no nonce of its own to carry a capability (the
/// protocol's only prover-chosen values are the committed transcript digests),
/// so the capability is the transcript itself: a caller that presents both
/// digests the record signs over has the bytes, because those bytes are what a
/// proof reveals. A caller that has neither has nothing to fetch.
fn digests_authorize(stored: &serde_json::Value, claimed: (&str, &str)) -> bool {
    let (sent, received) = claimed;
    if !is_hex64(sent) || !is_hex64(received) {
        return false;
    }
    let matches = |field: &str, claimed: &str| {
        stored
            .get(field)
            .and_then(|v| v.as_str())
            .is_some_and(|v| v.eq_ignore_ascii_case(claimed))
    };
    matches("sent_sha256", sent) && matches("received_sha256", received)
}

/// One answer for "not yours": an unknown id and a wrong digest must be
/// indistinguishable, or the endpoint becomes a way to test guesses about other
/// people's transcripts.
fn no_such_attestation(id: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "no such attestation in this boot",
            "session_id": id,
        })),
    )
}

/// Serve the attestation as **the text that was signed**, verbatim.
///
/// Not `Json(value)`: that would re-serialize through `serde_json::Value` and
/// emit the signed fields in alphabetical order, which the auditor page cannot
/// verify (v221). The bytes on the wire are the bytes the enclave hashed.
///
/// Two ways in: loopback with no query (the operator reading their own VM), or
/// anywhere with `?sent_sha256=&received_sha256=` matching the record — the
/// prover who ran the session knows both digests, and nobody else does.
async fn get_one(
    State(st): State<Arc<ProxyState>>,
    AxumPath(id): AxumPath<String>,
    Query(proof): Query<DownloadProof>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let store = st.attestations.lock().unwrap();
    let Some((_, json)) = store.iter().find(|(sid, _)| sid == &id) else {
        return Err(no_such_attestation(&id));
    };
    match (proof.sent_sha256.as_deref(), proof.received_sha256.as_deref()) {
        // The API binds loopback: this is the read the boot log's
        // "attestation <id>" line points at, and it stays queryless.
        (None, None) => {}
        (Some(sent), Some(received)) => {
            let stored: serde_json::Value =
                serde_json::from_str(json).unwrap_or(serde_json::Value::Null);
            if !digests_authorize(&stored, (sent, received)) {
                return Err(no_such_attestation(&id));
            }
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "sent_sha256 and received_sha256 go together",
                    "session_id": id,
                })),
            ))
        }
    }
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        json.clone(),
    )
        .into_response())
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
    let stall_timeout_secs: u64 = env_or(
        "TLS_PROXY_STALL_TIMEOUT",
        &DEFAULT_STALL_TIMEOUT.as_secs().to_string(),
    )
    .parse()
    .map_err(|e| format!("TLS_PROXY_STALL_TIMEOUT is not a number of seconds: {e}"))?;
    let dial_spacing_ms: u64 = env_or(
        "TLS_PROXY_DIAL_SPACING_MS",
        &DEFAULT_DIAL_SPACING_MS.to_string(),
    )
    .parse()
    .map_err(|e| format!("TLS_PROXY_DIAL_SPACING_MS is not a number of milliseconds: {e}"))?;
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
        stall_timeout: Duration::from_secs(stall_timeout_secs),
        pacer: DialPacer::new(Duration::from_millis(dial_spacing_ms)),
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
        .route("/pubkey", get(pubkey))
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
         (roots: {}, timeout: {session_timeout_secs}s, stall: {stall_timeout_secs}s, \
         dial spacing: {dial_spacing_ms}ms per target address)",
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

    /// Pacing is per ADDRESS: two sessions to one target are spaced, sessions to
    /// different targets are not delayed at all. The failure this exists for is
    /// bursts to a single edge, so a pacer that simply serialised everything
    /// would cost latency for nothing.
    #[tokio::test]
    async fn dial_pacer_spaces_one_address_only() {
        let pacer = DialPacer::new(Duration::from_millis(120));
        let a: IpAddr = "203.0.113.10".parse().unwrap();
        let b: IpAddr = "203.0.113.11".parse().unwrap();

        let first = pacer.claim(a).await;
        assert!(
            first < Duration::from_millis(5),
            "the first dial to an address goes at once, waited {first:?}"
        );
        // A different address is not waiting on the first one's slot.
        let other = pacer.claim(b).await;
        assert!(other < Duration::from_millis(20), "a distinct target waited {other:?}");

        let waited = pacer.claim(a).await;
        assert!(
            waited >= Duration::from_millis(100),
            "the second dial to the same address waited only {waited:?}"
        );

        // Consecutive claims reserve distinct slots: the second one waits a
        // whole spacing after the first, so a queued burst cannot collapse into
        // one dial.
        let starts = Instant::now();
        pacer.claim(b).await;
        pacer.claim(b).await;
        let both = starts.elapsed();
        assert!(
            both >= Duration::from_millis(100),
            "two consecutive dials to one address took {both:?}, not one spacing apart"
        );

        // And the shipped configuration is a no-op when the spacing is 0.
        let disabled = DialPacer::new(Duration::ZERO);
        assert_eq!(disabled.claim(a).await, Duration::ZERO);
        assert_eq!(disabled.claim(a).await, Duration::ZERO);
    }

    /// A relayed connection is not "stalled" before it is armed, is stale the
    /// moment it is armed, and any byte in either direction postpones the
    /// verdict. The live failure this models: TCP up, no ServerHello, ever.
    #[tokio::test]
    async fn relay_activity_arms_and_restamps() {
        let activity = RelayActivity::new(Duration::from_millis(120));
        assert!(activity.idle().is_none(), "unarmed is not idle");

        activity.arm();
        assert!(activity.idle().unwrap() < Duration::from_millis(50));

        // Bytes keep the session alive past the bound.
        let ok = tokio::time::timeout(Duration::from_millis(400), async {
            for _ in 0..4 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                activity.stamp();
            }
        })
        .await;
        assert!(ok.is_ok());

        // Then silence is a verdict, within the bound rather than the 120 s
        // session timeout.
        let started = Instant::now();
        tokio::time::timeout(Duration::from_secs(2), activity.clone().stalled())
            .await
            .expect("the stall watchdog never fired");
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(110) && took < Duration::from_secs(1),
            "the watchdog fired after {took:?}, not around the 120 ms bound"
        );

        // 0 disables it: a session may be silent forever and no verdict is
        // invented for it (the session timeout still applies).
        let off = RelayActivity::new(Duration::ZERO);
        off.arm();
        assert!(
            tokio::time::timeout(Duration::from_millis(150), off.stalled())
                .await
                .is_err(),
            "a disabled stall bound must never fire"
        );
    }

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

    const SENT: &str = "c2d43008022cb6af4267c4eb68a28f9d442f674a9f912e16225f097a9d35e756";
    const RECEIVED: &str = "16c4a1842ee93605a563e3c866dd2481521a836aee08a9281f1b19b3f2eba694";

    fn stored_with(digests: &str) -> serde_json::Value {
        serde_json::from_str(&stored_envelope("www.sandbox.paypal.com").replace(
            "\"sent_sha256\":\"00\",\"received_sha256\":\"00\"",
            digests,
        ))
        .expect("fixture parses")
    }

    /// The capability is the transcript: both digests of the record, nothing
    /// less. Pinned here because the failure mode is silent — a matcher that
    /// accepts a prefix or one field would serve transcripts to anyone who read
    /// the public list.
    #[test]
    fn digests_authorize_only_the_complete_pair() {
        let stored = stored_with(&format!(
            "\"sent_sha256\":\"{SENT}\",\"received_sha256\":\"{RECEIVED}\""
        ));
        assert!(digests_authorize(&stored, (SENT, RECEIVED)));
        // Case is not a capability: the digests are the same value.
        assert!(digests_authorize(
            &stored,
            (&SENT.to_uppercase(), &RECEIVED.to_uppercase())
        ));

        // One right, one wrong; both wrong; a prefix; a non-hex string.
        assert!(!digests_authorize(&stored, (SENT, &"0".repeat(64))));
        assert!(!digests_authorize(&stored, (&"0".repeat(64), RECEIVED)));
        assert!(!digests_authorize(&stored, (&SENT[..32], RECEIVED)));
        assert!(!digests_authorize(&stored, ("deadbeef", RECEIVED)));
        // Empty digests are legitimate for a fully redacted transcript, and
        // they must still be the pair the record signed over — not a bypass.
        let empty = stored_with("\"sent_sha256\":\"\",\"received_sha256\":\"\"");
        assert!(!digests_authorize(&empty, ("", "")));

        // A record that lost its digests authorizes nobody.
        let broken = stored_with("\"sent_sha256\":null,\"received_sha256\":null");
        assert!(!digests_authorize(&broken, (SENT, RECEIVED)));
    }
}
