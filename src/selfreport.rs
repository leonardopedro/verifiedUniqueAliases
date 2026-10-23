//! Boot-time self-report ("is the enclave alive, and if not, why?").
//!
//! Diagnosis of a dark instance has no reliable channel: the serial console is
//! a 64 KiB head-capped buffer that is often 100% verbose TDVF firmware text,
//! it is wiped when the instance stops, cloud-init does not re-run `user_data`
//! on a plain restart, and OSS objects in mainland buckets cannot be read from
//! an operator host outside mainland China. The one channel that always works
//! is a bucket that lives OUTSIDE the mainland, read over the normal internet:
//! the operator can `GET` it minutes after a boot with no console, no snapshot
//! and no in-VPC helper instance.
//!
//! This module publishes a small, SECRET-FREE status document there:
//!   - on every stage transition (boot progress, so "how far did it get?"),
//!   - on ACME failures (the usual reason a box serves nothing),
//!   - on a fail-closed halt (the exact reason, before the process parks), and
//!   - on success, so a silent box is distinguishable from a healthy one.
//!
//! Design constraints, all deliberate:
//!   * **Best effort, never blocking.** Uploads happen on a detached thread
//!     with a hard timeout. A failed report must never delay, alter or abort a
//!     boot decision; it only costs one kmsg line.
//!   * **No secrets, ever.** The payload carries status strings, counters and
//!     opaque booleans — never a token, key, domain credential or config
//!     value. `payload_never_contains_sink_secrets` pins that.
//!   * **Signed in-guest.** A presigned URL embeds an STS token that expires
//!     within hours, which is exactly how stale `user_data` URLs failed
//!     silently in the field; the enclave instead signs each request itself
//!     with the sink's write-only credential (OSS V1, HMAC-SHA1).
//!
//! The sink credential should be scoped to `PutObject` on the report prefix
//! only. Configuration (JSON, `self_report` in the enclave config, or the
//! `PAV_SELFREPORT_JSON` env var / `/boot/efi/selfreport.json`):
//!
//! ```json
//! {
//!   "bucket": "paypal-tdx-relay-1792227992",
//!   "endpoint": "oss-cn-hongkong.aliyuncs.com",
//!   "prefix": "boot",
//!   "access_key_id": "...",
//!   "access_key_secret": "...",
//!   "sts_token": null
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Where to publish. `endpoint` is the bare region endpoint
/// (`oss-cn-hongkong.aliyuncs.com`); the bucket is prepended as the
/// virtual-host label, which is the only addressing style OSS accepts.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SinkConfig {
    pub bucket: String,
    pub endpoint: String,
    #[serde(default = "default_prefix")]
    pub prefix: String,
    pub access_key_id: String,
    pub access_key_secret: String,
    #[serde(default)]
    pub sts_token: Option<String>,
}

fn default_prefix() -> String {
    "boot".to_string()
}

impl SinkConfig {
    fn looks_configured(&self) -> bool {
        !self.bucket.trim().is_empty()
            && !self.endpoint.trim().is_empty()
            && !self.access_key_id.trim().is_empty()
            && !self.access_key_secret.trim().is_empty()
    }

    fn host(&self) -> String {
        format!("{}.{}", self.bucket.trim(), self.endpoint.trim())
    }

    /// OSS V1 canonical string. `expires` is an absolute unix timestamp (the
    /// `Expires` query parameter form, so no client clock sync is needed).
    /// `CanonicalizedOSSHeaders` is empty because we send none.
    ///
    /// `content_type` must be the EXACT value of the request's `Content-Type`
    /// header (empty when the request sends none) — OSS signs that header, and
    /// a mismatch is a bare 403 with no explanation (caught by the live
    /// round-trip test on 2026-10-23).
    pub fn string_to_sign(&self, method: &str, content_type: &str, expires: u64, key: &str) -> String {
        let mut resource = format!("/{}/{}", self.bucket.trim(), key);
        if let Some(t) = self.sts_token.as_deref().filter(|t| !t.is_empty()) {
            resource.push_str(&format!("?security-token={}", t));
        }
        format!("{}\n\n{}\n{}\n{}", method, content_type, expires, resource)
    }

    /// Fully-signed virtual-host URL for `key`.
    pub fn signed_url(&self, method: &str, content_type: &str, key: &str, ttl_secs: u64) -> String {
        let expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            + ttl_secs;
        self.signed_url_at(method, content_type, key, expires)
    }

    /// Same, with an explicit expiry — the deterministic form the tests pin.
    pub fn signed_url_at(&self, method: &str, content_type: &str, key: &str, expires: u64) -> String {
        let sts = self.string_to_sign(method, content_type, expires, key);
        let sig = sign_hmac_sha1(&self.access_key_secret, &sts);
        let mut url = format!(
            "https://{}/{}?OSSAccessKeyId={}&Expires={}&Signature={}",
            self.host(),
            key,
            urlencoding::encode(self.access_key_id.trim()),
            expires,
            urlencoding::encode(&sig)
        );
        if let Some(t) = self.sts_token.as_deref().filter(|t| !t.is_empty()) {
            url.push_str(&format!("&security-token={}", urlencoding::encode(t)));
        }
        url
    }
}

/// base64(HMAC-SHA1(secret, canonical_string)) — OSS V1 signature.
pub fn sign_hmac_sha1(secret: &str, canonical: &str) -> String {
    use base64::Engine as _;
    use openssl::hash::MessageDigest;
    use openssl::sign::Signer;
    let pkey = match openssl::pkey::PKey::hmac(secret.as_bytes()) {
        Ok(k) => k,
        Err(_) => return String::new(),
    };
    let mut signer = match Signer::new(MessageDigest::sha1(), &pkey) {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    if signer.update(canonical.as_bytes()).is_err() {
        return String::new();
    }
    match signer.sign_to_vec() {
        Ok(v) => base64::engine::general_purpose::STANDARD.encode(v),
        Err(_) => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Global boot state
// ---------------------------------------------------------------------------

static SINK: OnceLock<Option<SinkConfig>> = OnceLock::new();
static STAGE: OnceLock<parking_lot::Mutex<String>> = OnceLock::new();
static LAST_FAILURE: OnceLock<parking_lot::Mutex<Option<String>>> = OnceLock::new();
static HALTED: AtomicBool = AtomicBool::new(false);
static STARTED: OnceLock<Instant> = OnceLock::new();

use std::time::Instant;

fn stage_cell() -> &'static parking_lot::Mutex<String> {
    STAGE.get_or_init(|| parking_lot::Mutex::new("mount".to_string()))
}

fn failure_cell() -> &'static parking_lot::Mutex<Option<String>> {
    LAST_FAILURE.get_or_init(|| parking_lot::Mutex::new(None))
}

fn uptime_secs() -> u64 {
    STARTED.get_or_init(Instant::now);
    Instant::now()
        .duration_since(*STARTED.get().unwrap())
        .as_secs()
}

/// Install the sink. Callable once; later calls are ignored. `None` disables
/// reporting entirely (the enclave still boots normally).
pub fn init(sink: Option<SinkConfig>) {
    let sink = sink.filter(|s| s.looks_configured());
    let _ = SINK.set(sink);
    STARTED.get_or_init(Instant::now);
    if SINK.get().and_then(|s| s.as_ref()).is_none() {
        log_line("selfreport: no sink configured — boot status stays local-only");
    }
}

/// Resolve a sink from the environment or the measured ESP, so a boot that
/// fails BEFORE `user_data` is read can still report (the exact blind spot
/// that made earlier outages undiagnosable). Never fatal.
pub fn init_from_bootstrap_file(path: &str) {
    if SINK.get().is_some() {
        return;
    }
    let raw = std::env::var("PAV_SELFREPORT_JSON")
        .ok()
        .or_else(|| std::fs::read_to_string(path).ok());
    // Only claim the slot when a usable sink was found: a missing bootstrap
    // file must NOT block the `user_data`-supplied sink later in the boot.
    if let Some(sink) = raw
        .as_deref()
        .and_then(|s| serde_json::from_str::<SinkConfig>(s.trim()).ok())
    {
        init(Some(sink));
    }
}

/// Record the current boot stage (cheap; no upload). The stage is included in
/// every later report, so a halted box says exactly how far it got.
pub fn stage(name: &str) {
    *stage_cell().lock() = name.to_string();
}

pub fn current_stage() -> String {
    stage_cell().lock().clone()
}

/// Record the reason a boot is about to fail closed. Does not upload by
/// itself — `halt()` publishes it, so the last reason always wins.
pub fn note_failure(reason: impl Into<String>) {
    *failure_cell().lock() = Some(reason.into());
}

fn payload(kind: &str, ok: bool, reason: Option<&str>) -> serde_json::Value {
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    serde_json::json!({
        "schema": "pav-selfreport/1",
        "kind": kind,
        "ok": ok,
        "stage": current_stage(),
        "reason": reason,
        "ts_unix": SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        "uptime_s": uptime_secs(),
        "hostname": host,
        "kernel": kernel,
    })
}

/// Publish one document off-thread. Never blocks, never panics, never affects
/// the caller's control flow.
fn publish(kind: &str, ok: bool, reason: Option<&str>) {
    let Some(Some(sink)) = SINK.get() else { return };
    let sink = sink.clone();
    let body = payload(kind, ok, reason).to_string();
    let kind = kind.to_string();
    std::thread::spawn(move || {
        if let Err(e) = sink.upload(&body, &kind) {
            log_line(&format!("selfreport: upload failed at stage '{}': {}", current_stage(), e));
        }
    });
}

impl SinkConfig {
    /// Two objects per report: a timestamped one (history survives a later
    /// overwrite) and a stable `latest.json` an operator can poll blindly.
    fn upload(&self, body: &str, kind: &str) -> Result<(), String> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let prefix = self.prefix.trim_matches('/');
        let stamp = format!("{}/{}-{}-{}.json", prefix, self.current_host_tag(), ts, kind);
        let latest = format!("{}/latest.json", prefix);
        put(self, &stamp, body)?;
        put(self, &latest, body)?;
        Ok(())
    }

    fn current_host_tag(&self) -> String {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|s| s.trim().replace('.', "-"))
            .unwrap_or_else(|_| "unknown".to_string())
    }
}

fn put(sink: &SinkConfig, key: &str, body: &str) -> Result<(), String> {
    // Blocking client in a detached thread: safe outside the tokio runtime and
    // bounded so a dead network can never pin the reporter.
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .put(sink.signed_url("PUT", "application/json", key, 3600))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .map_err(|e| e.to_string())?;
    let code = resp.status().as_u16();
    if (200..300).contains(&code) {
        Ok(())
    } else {
        Err(format!("HTTP {} for {}", code, key))
    }
}

/// Publish a progress heartbeat (kind `stage`). Safe to call often.
pub fn progress() {
    publish("stage", true, None);
}

/// Publish a non-fatal failure (ACME retries, DNS-01 errors, …) and record it
/// as the current failure so a later halt reports the same reason.
pub fn failure(reason: impl Into<String>) {
    let reason = reason.into();
    note_failure(reason.clone());
    publish("fatal", false, Some(&reason));
}

/// Publish a healthy boot (TLS cert in RAM, serving).
pub fn serving() {
    publish("ok", true, None);
}

/// Publish the halt reason exactly once, then return (the caller does the
/// parking). Called from `enclave_init::poweroff()`.
pub fn halt() {
    if HALTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let reason = failure_cell().lock().clone();
    let reason = reason.unwrap_or_else(|| format!("halted at stage '{}'", current_stage()));
    log_line(&format!("selfreport: FAIL-CLOSED — {}", reason));
    publish("halt", false, Some(&reason));
}

fn log_line(msg: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open("/dev/kmsg") {
        use std::io::Write as _;
        let _ = writeln!(f, "<6>[selfreport] {}", msg);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sink(token: Option<&str>) -> SinkConfig {
        SinkConfig {
            bucket: "paypal-tdx-relay-1792227992".into(),
            endpoint: "oss-cn-hongkong.aliyuncs.com".into(),
            prefix: "boot".into(),
            access_key_id: "STS.TESTKEYID".into(),
            access_key_secret: "TEST_SECRET_DO_NOT_LEAK".into(),
            sts_token: token.map(|t| t.to_string()),
        }
    }

    #[test]
    fn canonical_string_without_token() {
        let s = sink(None);
        assert_eq!(
            s.string_to_sign("PUT", "application/json", 1792704152, "boot/latest.json"),
            "PUT\n\napplication/json\n1792704152\n/paypal-tdx-relay-1792227992/boot/latest.json"
        );
    }

    #[test]
    fn canonical_string_with_token_carries_security_token() {
        let s = sink(Some("STS-TOKEN-XYZ"));
        assert_eq!(
            s.string_to_sign("PUT", "application/json", 1792704152, "boot/latest.json"),
            "PUT\n\napplication/json\n1792704152\n/paypal-tdx-relay-1792227992/boot/latest.json?security-token=STS-TOKEN-XYZ"
        );
    }

    #[test]
    fn canonical_string_leaves_content_type_empty_for_get() {
        let s = sink(None);
        assert_eq!(
            s.string_to_sign("GET", "", 1792704152, "boot/latest.json"),
            "GET\n\n\n1792704152\n/paypal-tdx-relay-1792227992/boot/latest.json"
        );
    }

    #[test]
    fn signature_matches_independent_implementation() {
        // Vectors computed OUTSIDE this crate (node crypto.createHmac('sha1'))
        // so the test pins the wire format, not just self-consistency.
        assert_eq!(
            sign_hmac_sha1("secret", "PUT\n\n\n1\n/b/k"),
            "W4whexMWq5Q8dHBpQK0gWLoa4Pc="
        );
        assert_eq!(
            sign_hmac_sha1(
                "TEST_SECRET_DO_NOT_LEAK",
                "PUT\n\napplication/json\n1792704152\n/paypal-tdx-relay-1792227992/boot/latest.json"
            ),
            "R33iCng3EmfOwq8Jnj3i4VtZmdA="
        );
    }

    #[test]
    fn signed_url_percent_encodes_signature_slashes() {
        // The pinned vector contains '/', which MUST be escaped or OSS receives
        // a truncated Signature parameter and answers a very quiet 403.
        // secret "k2" gives a signature containing '/', '=' and '+' — every
        // character that must be escaped for OSS to parse it back.
        let s = SinkConfig {
            access_key_secret: "k2".into(),
            ..sink(None)
        };
        let url = s.signed_url_at("PUT", "application/json", "boot/latest.json", 1792704152);
        assert!(
            url.contains("Signature=yqIXpXWjbT4L1RdzLLB6duxu%2FRE%3D"),
            "unexpected signature encoding in {}",
            url
        );
    }

    #[test]
    fn signature_with_plus_is_escaped() {
        let s = SinkConfig {
            access_key_secret: "k3".into(),
            ..sink(None)
        };
        let url = s.signed_url_at("PUT", "application/json", "boot/latest.json", 1792704152);
        assert!(url.contains("%2B"), "'+' must not survive as a space: {}", url);
    }

    #[test]
    fn signed_url_is_virtual_host_and_carries_expiry() {
        let s = sink(None);
        let url = s.signed_url("PUT", "application/json", "boot/latest.json", 60);
        assert!(url.starts_with(
            "https://paypal-tdx-relay-1792227992.oss-cn-hongkong.aliyuncs.com/boot/latest.json?"
        ));
        assert!(url.contains("OSSAccessKeyId="));
        assert!(url.contains("&Expires="));
        assert!(url.contains("&Signature="));
    }

    /// Opt-in end-to-end check against the REAL sink bucket (inert in CI and
    /// in normal runs): set `PAV_SELFREPORT_LIVE_SINK` to the sink JSON and
    /// this performs one signed PUT + one signed GET through the production
    /// code path. This is what proves the in-guest signer — not just the
    /// string format — is accepted by OSS.
    #[test]
    fn live_roundtrip_when_enabled() {
        let Ok(json) = std::env::var("PAV_SELFREPORT_LIVE_SINK") else { return };
        let sink: SinkConfig = serde_json::from_str(&json).expect("sink json");
        let body = "{\"selftest\":true}";
        sink.upload(body, "selftest").expect("live PUT accepted by OSS");
        let url = sink.signed_url("GET", "", &format!("{}/latest.json", sink.prefix.trim_matches('/')), 600);
        let got = reqwest::blocking::Client::new()
            .get(url)
            .send()
            .expect("live GET")
            .text()
            .expect("body");
        assert!(got.contains("selftest"), "unexpected body: {}", got);
    }

    #[test]
    fn payload_never_contains_sink_secrets() {
        let s = sink(Some("STS-TOKEN-XYZ"));
        init(Some(s.clone()));
        note_failure("ACME certificate failed: Cloudflare zone not found");
        let body = payload("halt", false, Some("ACME certificate failed")).to_string();
        assert!(!body.contains("TEST_SECRET_DO_NOT_LEAK"));
        assert!(!body.contains("STS.TESTKEYID"));
        assert!(!body.contains("STS-TOKEN-XYZ"));
        assert!(body.contains("\"schema\":\"pav-selfreport/1\""));
        assert!(body.contains("\"kind\":\"halt\""));
    }
}
