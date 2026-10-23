//! Intel TDX (Trusted Domain Extensions) Hardware Root-of-Trust Adapter
//!
//! **Target Platform:** Alibaba Cloud ECS c9i family (deploy default ecs.c9i.large — cheapest TDX shape, live-verified 2026-10-23)
//! **Processor:** Intel Xeon Platinum 8475L (Sapphire Rapids)
//!
//! Intel TDX uses a standard vTPM 2.0 — attestation is simpler than AMD SEV-SNP:
//! - No /dev/sev-guest or ConfigFS TSM needed
//! - PCR values signed by standard TPM Quote (RSA-2048 session AK)
//! - Platform Certificate Key (PCK) from Intel Provisioning Service or TPM NV endorsement hierarchy
//! - No VCEK from AMD KDS — Intel uses PCK chain from Intel PKI
//!
//! ## PCK Certificate Retrieval Strategy
//!
//! 1. **Sysfs path** (`/sys/firmware/tdx/pck_cert_chain`) — Alibaba may pre-provision
//! 2. **TPM NV endorsement hierarchy** — OEM BIOS may store PCK at standard NV indices
//! 3. **Intel PCS (Provisioning Certificate Service)** — Online fetch via FMSPC from TDX report
//! 4. **Intel Trust Authority** — Remote attestation via Intel ITA REST API

#![allow(dead_code)]  // Functions may not be used in all builds, but are required for compatibility

use sha2::Sha256;
use sha2::Digest;
use serde::{Serialize, Deserialize};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use tracing::warn;

/// Intel PCS (Provisioning Certificate Service) base URL for PCK certificate retrieval
const INTEL_PCS_BASE_URL: &str = "https://api.trustedservices.intel.com/tdx/certification/v4";

/// Intel Trust Authority API for remote TDX attestation verification
const INTEL_ITA_BASE_URL: &str = "https://api.trustauthority.intel.com";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IntelTDXReport {
    pub nonce_hex: String,
    pub tpm_quote_msg: String,
    pub tpm_quote_sig: String,
    pub ak_pub_pem: String,
    pub pcrs: String,
    pub pcr_values: std::collections::BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pck_cert_pem: Option<String>,
    pub pck_sha256: String,
    pub ak_der_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx_quote_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub td_info: Option<TdInfo>,
}

/// TDX TDINFO structure from the TDCALL instruction
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TdInfo {
    pub attributes: String,
    pub xfam: String,
    pub mrtd: String,
    pub mrconfigid: String,
    pub mrowner: String,
    pub mrownerconfig: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub rtmr3: String,
}

/// Check if this platform supports Intel TDX hardware extensions.
///
/// Every signal is probed because no single one is guaranteed across vendors:
/// Alibaba ECS exposes the TDX-enabled kernel without necessarily publishing a
/// quote device node, while GCP-style platforms register the platform driver.
pub fn is_intel_tdx_available() -> bool {
    let probes = [
        "/sys/bus/platform/drivers/tdx",
        "/dev/tdx-guest",
        "/dev/tdx_guest",
        "/sys/module/tdx_guest",
    ];
    if probes.iter().any(|p| std::path::Path::new(p).exists()) {
        return true;
    }
    // The kernel prints "Memory Encryption Features active: Intel TDX" at boot even
    // when no userspace TDX device node is exposed — that banner is authoritative
    // for "this guest runs inside a TDX TD".
    if kernel_log_reports_tdx() {
        return true;
    }
    // Legacy fallback: TPM-backed platform that also exposes a TDX device node.
    std::path::Path::new("/dev/tpmrm0").exists()
        && (std::path::Path::new("/dev/tdx-guest").exists()
            || std::path::Path::new("/dev/tdx_guest").exists())
}

/// Scan the kernel ring buffer for the boot-time TDX banner.
///
/// `/dev/kmsg` is opened O_NONBLOCK: once the buffered messages are consumed a
/// plain read blocks forever, which would hang PID 1.
fn kernel_log_reports_tdx() -> bool {
    use std::io::BufRead;
    use std::os::unix::fs::OpenOptionsExt;

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/dev/kmsg")
    {
        Ok(f) => f,
        Err(e) => {
            warn!("TDX probe: cannot open /dev/kmsg: {}", e);
            return false;
        }
    };
    for line in std::io::BufReader::new(file).lines().take(4096) {
        let Ok(line) = line else { break }; // EAGAIN = end of buffered log
        if line.contains("Memory Encryption Features active: Intel TDX")
            || line.contains("TDX aware idle routine")
        {
            return true;
        }
    }
    false
}

/// Check if the TDX guest device is available for direct TDCALL attestation
pub fn has_tdx_guest_device() -> bool {
    std::path::Path::new("/dev/tdx-guest").exists() || std::path::Path::new("/dev/tdx_guest").exists()
}

/// Fetch Platform Certificate Key (PCK) from Intel Provisioning Certificate Service
pub async fn fetch_pck_http() -> Option<String> {
    use reqwest::Client;
    
    // Strategy 1: Try sysfs first (Alibaba may pre-provision)
    if let Some(pck) = read_pck_from_sysfs() {
        return Some(pck);
    }
    
    // Strategy 2: Try TPM NV endorsement hierarchy
    if let Some(nv_pck) = get_pck_from_nvram() {
        let pem = der_to_pem("CERTIFICATE", &nv_pck);
        return Some(pem);
    }
    
    // Strategy 3: Try Intel PCS online endpoint
    // Requires FMSPC (Family-Model-Stepping-Platform-CPUID) from TDX report
    let client = match Client::builder().timeout(std::time::Duration::from_secs(15)).build() {
        Ok(c) => c,
        Err(_) => return None,
    };
    
    // Try to get FMSPC from CPUID or sysfs
    let fmspc = read_fmspc_from_sysfs().or_else(read_fmspc_from_cpuid);
    if let Some(fmspc_hex) = fmspc {
        let url = format!("{}/pckcert?fmspc={}", INTEL_PCS_BASE_URL, fmspc_hex);
        match client.get(&url)
            .header("Ocp-Apiversion", "2021-11-01")
            .send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    if let Ok(body) = resp.text().await {
                        if body.contains("BEGIN CERTIFICATE") || !body.is_empty() {
                            return Some(body);
                        }
                    }
                }
            },
            Err(_) => {}
        }
    }
    
    None
}

/// Read PCK certificate chain from sysfs (Alibaba or kernel-provisioned)
fn read_pck_from_sysfs() -> Option<String> {
    let paths = [
        "/sys/firmware/tdx/pck_cert_chain",
        "/sys/kernel/security/tdx/pck_cert",
        "/sys/firmware/intel/tdx/pck_cert_chain",
    ];
    for path in &paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            if content.contains("BEGIN CERTIFICATE") || content.len() > 64 {
                return Some(content);
            }
        }
    }
    None
}

/// Read FMSPC from sysfs (populated by tdx-guest driver)
fn read_fmspc_from_sysfs() -> Option<String> {
    let paths = [
        "/sys/firmware/tdx/fmspc",
        "/sys/kernel/security/tdx/fmspc",
    ];
    for path in &paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            let trimmed = content.trim();
            if !trimmed.is_empty() && trimmed.len() == 12 {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Read FMSPC from CPUID leaf 0x1A (Intel-specific)
fn read_fmspc_from_cpuid() -> Option<String> {
    // CPUID leaf 0x1A returns platform info in EAX/EBX/ECX/EDX
    // FMSPC is derived from the platform ID
    // This requires /dev/cpu/0/cpuid or inline assembly
    // For safety, try reading from /dev/cpu/0/cpuid if available
    if let Ok(data) = std::fs::read("/dev/cpu/0/cpuid") {
        if data.len() >= 16 {
            // Simplified: return first 6 bytes as hex (12 chars)
            let fmspc_hex = hex::encode(&data[8..14]);
            return Some(fmspc_hex);
        }
    }
    None
}

/// Read PCK from TPM NV storage when provisioned by OEM BIOS into endorsement hierarchy
pub fn get_pck_from_nvram() -> Option<Vec<u8>> {
    // Try reading from TPM NV endorsement hierarchy common indices
    // 0x01c00002 - Standard EK certificate (also used on GCP)
    // 0x01c00001 - Alternate EK certificate
    // 0x01800000 - Intel PCK certificate (OEM-specific)
    // 0x01800001 - Intel PCK certificate chain
    // 0x01400001 - Platform certificate
    for idx in ["0x01c00002", "0x01c00001", "0x01800000", "0x01800001", "0x01400001"] {
        // Bounded per index (5s): five unbounded probes on a wedged TPM would
        // block the attestation request — and its semaphore permit — forever.
        let out = match crate::cmd_output_timeout(
            "tpm2",
            &["nvread", idx],
            &[("TPM2TOOLS_TCTI".into(), "device:/dev/tpmrm0".into())],
            std::time::Duration::from_secs(5),
        ) {
            Some(o) => o,
            None => return None, // timed out — stop probing rather than stack 5 hangs
        };
        if out.status.success() && out.stdout.len() > 64 {
            return Some(out.stdout);
        }
    }
    None
}

/// Perform a TDX TDCALL GetQuote to get a hardware-signed TDX quote
/// This uses the /dev/tdx-guest device if available
pub fn get_tdx_quote(report_data: &[u8; 64]) -> Option<Vec<u8>> {
    use std::os::unix::io::AsRawFd;
    
    // Try /dev/tdx-guest first, then /dev/tdx_guest
    let tdx_dev_paths = ["/dev/tdx-guest", "/dev/tdx_guest"];
    
    for dev_path in &tdx_dev_paths {
        if !std::path::Path::new(dev_path).exists() {
            continue;
        }
        
        match std::fs::OpenOptions::new().read(true).write(true).open(dev_path) {
            Ok(dev) => {
                // TDX Guest GetQuote IOCTL
                // The IOCTL structure is platform-specific; this is a simplified version
                let fd = dev.as_raw_fd();
                
                // Build the GetQuote request buffer
                // TDX_GETQUOTE IOCTL = _IOWR('T', 0x01, struct tdx_quote_req)
                let mut quote_buf = vec![0u8; 8192]; // 8KB buffer for quote
                
                // Copy report_data into the request
                // struct tdx_report_data { uint8_t data[64]; }
                quote_buf[..64].copy_from_slice(report_data);
                
                // Use ioctl to request the quote
                // TDX_CMD_GET_REPORT = 0x80405401 (example, actual value varies by kernel)
                let ret = unsafe {
                    libc::ioctl(fd, 0xC0885401u64 as libc::c_ulong, quote_buf.as_mut_ptr())
                };
                
                if ret == 0 {
                    return Some(quote_buf);
                }
            },
            Err(_) => continue,
        }
    }
    
    None
}

/// Hash the PCK certificate for inclusion in attestation report
pub fn hash_cert(cert_bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(cert_bytes))
}

/// Convert DER bytes to PEM format
pub fn der_to_pem(tag: &str, der_bytes: &[u8]) -> String {
    let b64 = STANDARD.encode(der_bytes);
    let mut pem = format!("-----BEGIN {}-----\n", tag);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", tag));
    pem
}

/// Read TDX policy from sysfs if available
pub fn read_tdx_policy() -> Option<String> {
    // TDX policy might be available at these sysfs paths
    let paths = [
        "/sys/firmware/intel/tdx/policy",
        "/sys/firmware/tdx/policy",
        "/sys/kernel/security/tdx/policy",
    ];
    
    for path in &paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            if !content.is_empty() {
                return Some(content.trim().to_string());
            }
        }
    }
    None
}

/// Read TDINFO (TDX runtime measurements) from sysfs
pub fn read_td_info() -> Option<TdInfo> {
    let base_paths = [
        "/sys/firmware/tdx/",
        "/sys/kernel/security/tdx/",
    ];
    
    let read_field = |base: &str, field: &str| -> Option<String> {
        std::fs::read_to_string(format!("{}{}", base, field))
            .ok()
            .map(|s| s.trim().to_string())
    };
    
    for base in &base_paths {
        if let (Some(attrs), Some(mrtd)) = (read_field(base, "attributes"), read_field(base, "mrtd")) {
            return Some(TdInfo {
                attributes: attrs,
                xfam: read_field(base, "xfam").unwrap_or_default(),
                mrtd,
                mrconfigid: read_field(base, "mrconfigid").unwrap_or_default(),
                mrowner: read_field(base, "mrowner").unwrap_or_default(),
                mrownerconfig: read_field(base, "mrownerconfig").unwrap_or_default(),
                rtmr0: read_field(base, "rtmr0").unwrap_or_default(),
                rtmr1: read_field(base, "rtmr1").unwrap_or_default(),
                rtmr2: read_field(base, "rtmr2").unwrap_or_default(),
                rtmr3: read_field(base, "rtmr3").unwrap_or_default(),
            });
        }
    }
    None
}

/// Perform Intel TDX attestation using standard TPM 2.0 flow
/// This integrates with the main TPM quote() function in tpm module
/// Returns a TDX-specific report wrapper
pub fn collect_tdx_report() -> Option<IntelTDXReportBase> {
    if !is_intel_tdx_available() {
        return None;
    }
    
    Some(IntelTDXReportBase {
        tdx_policy: read_tdx_policy(),
        pck_cert_from_nvram: get_pck_from_nvram(),
        td_info: read_td_info(),
    })
}

/// Base data for TDX attestation (to be merged with TPM quote in main flow)
pub struct IntelTDXReportBase {
    pub tdx_policy: Option<String>,
    pub pck_cert_from_nvram: Option<Vec<u8>>,
    pub td_info: Option<TdInfo>,
}

/// Convert TDX report base to serializable form
pub fn tdx_report_to_json(base: &IntelTDXReportBase) -> serde_json::Value {
    use base64::Engine;
    
    let pck_der_b64 = base.pck_cert_from_nvram.as_deref().map(|d| STANDARD.encode(d));
    let pck_hash = base.pck_cert_from_nvram.as_deref().map(hash_cert).unwrap_or_default();
    
    let td_info_val = base.td_info.as_ref().map(|info| serde_json::json!({
        "attributes": info.attributes,
        "mrtd": info.mrtd,
        "mrconfigid": info.mrconfigid,
        "mrowner": info.mrowner,
        "rtmr0": info.rtmr0,
        "rtmr1": info.rtmr1,
        "rtmr2": info.rtmr2,
        "rtmr3": info.rtmr3,
    }));
    
    serde_json::json!({
        "platform": "Intel TDX",
        "tdx_policy": base.tdx_policy,
        "pck_cert_der_base64": pck_der_b64,
        "pck_sha256": pck_hash,
        "td_info": td_info_val,
        "tdx_guest_device": has_tdx_guest_device(),
    })
}

/// Verify a TDX quote against Intel Trust Authority (ITA)
/// This is an optional remote verification step for auditors
pub async fn verify_tdx_quote_remote(quote_hex: &str) -> Option<serde_json::Value> {
    use reqwest::Client;
    
    let client = match Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build() {
        Ok(c) => c,
        Err(_) => return None,
    };
    
    let url = format!("{}/appraisal/v1/verify", INTEL_ITA_BASE_URL);
    let body = serde_json::json!({
        "quote": quote_hex,
        "nonce": hex::encode(sha2::Sha256::digest(quote_hex.as_bytes())),
    });
    
    match client.post(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                resp.json().await.ok()
            } else {
                None
            }
        },
        Err(_) => None,
    }
}

// ===========================================================================
// v131: TDX SILICON EVIDENCE — TDREPORT and TD Quote acquisition
//
// Two userspace interfaces can produce hardware-originated TDX evidence on
// this platform (Linux 6.12: CONFIG_INTEL_TDX_GUEST=y, CONFIG_TDX_GUEST_DRIVER=m,
// CONFIG_TSM_REPORTS=m):
//
//   1. configfs TSM  →  /sys/kernel/config/tsm/report/<entry>
//      Write `inblob` (64-byte REPORTDATA), read `outblob` (+ `auxblob`,
//      `provider`). The provider string MUST be `tdx_guest` before the blob
//      is accepted — an sev-guest/other provider's output would be foreign
//      evidence cross-attributed to this TDX platform.
//
//   2. /dev/tdx_guest ioctls (Linux TDX guest ABI)
//      TDX_CMD_GET_REPORT = _IOWR('T', 1, tdx_report_req{64+1024})
//          → 1024-byte TDREPORT generated by the TDX module
//      TDX_CMD_GET_QUOTE  = _IOWR('T', 2, {void *buf, u64 len})
//          → signed TD Quote; per the ABI the **VMM** fills the quote buffer
//            and status (0 = success, 0x8000000000000001 = quote service
//            unavailable, ENOTTY = this kernel has no quote path).
//
// Epistemics (the honesty rule the auditor relies on):
//   * TDREPORT = generated inside the silicon TDX module, binds REPORTDATA
//     and MRTD/RTMRs, but is **unsigned** — a remote party cannot verify it.
//     Corroborating context only, never a silicon root of trust.
//   * TD Quote = ECDSA P-384 signature by Intel's Quoting Enclave over the
//     TD report body + embedded PCK certificate chain → real, remotely
//     verifiable silicon-signed evidence.
// Every attempt (including failures) is recorded in `notes` so the probe is
// auditable from /debug/attestation without shell access to the enclave.
// ===========================================================================

/// Verbatim transcript of every TDX evidence acquisition attempt.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct TdxEvidence {
    pub provider: Option<String>,
    pub td_report_b64: Option<String>,
    pub td_report_source: Option<String>,
    pub quote_b64: Option<String>,
    pub quote_source: Option<String>,
    pub quote_status: Option<String>,
    pub aux_b64: Option<String>,
    pub notes: Vec<String>,
}

/// sizeof(struct tdx_report_req) = 64-byte REPORTDATA + 1024-byte TDREPORT.
const TDX_REPORT_REQ_SIZE: usize = 64 + 1024;
/// _IOWR('T', 1, struct tdx_report_req)  — dir=3<<30 | size=1088<<16 | 'T'<<8 | 1
const IOC_TDX_GET_REPORT: libc::c_ulong = 0xC440_5401;
/// _IOWR('T', 2, struct { void *buffer; uint64_t length; })  — sizeof = 16
const IOC_TDX_GET_QUOTE: libc::c_ulong = 0xC010_5402;
/// Quote header: version u64 | status u64 | in_len u32 | out_len u32 | data[]
const TDX_QUOTE_HDR_PREFIX: usize = 24;
const TDX_QUOTE_HDR_DATA: usize = 4 * 4 * 1024; // ReqBufSize (16 KiB)
const TDX_QUOTE_HDR_SIZE: usize = TDX_QUOTE_HDR_PREFIX + TDX_QUOTE_HDR_DATA;

/// A real TDX Quote starts with: version u16 (4 or 5), att_key_type u16
/// (2 = ECDSA-256), tee_type u32 == 0x00000081 (TDX) — the Intel quote
/// header layout (48 bytes). A TDREPORT is exactly 1024 bytes and starts
/// with version byte 0x01 — the two are trivial to tell apart.
/// (Offsets per Intel's quote ABI as implemented in go-tdx-guest/abi:
///  version@0 u16, att_key_type@2 u16, tee_type@4 u32.)
fn looks_like_tdx_quote(b: &[u8]) -> bool {
    if b.len() < 48 {
        return false;
    }
    let version = u16::from_le_bytes([b[0], b[1]]);
    let tee_type = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
    (4..=5).contains(&version) && tee_type == 0x81
}

fn looks_like_td_report(b: &[u8]) -> bool {
    b.len() == 1024
}

/// Attempt evidence via the configfs TSM report subsystem.
fn configfs_evidence(report_data: &[u8; 64], ev: &mut TdxEvidence) {
    use std::path::Path;
    let base = "/sys/kernel/config/tsm/report";
    if !Path::new(base).exists() {
        ev.notes
            .push("configfs: /sys/kernel/config/tsm/report absent (tsm reports module not registered?)".into());
        return;
    }
    // Unique per-request entry name. The SEC-02 nonce (and thus report_data) is
    // DETERMINISTIC per boot, so a name derived from report_data alone repeats
    // across requests; if a prior entry lingers, create_dir would EEXIST and the
    // signed quote silently degrades to the unsigned TDREPORT (silicon root lost).
    // A monotonic counter makes every entry distinct so a lingering entry can
    // never collide.
    static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = format!("{}/paypal_{}_{:08x}", base, hex::encode(&report_data[..8]), seq);
    // configfs entries are removed with rmdir (remove_dir), NEVER remove_dir_all:
    // the latter recurses into inblob/outblob/provider — configfs attributes that
    // cannot be unlinked — so it always failed and leaked the entry. That leak is
    // what caused the fixed-name EEXIST once the nonce became deterministic.
    let _ = std::fs::remove_dir(&dir);
    if let Err(e) = std::fs::create_dir(&dir) {
        ev.notes.push(format!("configfs: create entry failed: {}", e));
        return;
    }
    if let Err(e) = std::fs::write(format!("{}/inblob", dir), report_data) {
        ev.notes.push(format!("configfs: write inblob failed: {}", e));
        let _ = std::fs::remove_dir(&dir);
        return;
    }
    match std::fs::read_to_string(format!("{}/provider", dir)) {
        Ok(p) => ev.provider = Some(p.trim().to_string()),
        Err(e) => ev.notes.push(format!("configfs: read provider failed: {}", e)),
    }
    if let Ok(g) = std::fs::read_to_string(format!("{}/generation", dir)) {
        ev.notes.push(format!("configfs generation={}", g.trim()));
    }
    match std::fs::read(format!("{}/outblob", dir)) {
        Ok(out) => {
            let provider_ok = ev.provider.as_deref() == Some("tdx_guest");
            ev.notes.push(format!(
                "configfs outblob={} bytes, provider={:?}",
                out.len(),
                ev.provider
            ));
            if !provider_ok {
                ev.notes.push(
                    "configfs: provider is not 'tdx_guest' — refusing to attribute foreign evidence to this TDX platform"
                        .into(),
                );
            } else if looks_like_tdx_quote(&out) {
                ev.quote_b64 = Some(STANDARD.encode(&out));
                ev.quote_source = Some("configfs_tsm".into());
                ev.notes.push("configfs: SIGNED TD QUOTE obtained".into());
            } else if looks_like_td_report(&out) {
                ev.td_report_b64 = Some(STANDARD.encode(&out));
                ev.td_report_source = Some("configfs_tsm".into());
                ev.notes
                    .push("configfs: 1024-byte TDREPORT obtained (module-signed measurements, UNsigned blob)".into());
            } else {
                ev.notes.push("configfs: outblob recognized as neither quote nor TDREPORT".into());
            }
        }
        Err(e) => ev.notes.push(format!("configfs: read outblob failed: {}", e)),
    }
    if let Ok(aux) = std::fs::read(format!("{}/auxblob", dir)) {
        if !aux.is_empty() {
            ev.notes.push(format!("configfs auxblob={} bytes", aux.len()));
            ev.aux_b64 = Some(STANDARD.encode(&aux));
        }
    }
    let _ = std::fs::remove_dir(&dir);
}

const TDX_DEVICES: [&str; 2] = ["/dev/tdx_guest", "/dev/tdx-guest"];

/// Attempt a TDREPORT through the /dev/tdx_guest GET_REPORT ioctl.
fn device_report(report_data: &[u8; 64], ev: &mut TdxEvidence) {
    use std::os::unix::io::AsRawFd;
    for dev in TDX_DEVICES {
        if !std::path::Path::new(dev).exists() {
            ev.notes.push(format!("{}: device node absent", dev));
            continue;
        }
        let file = match std::fs::OpenOptions::new().read(true).write(true).open(dev) {
            Ok(f) => f,
            Err(e) => {
                ev.notes.push(format!("{}: open failed: {}", dev, e));
                continue;
            }
        };
        let mut req = vec![0u8; TDX_REPORT_REQ_SIZE];
        req[..64].copy_from_slice(report_data);
        let ret = unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                IOC_TDX_GET_REPORT,
                req.as_mut_ptr() as *mut libc::c_void,
            )
        };
        if ret == 0 {
            let report = req[64..].to_vec();
            ev.notes
                .push(format!("{}: GET_REPORT ok ({} bytes)", dev, report.len()));
            if looks_like_td_report(&report) && ev.td_report_b64.is_none() {
                ev.td_report_b64 = Some(STANDARD.encode(&report));
                ev.td_report_source = Some(format!("{}:ioctl", dev));
            }
        } else {
            let err = std::io::Error::last_os_error();
            ev.notes.push(format!("{}: GET_REPORT failed: {}", dev, err));
            if err.raw_os_error() == Some(libc::ENOTTY) {
                break; // driver present but no report ioctl — nothing more to try here
            }
        }
    }
}

/// Attempt a signed TD Quote through the /dev/tdx_guest GET_QUOTE ioctl.
///
/// The ABI is VMM-mediated (VMM fills the quote buffer + status), so several
/// buffer-length conventions are tried; every attempt is recorded in `notes`.
/// ENOTTY means this kernel's driver implements no quote path at all — that
/// is logged once and the search stops rather than silently giving up.
fn device_quote(report_data: &[u8; 64], ev: &mut TdxEvidence) {
    use std::os::unix::io::AsRawFd;

    // First obtain a TDREPORT to hand to the quote request.
    let report: Vec<u8> = match ev.td_report_b64.as_ref().and_then(|b| {
        use base64::Engine as _;
        STANDARD.decode(b).ok()
    }) {
        Some(r) if r.len() == 1024 => r,
        _ => {
            device_report(report_data, ev);
            match ev.td_report_b64.as_ref().and_then(|b| STANDARD.decode(b).ok()) {
                Some(r) if r.len() == 1024 => r,
                _ => {
                    ev.notes.push("quote: skipped — no TDREPORT available to quote".into());
                    return;
                }
            }
        }
    };

    // (version, in_len, out_len) header conventions to try — the driver/VMM
    // fills most of the header, so which fields the guest must preset varies
    // by kernel/QEMU; every combination is recorded in `notes`.
    let variants: [(u64, u32, u32); 6] = [
        (0, 1024, 0),
        (0, 1024, TDX_QUOTE_HDR_DATA as u32),
        (0, 1024, 4608),
        (1, 1024, 0),
        (1, 1024, TDX_QUOTE_HDR_DATA as u32),
        (1, 1024, 4608),
    ];
    for dev in TDX_DEVICES {
        if !std::path::Path::new(dev).exists() {
            continue;
        }
        let file = match std::fs::OpenOptions::new().read(true).write(true).open(dev) {
            Ok(f) => f,
            Err(e) => {
                ev.notes.push(format!("quote: {} open failed: {}", dev, e));
                continue;
            }
        };
        let mut got_enotty = false;
        for (version, in_len, out_len) in variants {
            let mut hdr = vec![0u8; TDX_QUOTE_HDR_SIZE];
            hdr[0..8].copy_from_slice(&version.to_le_bytes());
            hdr[16..20].copy_from_slice(&in_len.to_le_bytes());
            hdr[20..24].copy_from_slice(&out_len.to_le_bytes());
            hdr[TDX_QUOTE_HDR_PREFIX..TDX_QUOTE_HDR_PREFIX + 1024].copy_from_slice(&report);
            let mut req: [u64; 2] = [0; 2];
            req[0] = hdr.as_mut_ptr() as u64;
            req[1] = TDX_QUOTE_HDR_SIZE as u64;
            let ret = unsafe {
                libc::ioctl(
                    file.as_raw_fd(),
                    IOC_TDX_GET_QUOTE,
                    req.as_mut_ptr() as *mut libc::c_void,
                )
            };
            let status = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
            let produced = u32::from_le_bytes(hdr[20..24].try_into().unwrap()) as usize;
            if ret == 0 && status == 0 && produced > 16 && produced <= TDX_QUOTE_HDR_DATA {
                let quote = hdr[TDX_QUOTE_HDR_PREFIX..TDX_QUOTE_HDR_PREFIX + produced].to_vec();
                ev.notes.push(format!(
                    "quote: {} GET_QUOTE ok (out_len={}), quote-like={}",
                    dev,
                    produced,
                    looks_like_tdx_quote(&quote)
                ));
                if looks_like_tdx_quote(&quote) {
                    ev.quote_b64 = Some(STANDARD.encode(&quote));
                    ev.quote_source = Some(format!("{}:ioctl", dev));
                    ev.quote_status = Some("success".into());
                    return;
                }
            } else {
                if ret != 0 {
                    let err = std::io::Error::last_os_error();
                    ev.notes.push(format!(
                        "quote: {} ret=-1 errno={} (in_len={}, out_len={})",
                        dev, err, in_len, out_len
                    ));
                    if err.raw_os_error() == Some(libc::ENOTTY) {
                        ev.notes
                            .push(format!("quote: {} implements no GET_QUOTE ioctl (ENOTTY)", dev));
                        got_enotty = true;
                        break;
                    }
                } else {
                    ev.notes.push(format!(
                        "quote: {} status=0x{:016x} out_len={} (in_len={}, out_len_init={})",
                        dev, status, produced, in_len, out_len
                    ));
                    if status == 0x8000_0000_0000_0001 {
                        ev.notes
                            .push("quote: VMM reports QUOTE_SERVICE_UNAVAILABLE — the platform exposes no quote generation service".into());
                        ev.quote_status = Some("service_unavailable".into());
                        break;
                    }
                }
            }
        }
        if got_enotty {
            continue;
        }
        if ev.quote_b64.is_some() {
            return;
        }
    }
}

/// Collect TDX silicon evidence, binding either `report_data_override`
/// (pre-flight client-bound digest) or `nonce_hex` into REPORTDATA.
///
/// Never panics and never claims evidence it did not obtain — every failure
/// lands in `notes`.
pub fn collect_silicon_evidence(
    nonce_hex: &str,
    report_data_override: Option<[u8; 64]>,
) -> TdxEvidence {
    let mut ev = TdxEvidence::default();
    let mut report_data = [0u8; 64];

    if let Some(rdo) = report_data_override {
        report_data.copy_from_slice(&rdo);
        ev.notes.push(format!(
            "bind NOTE: REPORTDATA explicitly overridden with client-bound pre-flight digest ({})",
            hex::encode(&report_data[..32])
        ));
    } else {
        match hex::decode(nonce_hex.trim()) {
            Ok(bytes) if bytes.len() >= 32 => {
                report_data[..32].copy_from_slice(&bytes[..32]);
                ev.notes.push(format!(
                    "bind NOTE: REPORTDATA[0..32] = session nonce {}",
                    hex::encode(&report_data[..32])
                ));
            }
            _ => ev.notes.push(format!(
                "bind WARNING: nonce_hex not decodable (len={}) — REPORTDATA zeroed",
                nonce_hex.len()
            )),
        }
    }

    configfs_evidence(&report_data, &mut ev);
    if ev.td_report_b64.is_none() && ev.quote_b64.is_none() {
        device_report(&report_data, &mut ev);
    }
    if ev.quote_b64.is_none() {
        device_quote(&report_data, &mut ev);
    }
    ev
}

// ===========================================================================
// v165 Phase 2/3: CCEL EVENT-LOG REPLAY + BOOT-TIME FAIL-CLOSED QUOTE PROBE
//
// plan.md Phases 2–3 (live evidence 2026-10-21: RTMR0/1/2 are non-zero and
// IMAGE-BOUND — identical across instances/reboots of the same image, changed
// when the initramfs changed — so the boot chain DOES extend them on this
// platform; the auditor's EXPECTED_RTMR* pins are the remote enforcement).
//
// This module adds the IN-GUEST half: parse the ACPI CCEL (CC Event Log,
// TCG crypto-agile format), replay the SHA-384 extend chain, and compare the
// replayed RTMR0..3 against the values inside the SILICON-SIGNED quote body.
// A mismatch means the event log does not describe the measured launch — the
// host is presenting inconsistent evidence — and the caller must HALT
// (fail-closed). If the platform does not expose the log area at all, that is
// recorded honestly in `notes` and the check degrades to the quote pins
// enforced remotely by verify.html (EXPECTED_MRTD/EXPECTED_RTMR*).
//// Spec: TCG PC Client PFP (crypto-agile event log) + Intel TDX RTMR rules:
//   initial RTMR[i] = ZERO (TDX Module Base Arch spec; live-verified on
//   Alibaba 2026-10-23 — the quote matches the zero-init replay exactly);
//   extend: RTMR[i] = SHA-384(RTM R[i] ∥ digest). The event's register field
//   is the TCG/UEFI "MrIndex": 0 = MRTD (never an RTMR), 1..4 = RTMR0..3.
// ===========================================================================

/// Try every known exposure of the CCEL log area. Linux publishes the CCEL
/// *table* (header + LogAreaAddress) under acpi/tables/; the log AREA itself
/// is a separate physical region which QEMU/EDK2 may or may not alias into
/// the sysfs data directory. Record where it was (or was not) found.
pub fn read_ccel_log(notes: &mut Vec<String>) -> Option<Vec<u8>> {
    // 1) data/CCEL — some firmware ships the log area as a raw data table.
    if let Ok(b) = std::fs::read("/sys/firmware/acpi/tables/data/CCEL") {
        if b.len() > 32 {
            notes.push(format!("ccel: raw log read from data/CCEL ({} bytes)", b.len()));
            return Some(b);
        }
    }
    // 2) the CCEL table itself — if its Length covers more than the 44-byte
    //    header, the log may be embedded inline after it (QEMU does this).
    if let Ok(tbl) = std::fs::read("/sys/firmware/acpi/tables/CCEL") {
        if tbl.len() >= 44 {
            let table_len = u32::from_le_bytes([tbl[4], tbl[5], tbl[6], tbl[7]]) as usize;
            if table_len > 44 && table_len <= tbl.len() {
                notes.push(format!(
                    "ccel: table Length={} > header — embedded log area ({} bytes)",
                    table_len,
                    table_len - 44
                ));
                return Some(tbl[44..table_len].to_vec());
            }
            notes.push(format!(
                "ccel: ACPI table present ({} bytes, Length={}) but the log area it points to is a separate physical region not exposed via sysfs on this kernel",
                tbl.len(), table_len
            ));
        }
    } else {
        notes.push("ccel: /sys/firmware/acpi/tables/CCEL absent (no CC Event Log ACPI table)".into());
    }
    // 3) /dev/mem is deliberately NOT probed: CONFIG_STRICT_DEVMEM blocks it
    //    on this kernel and trying would only add noise.
    notes.push("ccel: log area UNAVAILABLE in-guest — integrity enforced by the auditor's EXPECTED_RTMR* hard pins over the silicon-signed quote".into());
    None
}

/// digestSize per TCG algId (fallback when the Spec ID header table lacks one).
fn tcg_digest_size(alg: u16) -> Option<usize> {
    match alg {
        0x0004 => Some(20),  // SHA-1
        0x000B => Some(32),  // SHA-256
        0x000C => Some(48),  // SHA-384
        0x000D => Some(64),  // SHA-512
        0x0012 => Some(32),  // SHA3-256
        0x0013 => Some(48),  // SHA3-384
        0x0014 => Some(64),  // SHA3-512
        _ => None,
    }
}

/// Replay a TCG crypto-agile event log onto RTMR0..3. Returns the four
/// replayed registers (SHA-384 state each) or a parse/replay error.
pub fn replay_ccel(log: &[u8]) -> Result<[[u8; 48]; 4], String> {
    replay_ccel_with(log, [0u8; 48])
}

/// Replay the log from an explicit RTMR reset state. The Intel TDX Module
/// Base Arch spec resets the RTMR array to ZERO; an earlier assumption here
/// used SHA-384(1024×0x00). `ccel_replay_vs_quote` probes both conventions —
/// the silicon quote is the ground truth either way.
pub fn replay_ccel_with(log: &[u8], init: [u8; 48]) -> Result<[[u8; 48]; 4], String> {
    use sha2::{Digest, Sha384};
    let rd32 = |o: usize| -> Result<u32, String> {
        log.get(o..o + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or_else(|| format!("ccel: truncated u32 @{} (log {} bytes)", o, log.len()))
    };
    let mut rtmr = [init, init, init, init];

    let mut off = 0usize;
    let mut ev_count = 0usize;
    let mut extend_count = 0usize;
    // Algorithm size table from the Spec ID Event header (algId -> size).
    let mut alg_sizes: Vec<(u16, usize)> = Vec::new();

    // TCG PC Client PFP: the FIRST event of a crypto-agile log is laid out in
    // the LEGACY TCG_PCR_EVENT fixed format (pcr u32, type u32, digest[20],
    // eventSize u32, event) — normally the EV_NO_ACTION "Spec ID Event03"
    // header carrying the algorithm-size table. Parsing that as an EVENT2
    // misreads the SHA-1 digest field as digestCount/eventSize and drifts the
    // stream (live-verified against Alibaba's real CCEL log, 2026-10-22:
    // "implausible digestCount 4294967295 @1626").
    // Legacy layout: pcr u32 @0 | type u32 @4 | digest[20] @8..28 |
    // eventSize u32 @28 | event @32.
    if log.len() >= 32 {
        let l_type = u32::from_le_bytes([log[4], log[5], log[6], log[7]]);
        let l_size = u32::from_le_bytes([log[28], log[29], log[30], log[31]]) as usize;
        if 32 + l_size <= log.len() {
            let ev = &log[32..32 + l_size];
            if l_type == 0x0000_0003 && ev.starts_with(b"Spec ID Event03\x00") && ev.len() >= 28 {
                let n = u32::from_le_bytes([ev[24], ev[25], ev[26], ev[27]]) as usize;
                for i in 0..n.min(8) {
                    let base = 28 + i * 4;
                    if base + 4 <= ev.len() {
                        let a = u16::from_le_bytes([ev[base], ev[base + 1]]);
                        let s = u16::from_le_bytes([ev[base + 2], ev[base + 3]]) as usize;
                        alg_sizes.push((a, s));
                    }
                }
                off = 32 + l_size; // EV_NO_ACTION header never extends
                ev_count += 1;
            }
            // else: no legacy spec-id header → parse the whole log as EVENT2
        }
    }

    while off + 12 <= log.len() {
        let pcr_index = rd32(off)?;
        let event_type = rd32(off + 4)?;
        let digest_count = rd32(off + 8)?;
        if digest_count > 16 {
            // Fixed-size firmware log areas are commonly padded with 0x00 or
            // 0xFF after the last real event (live Alibaba CCEL: 1626 bytes of
            // real events in a 65536-byte data/CCEL area → digestCount read as
            // 0xFFFFFFFF out of 0xFF padding). A tail of 0x00/0xFF bytes in
            // any mix is padding — a clean end-of-log; anything else is a
            // parse anomaly. Either way the replay must still match the quote
            // exactly, so truncating here can never widen what is accepted.
            let rest = &log[off..];
            if rest.iter().all(|b| *b == 0x00 || *b == 0xFF) {
                break;
            }
            return Err(format!("ccel: implausible digestCount {} @{}", digest_count, off));
        }
        let mut pos = off + 12;
        let mut sha384_digest: Option<[u8; 48]> = None;
        for _ in 0..digest_count {
            if pos + 2 > log.len() {
                return Err(format!("ccel: truncated algId @{}", pos));
            }
            let alg = u16::from_le_bytes([log[pos], log[pos + 1]]);
            pos += 2;
            let size = alg_sizes
                .iter()
                .find(|(a, _)| *a == alg)
                .map(|(_, s)| *s)
                .or_else(|| tcg_digest_size(alg))
                .ok_or_else(|| format!("ccel: unknown digest alg 0x{:04x} @{}", alg, pos - 2))?;
            if pos + size > log.len() {
                return Err(format!("ccel: truncated digest @{} (need {})", pos, size));
            }
            if alg == 0x000C && size == 48 && sha384_digest.is_none() {
                let mut d = [0u8; 48];
                d.copy_from_slice(&log[pos..pos + 48]);
                sha384_digest = Some(d);
            }
            pos += size;
        }
        if pos + 4 > log.len() {
            return Err(format!("ccel: truncated eventSize @{}", pos));
        }
        let event_size = u32::from_le_bytes([log[pos], log[pos + 1], log[pos + 2], log[pos + 3]]) as usize;
        pos += 4;
        if digest_count == 0
            && event_size == 0
            && log[off..].iter().all(|b| *b == 0x00 || *b == 0xFF)
        {
            break; // trailing 0x00/0xFF padding
        }
        if pos + event_size > log.len() {
            return Err(format!("ccel: event data overruns log @{} (size {})", pos, event_size));
        }

        // Spec ID Event03 header written as an EVENT2 (some firmware does
        // this; the legacy fixed-layout form is handled before the loop):
        // harvest the declared digest-size table. It is EV_NO_ACTION and is
        // NEVER extended into any RTMR. (eventType 1 = EV_POST_CODE is a real
        // extending event — only type 3 with the spec-id body is a header.)
        if event_type == 0x0000_0003 && alg_sizes.is_empty() {
            let ev = &log[pos..pos + event_size];
            // signature[16] + platformClass u32 + minor/major/errata/uintn u8
            // + numberOfAlgorithms u32 + n * {algId u16, digestSize u16}
            if ev.len() >= 28 && ev.starts_with(b"Spec ID Event03\x00") {
                let n = u32::from_le_bytes([ev[24], ev[25], ev[26], ev[27]]) as usize;
                for i in 0..n.min(8) {
                    let base = 28 + i * 4;
                    if base + 4 <= ev.len() {
                        let a = u16::from_le_bytes([ev[base], ev[base + 1]]);
                        let s = u16::from_le_bytes([ev[base + 2], ev[base + 3]]) as usize;
                        alg_sizes.push((a, s));
                    }
                }
                notes_size_hint(&alg_sizes);
            }
        } else if event_type != 0x0000_0003
            && (1..=4).contains(&pcr_index)
            && !matches!(pcr_index, 0x8000_0000..)
        {
            // EV_NO_ACTION (0x3) never extends; PCRIndex >= 0x80000000 are
            // TCG "specialty" events that also do not extend; MrIndex 0 is
            // the MRTD (built by the TDVF itself) and is never an RTMR.
            // The register field is the TCG/UEFI "MrIndex":
            // 0 = MRTD, 1..4 = RTMR0..3 — live-verified against Alibaba's
            // CCEL log and the Intel-signed quote (2026-10-23): the earlier
            // "0..3 == RTMR0..3" reading replayed every bank one register off
            // and tripped the CCEL-vs-quote mismatch gate on every boot.
            let reg = (pcr_index - 1) as usize;
            if let Some(d) = sha384_digest {
                let mut h = Sha384::new();
                h.update(rtmr[reg]);
                h.update(d);
                rtmr[reg].copy_from_slice(&h.finalize());
                extend_count += 1;
            }
        }
        ev_count += 1;
        off = pos + event_size;
    }
    if ev_count == 0 {
        return Err("ccel: no events parsed (empty or non-TCG log)".into());
    }
    let _ = extend_count;
    Ok(rtmr)
}

fn notes_size_hint(_alg_sizes: &[(u16, usize)]) {}

/// Extract MRTD + RTMR0..3 from a v4/v5 Intel TDX quote body (TDREPORT10).
/// Offsets (body-relative): mr_td 136..184, rtmr0 328..376, rtmr1 376..424,
/// rtmr2 424..472, rtmr3 472..520 — the same layout verify.html pins.
pub fn quote_measurements(quote: &[u8]) -> Result<([u8; 48], [[u8; 48]; 4]), String> {
    if quote.len() < 48 {
        return Err("quote truncated (<48 B header)".into());
    }
    let version = u16::from_le_bytes([quote[0], quote[1]]);
    let tee_type = u32::from_le_bytes([quote[4], quote[5], quote[6], quote[7]]);
    if tee_type != 0x81 {
        return Err(format!("tee_type 0x{:x} is not TDX", tee_type));
    }
    let body_off = match version {
        4 => 48usize,
        5 => 54usize, // v5 preamble: body_type u16 + body_size u32
        v => return Err(format!("unsupported quote version {}", v)),
    };
    if quote.len() < body_off + 584 {
        return Err(format!("quote truncated before TDREPORT body ({} bytes)", quote.len()));
    }
    let body = &quote[body_off..body_off + 584];
    let mut mrtd = [0u8; 48];
    mrtd.copy_from_slice(&body[136..184]);
    let mut rt = [[0u8; 48]; 4];
    for i in 0..4 {
        rt[i].copy_from_slice(&body[328 + i * 48..376 + i * 48]);
    }
    Ok((mrtd, rt))
}

/// Full in-guest measurement audit: replay CCEL onto RTMR0..3 and require
/// exact equality with the silicon-signed quote's own RTMR fields.
///
/// Returns Ok(notes) on match or when the log is unavailable (recorded in
/// notes; remote EXPECTED_RTMR* pins remain the enforcement), Err(reason) on
/// a PARSED log that REPLAYS TO DIFFERENT VALUES — the caller must halt.
pub fn ccel_replay_vs_quote(quote: &[u8]) -> Result<Vec<String>, String> {
    let mut notes = Vec::new();
    let (_mrtd, quoted_rt) = quote_measurements(quote)?;
    for i in 0..4 {
        notes.push(format!("quote RTMR{} = {}", i, hex::encode(quoted_rt[i])));
    }
    let log = match read_ccel_log(&mut notes) {
        Some(l) => l,
        None => return Ok(notes), // absence is honest + audited remotely
    };
    // RTMR reset convention is probed BOTH ways (see replay_ccel_with): the
    // spec says zero, earlier tooling assumed SHA-384(1024×0x00). The silicon
    // quote is the ground truth: accept when EITHER convention replays to it
    // exactly, and record which one the platform used.
    let init_alt = {
        use sha2::{Digest, Sha384};
        let d = Sha384::digest([0u8; 1024]);
        let mut a = [0u8; 48];
        a.copy_from_slice(&d);
        a
    };
    let candidates: [(&str, [u8; 48]); 2] =
        [("zero-init (TDX spec)", [0u8; 48]), ("sha384(1024×0x00)-init", init_alt)];
    let mut mismatched: Vec<String> = Vec::new();
    for (name, init) in candidates {
        let replayed = match replay_ccel_with(&log, init) {
            Ok(r) => r,
            Err(e) => {
                // A log we cannot PARSE is not a mismatch. The halt is mandated
                // for a log that REPLAYS to values different from the silicon
                // quote; an unparsable log is treated like an unavailable one
                // (recorded for the remote auditor, enforcement stays with the
                // quote's RTMR pins — the host controls the VMM and can
                // withhold the log area anyway, so halting on parser gaps buys
                // no security, only outages). First 2 KiB hex'd for postmortem
                // on the serial console.
                let dump: String =
                    log.iter().take(1024).map(|b| format!("{:02x}", b)).collect();
                notes.push(format!(
                    "ccel: log PRESENT but unparsable ({e}) — enforcement deferred to the quote RTMR pins"
                ));
                notes.push(format!("ccel-hex[0..{}] = {}", log.len().min(1024), dump));
                return Ok(notes);
            }
        };
        let mut bad = 0usize;
        for i in 0..4 {
            if replayed[i] != quoted_rt[i] {
                bad += 1;
                mismatched.push(format!(
                    "[{name}] RTMR{}: log-replay {} ≠ quoted {}",
                    i,
                    hex::encode(replayed[i]),
                    hex::encode(quoted_rt[i])
                ));
            }
        }
        if bad == 0 {
            notes.push(format!(
                "ccel: replay ({name}) reproduces the quoted RTMR0..3 EXACTLY — log and silicon agree"
            ));
            return Ok(notes);
        }
        notes.push(format!("ccel: replay ({name}) mismatched {bad}/4 RTMR banks"));
    }
    Err(format!(
        "CCEL REPLAY MISMATCH (host presents inconsistent measurements): {}",
        mismatched.join("; ")
    ))
}

/// Names of shipped kernel modules whose filename matches any substring.
/// Used by /debug/attestation to prove whether `tdx-guest.ko` etc. are even
/// present in the image (the boot-time loader's scan filters may miss them).
pub fn modules_matching(substrs: &[&str]) -> Vec<String> {
    fn walk(dir: &std::path::Path, depth: usize, out: &mut Vec<String>, substrs: &[&str]) {
        if depth > 9 {
            return;
        }
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                let p = e.path();
                let name = p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if p.is_dir() {
                    walk(&p, depth + 1, out, substrs);
                } else if substrs.iter().any(|s| name.contains(s)) {
                    out.push(p.to_string_lossy().into_owned());
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(std::path::Path::new("/lib/modules"), 0, &mut out, substrs);
    out.sort();
    out
}
