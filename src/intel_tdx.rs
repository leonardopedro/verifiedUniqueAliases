//! Intel TDX (Trusted Domain Extensions) Hardware Root-of-Trust Adapter
//!
//! **Target Platform:** Alibaba Cloud ECS.r9i.xlarge
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
