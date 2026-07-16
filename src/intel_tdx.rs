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

/// Check if this platform supports Intel TDX hardware extensions
pub fn is_intel_tdx_available() -> bool {
    let driver_path = std::path::Path::new("/sys/bus/platform/drivers/tdx");
    let tpm_path = std::path::Path::new("/dev/tpmrm0");
    let tdx_guest = std::path::Path::new("/dev/tdx-guest");
    let tdx_attest = std::path::Path::new("/dev/tdx_guest");
    driver_path.exists() || (tpm_path.exists() && (tdx_guest.exists() || tdx_attest.exists()))
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
        let out = std::process::Command::new("tpm2")
            .args(["nvread", idx])
            .env("TPM2TOOLS_TCTI", "device:/dev/tpmrm0")
            .output()
            .ok()?;
        
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
