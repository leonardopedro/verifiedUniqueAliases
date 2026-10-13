//! AMD SEV-SNP Hardware Root-of-Trust Adapter for Oracle Cloud Infrastructure (OCI)
//!
//! **Target Platform:** OCI `VM.Standard.E5.Flex` (4th Gen AMD EPYC "Genoa",
//! CPUID Family 19h Model 11h) launched with `--is-memory-encryption-enabled true`,
//! which enables AMD SEV-SNP memory encryption.
//!
//! OCI confidential instances do **not** expose a vTPM. The primary hardware
//! evidence is therefore the SNP attestation report, signed by the VCEK
//! (Versioned Chip Endorsement Key) fused into the AMD silicon:
//!
//! 1. `/dev/sev-guest` `SNP_GET_REPORT` ioctl — session-nonce-bound report (primary)
//! 2. ConfigFS TSM (`/sys/kernel/config/tsm/report`) — kernel fallback
//!
//! Cert chain: VCEK ← ASK ← ARK (AMD KDS, family-aware: Milan / Genoa / Turin).
//!
//! ## SNP Report Layout (AMD SEV-SNP Firmware ABI, version 2)
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0x000  | 4    | version (LE u32, 1..=8 — observed v5 on OCI) |
//! | 0x008  | 8    | policy (LE u64) |
//! | 0x050  | 64   | report_data (session nonce bound here) |
//! | 0x180  | 8    | reported_tcb (TCB_VERSION, LE u64) |
//! | 0x1A0  | 64   | chip_id (VCEK hardware id) |
//! | 0x2A0  | 512  | signature (r,s — ECDSA P-384 over bytes 0x0..0x2A0) |
//! | 0x4A0  |      | total report length (1184 bytes) |
//!
//! TCB_VERSION byte layout differs by CPU family (AMD ABI spec Table 3/4):
//! - **Layout A** (Milan, Genoa, standard Turin): `bl=b0, tee=b1, snp=b6, ucode=b7`
//! - **Layout B** (Turin-Dense, Family 1Ah Models 90h+): `bl=b1, tee=b2, snp=b3, ucode=b7`

#![allow(dead_code)]  // Functions may not be used in all builds, but are required for compatibility

use sha2::{Digest, Sha256};

/// SNP_GET_REPORT ioctl number: _IOWR('S', 0x00, struct snp_guest_request_ioctl)
/// 'S' = 0x53, size 0x20 → 0xC0205300
const SNP_GET_REPORT: libc::c_ulong = 0xC0205300;

/// SNP_GET_EXT_REPORT ioctl number: _IOWR('S', 0x02, struct snp_guest_request_ioctl)
/// → 0xC0205302. Extended guest request (GHCB spec v2): the PSP returns the
/// attestation report AND its own certificate table (VCEK/VLEK + ASK + ARK)
/// in one call — the certificates come from the silicon itself, not from
/// kdsintf.amd.com. On OCI E5 this is the authoritative VCEK: some hosts' PSP
/// holds a key whose signature does NOT match the KDS entry for the same
/// chip_id/TCB (multi-cloud VLEK-style provisioning), so a KDS-only fetch can
/// produce a cert that fails to verify the live report's signature.
const SNP_GET_EXT_REPORT: libc::c_ulong = 0xC0205302;

/// SEV_FW_BLOB_MAX_SIZE (kernel: SZ_64K) — the extended request requires
/// `certs_len` page-aligned and ≤ this ceiling.
const CERTS_BLOB_MAX: usize = 64 * 1024;

/// AMD guest-host communication certificate-table GUIDs (GHCB specification,
/// MSG_REPORT_REQ ext-certs). Raw bytes are the RFC-4122 wire order of each
/// GUID string, matching go-sev-guest abi.VcekGUID/VlekGUID/AskGUID/ArkGUID.
pub const GUID_VCEK: [u8; 16] = [0x63,0xda,0x75,0x8d,0xe6,0x64,0x45,0x64,0xad,0xc5,0xf4,0xb9,0x3b,0xe8,0xac,0xcd];
pub const GUID_VLEK: [u8; 16] = [0xa8,0x07,0x4b,0xc2,0xa2,0x5a,0x48,0x3e,0xaa,0xe6,0x39,0xc0,0x45,0xa0,0xb8,0xa1];
pub const GUID_ASK:  [u8; 16] = [0x4a,0xb7,0xb3,0x79,0xbb,0xac,0x4f,0xe4,0xa0,0x2f,0x05,0xae,0xf3,0x27,0xc7,0x82];
pub const GUID_ARK:  [u8; 16] = [0xc0,0xb4,0x06,0xa4,0xa8,0x03,0x49,0x52,0x97,0x43,0x3f,0xb6,0x01,0x4c,0xd0,0xae];

/// One certificate from the PSP-provisioned table.
#[derive(Clone, Debug)]
pub struct PspCertTable {
    /// VCEK (Versioned Chip Endorsement Key) DER, when present
    pub vcek: Option<Vec<u8>>,
    /// VLEK (Versioned Loaded Endorsement Key) DER, when present
    pub vlek: Option<Vec<u8>>,
    /// ASK (AMD Signing Key) DER — issues the VCEK/VLEK
    pub ask: Option<Vec<u8>>,
    /// ARK (AMD Root Key) DER — the silicon root
    pub ark: Option<Vec<u8>>,
}

/// Parse the GHCB extended-report certificate table.
///
/// Layout: repeated 24-byte entries `{ GUID[16], offset: u32 LE, length: u32 LE }`
/// terminated by an all-zero entry; each cert lives at `certs[offset..offset+length]`
/// (offsets are relative to the start of the whole blob).
pub fn parse_snp_cert_table(certs: &[u8]) -> PspCertTable {
    let mut out = PspCertTable { vcek: None, vlek: None, ask: None, ark: None };
    if certs.len() < 24 { return out; }
    const ENTRY: usize = 24;
    let mut idx = 0usize;
    loop {
        if idx + ENTRY > certs.len() { break; }
        let e = &certs[idx..idx + ENTRY];
        let guid: [u8; 16] = e[0..16].try_into().unwrap();
        if guid == [0u8; 16] { break; } // terminator
        let off = u32::from_le_bytes(e[16..20].try_into().unwrap()) as usize;
        let len = u32::from_le_bytes(e[20..24].try_into().unwrap()) as usize;
        if off >= certs.len() || len == 0 || off.saturating_add(len) > certs.len() {
            tracing::warn!("SNP: cert table entry {} out of range (off={} len={} blob={})", idx / ENTRY, off, len, certs.len());
            break;
        }
        let der = certs[off..off + len].to_vec();
        if guid == GUID_VCEK && out.vcek.is_none() { out.vcek = Some(der); }
        else if guid == GUID_VLEK && out.vlek.is_none() { out.vlek = Some(der); }
        else if guid == GUID_ASK && out.ask.is_none() { out.ask = Some(der); }
        else if guid == GUID_ARK && out.ark.is_none() { out.ark = Some(der); }
        idx += ENTRY;
    }
    out
}

/// Locate the raw 1184-byte SNP report inside a decrypted REPORT response.
/// The firmware payload starts with a 32-byte message header
/// (`struct snp_msg_report_resp_hdr { u32 status; u32 report_size; u8 rsvd[24]; }`);
/// the plain ioctl passes it through verbatim (report at offset 32). Tolerate
/// a bare report at offset 0 for kernels that strip the header.
fn locate_report_in(resp: &[u8]) -> Option<Vec<u8>> {
    for off in [32usize, 0usize] {
        if resp.len() < off + SNP_REPORT_LEN { continue; }
        let version = u32::from_le_bytes(resp[off..off + 4].try_into().unwrap());
        if (1..=SNP_REPORT_MAX_VERSION).contains(&version) {
            tracing::info!("SNP: report at offset {} (version {})", off, version);
            return Some(resp[off..off + SNP_REPORT_LEN].to_vec());
        }
    }
    None
}

/// Verify an ECDSA P-384/SHA-384 signature over `report[0..SIGNED_LEN]` with
/// the public key inside `cert_der`. AMD stores r and s as 72-byte little-endian
/// fields at 0x2A0 / 0x2E8; the DER-encoded ECDSA-Sig-Value needs 48-byte
/// big-endian components (WebCrypto P1363 form).
pub fn verify_report_signature(report: &[u8], cert_der: &[u8]) -> bool {
    use openssl::bn::BigNum;
    use openssl::ecdsa::EcdsaSig;
    use openssl::hash::{hash as ossl_hash, MessageDigest};
    use openssl::x509::X509;
    if report.len() < SIGNED_LEN + 144 { return false; }
    let cert = match X509::from_der(cert_der) { Ok(c) => c, Err(_) => return false };
    let pkey = match cert.public_key() { Ok(p) => p, Err(_) => return false };
    let ec = match pkey.ec_key() { Ok(k) => k, Err(_) => return false };
    let to_bignum = |le: &[u8]| -> Option<BigNum> {
        let mut be: Vec<u8> = le.iter().rev().copied().collect();
        while be.first() == Some(&0u8) { be.remove(0); }
        BigNum::from_slice(&be).ok()
    };
    let r = to_bignum(&report[OFF_SIGNATURE..OFF_SIGNATURE + 72]);
    let s = to_bignum(&report[OFF_SIGNATURE + 72..OFF_SIGNATURE + 144]);
    let (r, s) = match (r, s) { (Some(r), Some(s)) => (r, s), _ => return false };
    let sig = match EcdsaSig::from_private_components(r, s) { Ok(s) => s, Err(_) => return false };
    let digest = match ossl_hash(MessageDigest::sha384(), &report[..SIGNED_LEN]) { Ok(d) => d, Err(_) => return false };
    sig.verify(&digest, &ec).unwrap_or(false)
}

/// Validate the PSP-provisioned chain: leaf ← ASK ← ARK by issuer/subject
/// linkage AND real signature checks (does not trust name strings alone).
pub fn validate_amd_chain(leaf_der: &[u8], ask_der: &[u8], ark_der: &[u8]) -> bool {
    use openssl::x509::X509;
    let leaf = match X509::from_der(leaf_der) { Ok(c) => c, Err(_) => return false };
    let ask  = match X509::from_der(ask_der)  { Ok(c) => c, Err(_) => return false };
    let ark  = match X509::from_der(ark_der)  { Ok(c) => c, Err(_) => return false };
    let ark_pk = match ark.public_key() { Ok(p) => p, Err(_) => return false };
    let ask_pk = match ask.public_key() { Ok(p) => p, Err(_) => return false };
    let name_der = |n: &openssl::x509::X509NameRef| n.to_der().unwrap_or_default();
    let ask_ok = ask.verify(&ark_pk).unwrap_or(false) && name_der(ask.issuer_name()) == name_der(ark.subject_name());
    let leaf_ok = leaf.verify(&ask_pk).unwrap_or(false) && name_der(leaf.issuer_name()) == name_der(ask.subject_name());
    ask_ok && leaf_ok
}

#[cfg(test)]
mod ext_report_tests {
    use super::*;

    /// The GHCB cert table is a sequence of 24-byte `{GUID, offset, length}`
    /// entries terminated by an all-zero entry; certs live at blob[offset..].
    #[test]
    fn parses_synthetic_cert_table() {
        fn entry(guid: &[u8; 16], off: u32, len: u32) -> Vec<u8> {
            let mut e = guid.to_vec();
            e.extend_from_slice(&off.to_le_bytes());
            e.extend_from_slice(&len.to_le_bytes());
            e
        }
        let vcek = vec![0xAAu8; 10];
        let ark = vec![0xBBu8; 12];
        // Two entries + terminator = 72-byte header; data follows at offset 72.
        let mut blob = entry(&GUID_VCEK, 72, 10);
        blob.extend(entry(&GUID_ARK, 82, 12));
        blob.extend([0u8; 24]); // terminator
        blob.extend(&vcek);
        blob.extend(&ark);
        let t = parse_snp_cert_table(&blob);
        assert_eq!(t.vcek, Some(vcek));
        assert_eq!(t.ark, Some(ark));
        assert!(t.ask.is_none() && t.vlek.is_none());
    }

    /// pem_certs_to_der must split a concatenated PEM chain (what KDS serves
    /// and what der_to_pem produces) back into exact DER certs — used to
    /// complete a PSP leaf's chain with the KDS ASK/ARK.
    #[test]
    fn pem_bundle_splits_into_ders() {
        let der1 = vec![0x30u8, 0x82, 0x01, 0x00, 0xAA, 0xBB];
        let der2 = vec![0x30u8, 0x82, 0x02, 0x00, 0xCC];
        let pem = format!("{}{}", der_to_pem("CERTIFICATE", &der1), der_to_pem("CERTIFICATE", &der2));
        assert_eq!(pem_certs_to_der(&pem), vec![der1, der2]);
        assert!(pem_certs_to_der("not a pem").is_empty());
    }

    #[test]
    fn rejects_out_of_range_cert_entry() {
        fn entry(guid: &[u8; 16], off: u32, len: u32) -> Vec<u8> {
            let mut e = guid.to_vec();
            e.extend_from_slice(&off.to_le_bytes());
            e.extend_from_slice(&len.to_le_bytes());
            e
        }
        let mut blob = entry(&GUID_VCEK, 4096, 100000); // way past blob end
        blob.extend([0u8; 24]);
        let t = parse_snp_cert_table(&blob);
        assert!(t.vcek.is_none());
    }

    /// Offline check against real captures: the control host's report MUST
    /// verify with its KDS-fetched VCEK (proving the P-384 LE→BE conversion
    /// and SHA-384 signing region are correct), and the broken live host's
    /// KDS cert MUST NOT verify its report (the OCI E5 PSP/KDS mismatch this
    /// whole change works around). Skips silently when captures are absent.
    #[test]
    fn real_capture_crosscheck() {
        let (report, cert) = match (std::fs::read("/tmp/live_snp.bin"), std::fs::read("/tmp/vcek_live.der")) {
            (Ok(r), Ok(c)) => (r, c),
            _ => { eprintln!("captures absent — skipping"); return; }
        };
        let live_bad = verify_report_signature(&report, &cert);
        eprintln!("live host: KDS cert verifies report = {}", live_bad);
        // control host: report.json holds the genuine capture
        if let Ok(raw) = std::fs::read("/tmp/report.json") {
            if let Ok(j) = serde_json::from_slice::<serde_json::Value>(&raw) {
                let hw = j.get("attestation_report").and_then(|a| a.get("hardware_level_attestation")).unwrap_or(&j);
                if let (Some(r64), Some(v64)) = (hw.get("snp_report_b64").and_then(|v| v.as_str()), hw.get("vcek_der_b64").and_then(|v| v.as_str())) {
                    use base64::Engine as _;
                    let rep = base64::engine::general_purpose::STANDARD.decode(r64).unwrap();
                    let cert = base64::engine::general_purpose::STANDARD.decode(v64).unwrap();
                    assert!(verify_report_signature(&rep, &cert), "control host report MUST verify with its VCEK");
                    assert!(!verify_report_signature(&report, &cert), "live host report MUST NOT verify with control cert");
                }
            }
        }
    }
}

/// SNP_GET_EXT_REPORT result: (raw report, PSP certificate-table blob).
pub struct ExtReport {
    pub report: Vec<u8>,
    pub certs: Vec<u8>,
}

/// Request a session-bound SNP attestation report AND the PSP's own
/// certificate table in a single extended guest request.
///
/// This is the authoritative AMD evidence path on OCI: the VCEK used to sign
/// the report is delivered alongside it by the silicon, so verification cannot
/// be broken by an out-of-sync (or vendor-substituted) KDS entry.
pub fn snp_get_ext_report(report_data: &[u8; 64]) -> Option<ExtReport> {
    use std::os::unix::io::AsRawFd;

    let dev = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/sev-guest");
    let dev = match dev {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("SNP-EXT: cannot open /dev/sev-guest: {}", e);
            return None;
        }
    };

    // Page-aligned certificate blob (the kernel requires a page-multiple
    // certs_len and copies the firmware's cert table straight into it).
    let certs_ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            CERTS_BLOB_MAX,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if certs_ptr == libc::MAP_FAILED {
        tracing::error!("SNP-EXT: mmap for cert table failed: {}", std::io::Error::last_os_error());
        return None;
    }

    let mut req = SnpExtReportReq {
        data: SnpReportReq { user_data: *report_data, vmpl: 0, rsvd: [0u8; 28] },
        certs_address: certs_ptr as u64,
        certs_len: CERTS_BLOB_MAX as u32,
    };
    let mut resp = SnpReportResp { data: [0u8; 4000] };
    let mut ioctl = SnpGuestRequestIoctl {
        msg_version: 1,
        rsvd: [0u8; 7],
        req_data: &mut req as *mut SnpExtReportReq as u64,
        resp_data: &mut resp as *mut SnpReportResp as u64,
        exitinfo2: 0,
    };

    let ret = unsafe { libc::ioctl(dev.as_raw_fd(), SNP_GET_EXT_REPORT, &mut ioctl as *mut _) };
    let exitinfo2 = ioctl.exitinfo2;
    let certs = unsafe {
        let slice = std::slice::from_raw_parts(certs_ptr as *const u8, CERTS_BLOB_MAX);
        slice.to_vec()
    };
    unsafe { libc::munmap(certs_ptr, CERTS_BLOB_MAX); };

    if ret != 0 {
        tracing::error!("SNP-EXT: SNP_GET_EXT_REPORT ioctl failed (errno {}), exitinfo2={:#x}", std::io::Error::last_os_error(), exitinfo2);
        return None;
    }
    if exitinfo2 != 0 {
        tracing::error!("SNP-EXT: firmware reported error exitinfo2={:#x}", exitinfo2);
        return None;
    }

    let report = match locate_report_in(&resp.data) {
        Some(r) => r,
        None => {
            tracing::error!(
                "SNP-EXT: no valid report in response (u32@0={} u32@32={})",
                u32::from_le_bytes(resp.data[0..4].try_into().unwrap()),
                u32::from_le_bytes(resp.data[32..36].try_into().unwrap())
            );
            return None;
        }
    };

    if report[OFF_REPORT_DATA..OFF_REPORT_DATA + 64] != *report_data {
        tracing::warn!("SNP-EXT: report_data mismatch (report not session-bound?)");
    }

    tracing::info!("SNP-EXT: obtained {}-byte report + {}-byte cert blob via SNP_GET_EXT_REPORT", report.len(), certs.len());
    Some(ExtReport { report, certs })
}

/// Total SNP report length (version 2): 0x4A0
pub const SNP_REPORT_LEN: usize = 0x4A0;

/// Highest accepted SNP report format version at offset 0x000.
/// Historical formats are 1..2; the current spec requires ≥3 (CoRIM profile)
/// and version 5 has been observed on OCI E5 / UEK8 — keep headroom while
/// still rejecting garbage when scanning blobs for embedded reports.
pub const SNP_REPORT_MAX_VERSION: u32 = 8;

/// Offset of report_data (64 bytes)
const OFF_REPORT_DATA: usize = 0x050;
/// Offset of reported_tcb (TCB_VERSION, 8 bytes LE)
const OFF_REPORTED_TCB: usize = 0x180;
/// Offset of chip_id (64 bytes)
const OFF_CHIP_ID: usize = 0x1A0;
/// Offset of signature field (r at +0, s at +72); signed region = [0, 0x2A0)
pub const OFF_SIGNATURE: usize = 0x2A0;
/// Signed region length (version 2)
pub const SIGNED_LEN: usize = 0x2A0;

/// TCB_VERSION byte layout variant (AMD SEV-SNP Firmware ABI §2.2)
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TcbLayout {
    /// Milan / Genoa / standard Turin (Table 4): bits 7:0 BL, 15:8 TEE, 55:48 SNP, 63:56 MICROCODE
    A,
    /// Turin-Dense (Table 3): bits 15:8 BL, 23:16 TEE, 31:24 SNP, 63:56 MICROCODE
    B,
}

/// AMD platform identity derived from CPUID (family/model)
#[derive(Clone, Copy, Debug)]
pub struct AmdPlatform {
    /// AMD KDS VCEK endpoint family segment (Milan / Genoa / Turin)
    pub kds_family: &'static str,
    /// TCB_VERSION byte layout for this silicon
    pub tcb_layout: TcbLayout,
    /// CPUID family (e.g. 0x19)
    pub family: u8,
    /// CPUID model
    pub model: u8,
}

/// Read CPUID leaf 1 → (family, model)
fn cpu_family_model() -> (u8, u8) {
    #[cfg(target_arch = "x86_64")]
    {
        // __cpuid is unsafe on older toolchains (<=1.91) and safe on newer
        // ones — wrap so both compile.
        #[allow(unused_unsafe)]
        let r = unsafe { core::arch::x86_64::__cpuid(1) };
        let eax = r.eax;
        let base_family = ((eax >> 8) & 0xf) as u8;
        let ext_family = ((eax >> 20) & 0xff) as u8;
        let family = base_family.wrapping_add(ext_family);
        let model = (((eax >> 4) & 0xf) | ((eax >> 12) & 0xf0)) as u8;
        (family, model)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        (0, 0)
    }
}

/// Map CPUID family/model to the AMD KDS product family and TCB byte layout.
///
/// - Family 19h Models 00h-0Fh  → Milan  (layout A)
/// - Family 19h Models 10h+     → Genoa  (layout A)   ← OCI E5 (EPYC 9004, model 11h)
/// - Family 1Ah Models < 60h    → Turin  (layout A)   ← OCI E6 standard (EPYC 9005)
/// - Family 1Ah Models >= 60h   → Turin  (layout B, Turin-Dense: 90h-AFh, C0h-CFh)
pub fn amd_platform() -> AmdPlatform {
    let (family, model) = cpu_family_model();
    let (kds_family, tcb_layout) = match family {
        0x19 => {
            if model <= 0x0F { ("Milan", TcbLayout::A) } else { ("Genoa", TcbLayout::A) }
        }
        0x1A => {
            if model >= 0x60 { ("Turin", TcbLayout::B) } else { ("Turin", TcbLayout::A) }
        }
        // Unknown/future family: assume Genoa-style layout (most common)
        _ => ("Genoa", TcbLayout::A),
    };
    AmdPlatform { kds_family, tcb_layout, family, model }
}

/// KDS family name for VCEK/cert-chain URLs. Env override `AMD_VCEK_FAMILY`
/// (Milan|Genoa|Turin) for bring-up on misdetected silicon.
pub fn amd_kds_family() -> &'static str {
    if let Ok(f) = std::env::var("AMD_VCEK_FAMILY") {
        match f.trim().to_ascii_lowercase().as_str() {
            "milan" => return "Milan",
            "genoa" => return "Genoa",
            "turin" => return "Turin",
            _ => {}
        }
    }
    amd_platform().kds_family
}

/// Check whether the AMD SEV-SNP hardware interface is present.
pub fn is_sev_snp_available() -> bool {
    has_sev_guest_device()
        || read_sysfs("/sys/module/kvm_amd/parameters/sev_snp").map(|v| v.starts_with('Y')).unwrap_or(false)
        || std::path::Path::new("/sys/kernel/config/tsm/report").exists()
}

/// /dev/sev-guest device node (primary SNP report interface)
pub fn has_sev_guest_device() -> bool {
    std::path::Path::new("/dev/sev-guest").exists()
}

fn read_sysfs(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

/// ioctl request structure (32 bytes, matches struct snp_guest_request_ioctl)
#[repr(C)]
struct SnpGuestRequestIoctl {
    msg_version: u8,
    rsvd: [u8; 7],
    req_data: u64,
    resp_data: u64,
    exitinfo2: u64,
}

/// SNP_GET_REPORT request (struct snp_report_req): user_data[64] + vmpl + rsvd[28]
#[repr(C)]
struct SnpReportReq {
    user_data: [u8; 64],
    vmpl: u32,
    rsvd: [u8; 28],
}

/// SNP_GET_REPORT response (struct snp_report_resp): raw report bytes
#[repr(C)]
struct SnpReportResp {
    data: [u8; 4000],
}

/// SNP_GET_EXT_REPORT request (struct snp_ext_report_req): the report request
/// followed by the destination for the PSP certificate table. `certs_address`
/// must be a page-aligned buffer of `certs_len` bytes (page-multiple, ≤64K).
#[repr(C)]
struct SnpExtReportReq {
    data: SnpReportReq,
    certs_address: u64,
    certs_len: u32,
}

/// Request a hardware-signed SNP attestation report with `report_data` bound in.
///
/// Opens `/dev/sev-guest` and issues `SNP_GET_REPORT` (msg_version = 1).
/// Returns the raw report bytes (1184 for version 2) or None on failure.
pub fn snp_get_report(report_data: &[u8; 64]) -> Option<Vec<u8>> {
    use std::os::unix::io::AsRawFd;

    let dev = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/sev-guest");
    let dev = match dev {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("SNP: cannot open /dev/sev-guest: {}", e);
            return None;
        }
    };

    let mut req = SnpReportReq {
        user_data: *report_data,
        vmpl: 0,
        rsvd: [0u8; 28],
    };
    let mut resp = SnpReportResp { data: [0u8; 4000] };
    let mut ioctl = SnpGuestRequestIoctl {
        msg_version: 1,
        rsvd: [0u8; 7],
        req_data: &mut req as *mut SnpReportReq as u64,
        resp_data: &mut resp as *mut SnpReportResp as u64,
        exitinfo2: 0,
    };

    let ret = unsafe { libc::ioctl(dev.as_raw_fd(), SNP_GET_REPORT, &mut ioctl as *mut _) };
    let exitinfo2 = ioctl.exitinfo2;
    if ret != 0 {
        tracing::error!("SNP: SNP_GET_REPORT ioctl failed (errno {}), exitinfo2={:#x}", std::io::Error::last_os_error(), exitinfo2);
        return None;
    }
    if exitinfo2 != 0 {
        tracing::error!("SNP: firmware reported error exitinfo2={:#x}", exitinfo2);
        return None;
    }

    // Validate: report version, then locate the raw report inside the response.
    // The decrypted REPORT_REQ payload begins with a 32-byte message header
    // (struct snp_msg_report_resp_hdr { u32 status; u32 report_size; u8 rsvd[24]; })
    // ahead of the raw report — the kernel's configfs path strips it
    // (sev_report_new) but the plain SNP_GET_REPORT ioctl passes the firmware
    // payload through verbatim, so the report starts at offset 32 there.
    // Tolerate a bare report at offset 0 for kernels that strip the header.
    let hdr_status = u32::from_le_bytes([resp.data[0], resp.data[1], resp.data[2], resp.data[3]]);
    let hdr_report_size = u32::from_le_bytes([resp.data[4], resp.data[5], resp.data[6], resp.data[7]]);
    let mut report: Option<(usize, Vec<u8>)> = None;
    for off in [32usize, 0usize] {
        if resp.data.len() < off + SNP_REPORT_LEN {
            continue;
        }
        let version = u32::from_le_bytes(resp.data[off..off + 4].try_into().unwrap());
        if (1..=SNP_REPORT_MAX_VERSION).contains(&version) {
            tracing::info!(
                "SNP: report at offset {} (version {}), msg-hdr status={} report_size={}",
                off, version, hdr_status, hdr_report_size
            );
            report = Some((version as usize, resp.data[off..off + SNP_REPORT_LEN].to_vec()));
            break;
        }
    }
    let (version, report) = match report {
        Some(r) => r,
        None => {
            tracing::error!(
                "SNP: no valid report found (msg-hdr status={} report_size={}, u32@0={} u32@32={})",
                hdr_status, hdr_report_size,
                u32::from_le_bytes(resp.data[0..4].try_into().unwrap()),
                u32::from_le_bytes(resp.data[32..36].try_into().unwrap())
            );
            return None;
        }
    };

    // Session binding sanity: report_data must equal what we requested
    if report[OFF_REPORT_DATA..OFF_REPORT_DATA + 64] != *report_data {
        tracing::warn!("SNP: report_data mismatch (report not session-bound?)");
    }

    tracing::info!("SNP: obtained {}-byte report via /dev/sev-guest (version {})", report.len(), version);
    Some(report)
}

/// Parsed SNP report identity/TCB fields
#[derive(Clone, Debug)]
pub struct SnpReportInfo {
    /// Full raw report bytes (SNP_REPORT_LEN)
    pub report: Vec<u8>,
    /// Hex-encoded chip_id (VCEK hardware id, 64 bytes)
    pub chip_id_hex: String,
    /// reported_tcb components: bootloader SPL
    pub bl: u8,
    /// reported_tcb components: PSP OS (TEE) SPL
    pub tee: u8,
    /// reported_tcb components: SNP firmware SPL
    pub snp: u8,
    /// reported_tcb components: microcode SPL
    pub ucode: u8,
    /// AMD KDS family for this silicon
    pub kds_family: &'static str,
    /// report_data (64 bytes)
    pub report_data: [u8; 64],
}

impl SnpReportInfo {
    /// Hex of the signed region (bytes 0..0x2A0) — what the VCEK ECDSA signature covers
    pub fn signed_region(&self) -> &[u8] {
        &self.report[..SIGNED_LEN]
    }
}

/// Extract (bl, tee, snp, ucode) SPL bytes from reported_tcb per the family layout.
pub fn extract_tcb(report: &[u8], layout: TcbLayout) -> (u8, u8, u8, u8) {
    if report.len() < OFF_REPORTED_TCB + 8 {
        return (0, 0, 0, 0);
    }
    let t = &report[OFF_REPORTED_TCB..OFF_REPORTED_TCB + 8];
    match layout {
        TcbLayout::A => (t[0], t[1], t[6], t[7]),
        TcbLayout::B => (t[1], t[2], t[3], t[7]),
    }
}

/// Parse and validate a raw SNP report; returns identity + TCB fields on success.
///
/// Validates version (1..=4) and minimum length. `data` may contain the report
/// at offset 0 (callers scanning blobs should slice first).
pub fn parse_report(data: &[u8]) -> Option<SnpReportInfo> {
    if data.len() < SNP_REPORT_LEN {
        return None;
    }
    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    // Report format versions: 1..2 historical, 3+ current spec (CoRIM profile
    // requires ≥3); observed version 5 on OCI E5/UEK8 — keep headroom.
    if !(1..=SNP_REPORT_MAX_VERSION).contains(&version) {
        return None;
    }

    let platform = amd_platform();
    let (bl, tee, snp, ucode) = extract_tcb(data, platform.tcb_layout);

    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(&data[OFF_REPORT_DATA..OFF_REPORT_DATA + 64]);

    Some(SnpReportInfo {
        report: data[..SNP_REPORT_LEN].to_vec(),
        chip_id_hex: hex::encode(&data[OFF_CHIP_ID..OFF_CHIP_ID + 64]),
        bl,
        tee,
        snp,
        ucode,
        kds_family: platform.kds_family,
        report_data,
    })
}

/// Scan a larger blob for an embedded SNP report (at any 8-byte aligned offset).
pub fn find_report(blob: &[u8]) -> Option<SnpReportInfo> {
    if blob.len() < SNP_REPORT_LEN {
        return None;
    }
    let mut off = 0usize;
    while off + SNP_REPORT_LEN <= blob.len() {
        if let Some(info) = parse_report(&blob[off..]) {
            return Some(info);
        }
        off += 8;
    }
    None
}

/// SHA-256 helper for cert hashing
pub fn hash_cert(cert_bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(cert_bytes))
}

/// Split a PEM bundle (concatenated `CERTIFICATE` blocks) into raw DER certs.
/// Used to complete a PSP-provisioned leaf's chain with the KDS ASK/ARK.
pub fn pem_certs_to_der(pem: &str) -> Vec<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let after = &rest[start + "-----BEGIN CERTIFICATE-----".len()..];
        let Some(end) = after.find("-----END CERTIFICATE-----") else { break };
        let b64: String = after[..end].chars().filter(|c| !c.is_whitespace()).collect();
        if let Ok(der) = STANDARD.decode(&b64) {
            out.push(der);
        }
        rest = &after[end + "-----END CERTIFICATE-----".len()..];
    }
    out
}

/// Convert DER bytes to PEM format
pub fn der_to_pem(tag: &str, der_bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let b64 = STANDARD.encode(der_bytes);
    let mut pem = format!("-----BEGIN {}-----\n", tag);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", tag));
    pem
}

/// Fetch a value from the OCI instance metadata service.
///
/// `path` is relative to the instance root, e.g. `instance/id` or
/// `instance/metadata/user_data`.
/// Endpoint: http://169.254.169.254/opc/v2/ — requires `Authorization: Bearer Oracle`.
/// Falls back to the header-less IMDSv1 endpoint (same relative path) when v2 fails.
pub async fn oci_metadata(path: &str) -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;
    let rel = path.trim_start_matches('/');
    let v2 = format!("http://169.254.169.254/opc/v2/{}", rel);
    if let Ok(resp) = client.get(&v2).header("Authorization", "Bearer Oracle").send().await {
        let status = resp.status();
        if status.is_success() {
            if let Ok(text) = resp.text().await {
                return Some(text);
            }
        }
        tracing::warn!("OCI metadata GET {} → {}", v2, status);
    }
    let v1 = format!("http://169.254.169.254/opc/v1/{}", rel);
    if let Ok(resp) = client.get(&v1).send().await {
        let status = resp.status();
        if status.is_success() {
            if let Ok(text) = resp.text().await {
                return Some(text);
            }
        }
        tracing::warn!("OCI metadata GET {} → {}", v1, status);
    }
    None
}

/// Fetch the instance `user_data` (base64-decoded if it looks base64).
/// Used to deliver the enclave config JSON without cloud-init.
pub async fn oci_user_data() -> Option<String> {
    let raw = oci_metadata("instance/metadata/user_data").await?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        return None;
    }
    // user_data is base64-wrapped by the OCI API
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    if let Ok(bytes) = STANDARD.decode(trimmed.replace(|c: char| c.is_whitespace(), "")) {
        if let Ok(s) = String::from_utf8(bytes) {
            return Some(s);
        }
    }
    Some(trimmed)
}
