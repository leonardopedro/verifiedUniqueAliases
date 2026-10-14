//! enclave-evidence — run INSIDE the OCI SEV-SNP Confidential VM
//! (VM.Standard.E5.Flex with memory encryption). Collects a session-bound
//! SNP attestation report + the PSP's own certificate table via
//! SNP_GET_EXT_REPORT, binding the challenge, the enclave's x25519 sealing
//! channel key and the software identity into report_data.
//!
//!     enclave-evidence --challenge 0x… --channel 0x… --binary 0x… \
//!         --manifest 0x… --expiry 4102444800 --out evidence.json
//!
//! binary/manifest values are the sha256 digests of the EXACT bytes the
//! enclave runs (verbatim file hashes). The ioctl path mirrors
//! verifiedUniqueAliases/src/oci_snp.rs (live-validated on OCI E5).

use base64::Engine;
use snp_vault_verifier::snp::{expected_report_data, parse_snp_cert_table, software_binding, GUID_VCEK, GUID_VLEK};
use snp_vault_verifier::{hex_arr, hex_str, AttestError};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let get = |k: &str| -> Option<String> {
        args.iter().position(|a| a == k).and_then(|i| args.get(i + 1).cloned())
    };
    let (challenge, channel, binary, manifest, expiry, out) = match (
        get("--challenge"), get("--channel"), get("--binary"), get("--manifest"),
        get("--expiry"), get("--out"),
    ) {
        (Some(c), Some(ch), Some(b), Some(m), Some(e), Some(o)) => (c, ch, b, m, e, o),
        _ => {
            eprintln!("usage: enclave-evidence --challenge 0x… --channel 0x… --binary 0x… --manifest 0x… --expiry <unix> --out evidence.json");
            std::process::exit(2);
        }
    };

    match run(&challenge, &channel, &binary, &manifest, &expiry, &out) {
        Ok(()) => println!("wrote {out}"),
        Err(e) => {
            eprintln!("FAILED: {e}");
            std::process::exit(1);
        }
    }
}

fn run(challenge: &str, channel: &str, binary: &str, manifest: &str, expiry: &str, out: &str) -> Result<(), AttestError> {
    let challenge: [u8; 32] = hex_arr(challenge)?;
    let channel: [u8; 32] = hex_arr(channel)?;
    let binary: [u8; 32] = hex_arr(binary)?;
    let manifest: [u8; 32] = hex_arr(manifest)?;
    let expiry: u64 = expiry
        .parse()
        .map_err(|_| AttestError::Encoding("--expiry must be unix seconds".into()))?;
    let requester = std::env::var("REQUESTER_ADDRESS")
        .map_err(|_| AttestError::Io("REQUESTER_ADDRESS env (enclave Sapphire account 0x…) required".into()))?;
    let requester: [u8; 20] = hex_arr(&requester)?;

    let software = software_binding(&binary, &manifest);
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&expected_report_data(&challenge, &channel, &measurement_placeholder(), &software));
    // NOTE: the LAUNCH_DIGEST is only known AFTER the report is fetched, but
    // it must be bound INTO report_data before the PSP signs. On OCI E5 the
    // LAUNCH_DIGEST measures the OVMF launch path (identical for every
    // instance type), so the enclave fetches a first report to learn it,
    // then fetches the binding report. Two-step, exactly like the reference
    // stack's session nonce.

    println!("enclave-evidence: first report to learn LAUNCH_DIGEST…");
    let first = collect_report(&report_data)?;
    let measurement: [u8; 48] = first.report[0x90..0xC0].try_into().unwrap();
    report_data[..32].copy_from_slice(&expected_report_data(&challenge, &channel, &measurement, &software));
    println!("enclave-evidence: binding report for measurement {}…", &hex_str(&measurement)[..15]);
    let bound = collect_report(&report_data)?;

    let table = parse_snp_cert_table(&bound.certs);
    let vcek = table.vcek.clone().or(table.vlek.clone()).ok_or_else(|| {
        AttestError::Encoding("PSP cert table has neither VCEK nor VLEK".into())
    })?;
    let ask = table.ask.clone().ok_or_else(|| AttestError::Encoding("PSP cert table has no ASK".into()))?;
    let ark = table.ark.clone().ok_or_else(|| AttestError::Encoding("PSP cert table has no ARK".into()))?;
    // Sanity: the binding report's report_data must round-trip.
    if bound.report[0x50..0x80] != report_data[..32] {
        return Err(AttestError::Binding("binding report_data mismatch".into()));
    }

    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let ev = serde_json::json!({
        "report": b64(&bound.report),
        "vcek": b64(&vcek), "ask": b64(&ask), "ark": b64(&ark),
        "challenge": hex_str(&challenge),
        "channelKey": hex_str(&channel),
        "requester": hex_str(&requester),
        "expiry": expiry,
        "binarySha256": hex_str(&binary),
        "manifestSha256": hex_str(&manifest),
    });
    std::fs::write(out, format!("{}\n", serde_json::to_string_pretty(&ev)
        .map_err(|e| AttestError::Encoding(format!("evidence json: {e}")))?))
    .map_err(|e| AttestError::Io(format!("{out}: {e}")))?;
    let _ = (GUID_VCEK, GUID_VLEK); // table GUIDs re-exported for tooling
    Ok(())
}

/// report_data before the measurement is known: zeros in the measurement
/// slot (the hash input still commits to it being the placeholder, which is
/// why we fetch twice).
fn measurement_placeholder() -> [u8; 48] {
    [0u8; 48]
}

#[cfg(target_os = "linux")]
fn collect_report(report_data: &[u8; 64]) -> Result<snp_vault_verifier::snp::ExtReport, AttestError> {
    snp_get_ext_report(report_data)
}

#[cfg(not(target_os = "linux"))]
fn collect_report(_: &[u8; 64]) -> Result<snp_vault_verifier::snp::ExtReport, AttestError> {
    Err(AttestError::Io("enclave-evidence requires Linux /dev/sev-guest (run inside the OCI CVM)".into()))
}

// ---------------------------------------------------------------------------
// /dev/sev-guest SNP_GET_EXT_REPORT — ioctl structs and flow copied from
// verifiedUniqueAliases/src/oci_snp.rs (live-validated on OCI E5/UEK8).
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn snp_get_ext_report(report_data: &[u8; 64]) -> Result<snp_vault_verifier::snp::ExtReport, AttestError> {
    use std::os::unix::io::AsRawFd;

    const SNP_GET_EXT_REPORT: libc::c_ulong = 0xC0205302; // _IOWR('S', 0x02, struct snp_guest_request_ioctl)
    const CERTS_BLOB_MAX: usize = 64 * 1024;

    #[repr(C)]
    struct SnpGuestRequestIoctl {
        msg_version: u8,
        rsvd: [u8; 7],
        req_data: u64,
        resp_data: u64,
        exitinfo2: u64,
    }
    #[repr(C)]
    struct SnpReportReq {
        user_data: [u8; 64],
        vmpl: u32,
        rsvd: [u8; 28],
    }
    #[repr(C)]
    struct SnpReportResp {
        data: [u8; 4000],
    }
    #[repr(C)]
    struct SnpExtReportReq {
        data: SnpReportReq,
        certs_address: u64,
        certs_len: u32,
    }

    let dev = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/sev-guest")
        .map_err(|e| AttestError::Io(format!("/dev/sev-guest: {e}")))?;
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
        return Err(AttestError::Io(format!("mmap certs: {}", std::io::Error::last_os_error())));
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
        return Err(AttestError::Io(format!(
            "SNP_GET_EXT_REPORT ioctl failed (errno {}, exitinfo2={exitinfo2:#x})",
            std::io::Error::last_os_error()
        )));
    }
    if exitinfo2 != 0 {
        return Err(AttestError::Io(format!("firmware error exitinfo2={exitinfo2:#x}")));
    }

    // The decrypted REPORT response carries a 32-byte message header
    // (struct snp_msg_report_resp_hdr) ahead of the raw report; tolerate a
    // bare report at offset 0 for kernels that strip it (oci_snp.rs logic).
    for off in [32usize, 0usize] {
        if resp.data.len() < off + 1184 {
            continue;
        }
        let version = u32::from_le_bytes(resp.data[off..off + 4].try_into().unwrap());
        if (2..=8).contains(&version) {
            let report = resp.data[off..off + 1184].to_vec();
            if report[0x50..0x80] != report_data[..32] {
                return Err(AttestError::Binding("report_data not session-bound".into()));
            }
            return Ok(snp_vault_verifier::snp::ExtReport { report, certs });
        }
    }
    Err(AttestError::Structure("no valid report in response".into()))
}
