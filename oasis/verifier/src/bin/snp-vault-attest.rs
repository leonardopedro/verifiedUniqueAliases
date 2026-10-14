//! snp-vault-attest — verify AMD SEV-SNP evidence from an OCI Confidential
//! VM and sign a release authorization for AttestedKeyVault.sol, fail-closed.
//!
//!     snp-vault-attest verify --config verifier.json --evidence evidence.json --out auth.json
//!
//! verifier.json:
//! {
//!   "verifierKey": "0x<32-byte secp256k1 scalar — the key the vault trusts>",
//!   "vault":       "0x<20-byte vault address>",
//!   "chainId":     23293,
//!   "measurements":["0x<48-byte LAUNCH_DIGEST>", ...],
//!   "arkPins":     ["0x<sha256 ARK DER hex>", ...],   // optional
//!   "allowedTcb":  ["0x<8-byte reported_tcb>", ...]   // optional
//! }
//!
//! evidence.json (produced by `enclave-evidence` inside the CVM):
//! {
//!   "report": "<base64 1184-byte SNP report>",
//!   "vcek": "<base64 DER>", "ask": "<base64 DER>", "ark": "<base64 DER>",
//!   "challenge": "0x<32>", "channelKey": "0x<32>",
//!   "requester": "0x<20 — enclave's Sapphire account>",
//!   "expiry": <unix seconds>,
//!   "binarySha256": "0x<32>", "manifestSha256": "0x<32>"
//! }

use base64::Engine;
use snp_vault_verifier::auth::{measurement_id, ReleaseBinding};
use snp_vault_verifier::snp::{software_binding, verify_evidence, VerifierConfig};
use snp_vault_verifier::{hex_arr, hex_str, AttestError};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 8 || args[1] != "verify" || args[2] != "--config" || args[4] != "--evidence" || args[6] != "--out" {
        eprintln!("usage: snp-vault-attest verify --config verifier.json --evidence evidence.json --out auth.json");
        std::process::exit(2);
    }
    match run(&args[3], &args[5], &args[7]) {
        Ok(signer) => println!("OK: signed release authorization (verifier {signer})"),
        Err(e) => {
            eprintln!("REFUSED: {e}");
            std::process::exit(1);
        }
    }
}

fn b64(s: &str, what: &str) -> Result<Vec<u8>, AttestError> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| AttestError::Encoding(format!("{what}: base64: {e}")))
}

fn run(cfg_path: &str, ev_path: &str, out_path: &str) -> Result<String, AttestError> {
    let cfg: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(cfg_path).map_err(|e| AttestError::Io(format!("{cfg_path}: {e}")))?,
    )
    .map_err(|e| AttestError::Encoding(format!("{cfg_path}: {e}")))?;
    let ev: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(ev_path).map_err(|e| AttestError::Io(format!("{ev_path}: {e}")))?,
    )
    .map_err(|e| AttestError::Encoding(format!("{ev_path}: {e}")))?;

    let g = |v: &serde_json::Value, k: &str| -> Result<String, AttestError> {
        v[k].as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| AttestError::Encoding(format!("missing string field {k}")))
    };

    // ---- config ----
    let verifier_key: [u8; 32] = hex_arr(&g(&cfg, "verifierKey")?)?;
    let vault: [u8; 20] = hex_arr(&g(&cfg, "vault")?)?;
    let chain_id = cfg["chainId"]
        .as_u64()
        .ok_or_else(|| AttestError::Encoding("missing number field chainId".into()))?;
    let mut measurements: Vec<[u8; 48]> = Vec::new();
    for m in cfg["measurements"]
        .as_array()
        .ok_or_else(|| AttestError::Encoding("measurements must be an array".into()))?
    {
        measurements.push(hex_arr(m.as_str().ok_or_else(|| {
            AttestError::Encoding("measurement entries must be hex strings".into())
        })?)?);
    }
    let mut vc = VerifierConfig { measurements, ..Default::default() };
    if let Some(pins) = cfg["arkPins"].as_array() {
        vc.ark_pins = pins
            .iter()
            .map(|p| p.as_str().unwrap_or_default().trim_start_matches("0x").to_string())
            .collect();
    }
    if let Some(tcbs) = cfg["allowedTcb"].as_array() {
        let mut v = Vec::new();
        for t in tcbs {
            v.push(hex_arr(t.as_str().ok_or_else(|| {
                AttestError::Encoding("allowedTcb entries must be hex strings".into())
            })?)?);
        }
        vc.allowed_tcb = Some(v);
    }

    // ---- evidence ----
    let report = b64(&g(&ev, "report")?, "report")?;
    let vcek = b64(&g(&ev, "vcek")?, "vcek")?;
    let ask = b64(&g(&ev, "ask")?, "ask")?;
    let ark = b64(&g(&ev, "ark")?, "ark")?;
    let challenge: [u8; 32] = hex_arr(&g(&ev, "challenge")?)?;
    let channel: [u8; 32] = hex_arr(&g(&ev, "channelKey")?)?;
    let requester: [u8; 20] = hex_arr(&g(&ev, "requester")?)?;
    let expiry = ev["expiry"]
        .as_u64()
        .ok_or_else(|| AttestError::Encoding("missing number field expiry".into()))?;
    let binary: [u8; 32] = hex_arr(&g(&ev, "binarySha256")?)?;
    let manifest: [u8; 32] = hex_arr(&g(&ev, "manifestSha256")?)?;
    let software = software_binding(&binary, &manifest);

    // ---- verify (fail-closed: any error = DO NOT SIGN) ----
    println!("SNP: report structure ................. checking");
    println!("SNP: AMD VCEK<-ASK<-ARK chain + pins .. checking");
    println!("SNP: report signature (P-384/SHA-384) . checking");
    println!("SNP: policy (no debug/migrate, VMPL0) . checking");
    println!("SNP: measurement allowlist ............ checking");
    println!("SNP: report_data binding .............. checking");
    let verified = verify_evidence(&report, &vcek, &ask, &ark, &challenge, &channel, &software, &vc)?;
    println!("all hardware checks passed (chip_id {}…)", hex_str(&verified.chip_id)[..19].to_string() + "…");

    // ---- sign the release authorization ----
    let binding = ReleaseBinding {
        vault,
        chain_id,
        requester,
        measurement_id: measurement_id(&verified.measurement),
        software_id: keccak_software_id(&software),
        challenge,
        channel_key: channel,
        expiry,
    };
    let key = k256::ecdsa::SigningKey::from_slice(&verifier_key)
        .map_err(|e| AttestError::Auth(format!("verifierKey: {e}")))?;
    let (digest, sig) = binding.sign(&key)?;
    let signer = snp_vault_verifier::auth::address_of(key.verifying_key());

    let auth = serde_json::json!({
        "requester": hex_str(&requester),
        "measurementId": hex_str(&binding.measurement_id),
        "softwareId": hex_str(&binding.software_id),
        "challenge": hex_str(&challenge),
        "channelKey": hex_str(&channel),
        "expiry": expiry,
        "vault": hex_str(&vault),
        "chainId": chain_id,
        "eip191Digest": hex_str(&digest),
        "signature": hex_str(&sig),
        "signer": hex_str(&signer),
        "chipId": hex_str(&verified.chip_id),
        "reportedTcb": hex_str(&verified.reported_tcb),
    });
    std::fs::write(
        out_path,
        format!("{}\n", serde_json::to_string_pretty(&auth).map_err(|e| {
            AttestError::Encoding(format!("auth json: {e}"))
        })?),
    )
    .map_err(|e| AttestError::Io(format!("{out_path}: {e}")))?;
    Ok(hex_str(&signer))
}

/// On-chain softwareId = keccak256(software_binding).
fn keccak_software_id(software: &[u8; 32]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    Keccak256::digest(software).into()
}
