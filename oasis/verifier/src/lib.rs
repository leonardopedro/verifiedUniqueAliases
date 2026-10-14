//! SEV-SNP attestation verifier + release-authorization signer for the
//! Oasis Sapphire `AttestedKeyVault` contract (../contracts).
//!
//! The vault releases a stored private key only against a release
//! authorization signed by this verifier's secp256k1 key. This crate is the
//! off-chain attestation gate: it verifies real AMD SEV-SNP evidence from an
//! OCI Confidential VM (`VM.Standard.E5.Flex`, Genoa) and signs only when
//! every check passes, fail-closed:
//!
//! 1. report structure (length, format version 2..=8, signature algorithm
//!    = ECDSA P-384/SHA-384)
//! 2. AMD cert chain VCEK <- ASK <- ARK (signature-checked, issuer/subject
//!    linked, ARK fingerprint pinned)
//! 3. report signature (VCEK over report bytes [0..672))
//! 4. policy bits (no debug, no migration agent, VMPL 0)
//! 5. LAUNCH_DIGEST measurement against the allowlist
//! 6. reported TCB (optional allowlist)
//! 7. report_data binding: challenge + enclave channel key + measurement +
//!    software identity fused by the enclave itself (this is what "specific
//!    software and nothing else" rests on — see README: on OCI E5 the SNP
//!    LAUNCH_DIGEST only measures OVMF, so the code identity MUST ride in
//!    the hardware-signed report_data, exactly like verifiedUniqueAliases
//!    fuses its 160-byte pre-image)
//! 8. release-authorization signature (EIP-191 over the contract's struct
//!    hash) — cross-language parity with the Solidity side is pinned by
//!    fixtures/parity.json, checked by BOTH test suites.
//!
//! Report offsets and the P-384 LE->BE signature conversion mirror
//! verifiedUniqueAliases/src/oci_snp.rs (live-validated on OCI E5 captures).

pub mod auth;
pub mod snp;

/// Crate-wide error type: every variant names the check that failed, so CLI
/// output can stay fail-closed and specific (verify.html discipline).
#[derive(Debug)]
pub enum AttestError {
    Structure(String),
    AmdChain(String),
    Signature(String),
    Policy(String),
    Measurement(String),
    Tcb(String),
    Binding(String),
    Auth(String),
    Io(String),
    Encoding(String),
}

impl std::fmt::Display for AttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestError::Structure(m) => write!(f, "SNP report structure: {m}"),
            AttestError::AmdChain(m) => write!(f, "AMD cert chain: {m}"),
            AttestError::Signature(m) => write!(f, "report signature: {m}"),
            AttestError::Policy(m) => write!(f, "SNP policy: {m}"),
            AttestError::Measurement(m) => write!(f, "measurement: {m}"),
            AttestError::Tcb(m) => write!(f, "TCB: {m}"),
            AttestError::Binding(m) => write!(f, "report_data binding: {m}"),
            AttestError::Auth(m) => write!(f, "release authorization: {m}"),
            AttestError::Io(m) => write!(f, "io: {m}"),
            AttestError::Encoding(m) => write!(f, "encoding: {m}"),
        }
    }
}

impl std::error::Error for AttestError {}

/// Parse a "0x..."-prefixed hex string into a fixed-size array.
pub fn hex_arr<const N: usize>(s: &str) -> Result<[u8; N], AttestError> {
    let trimmed = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let bytes = hex::decode(trimmed)
        .map_err(|e| AttestError::Encoding(format!("bad hex {s}: {e}")))?;
    <[u8; N]>::try_from(bytes.as_slice())
        .map_err(|_| AttestError::Encoding(format!("expected {N} bytes, got {}", bytes.len())))
}

/// Render bytes as a 0x-prefixed hex string.
pub fn hex_str(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}
