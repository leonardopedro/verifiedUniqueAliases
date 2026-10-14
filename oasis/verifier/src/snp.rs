//! AMD SEV-SNP evidence verification (report parsing, AMD chain, policy,
//! measurement, report_data binding). Offsets and the LE->BE signature
//! conversion are taken from verifiedUniqueAliases/src/oci_snp.rs and
//! verifiedUniqueAliases/verify.html, which are live-validated against real
//! OCI E5 captures.

use sha2::{Digest, Sha256, Sha384};

use crate::{hex_str, AttestError};

// ---------------------------------------------------------------------------
// Report layout constants (AMD SEV-SNP Firmware ABI, validated by the
// reference stack on OCI E5)
// ---------------------------------------------------------------------------

/// Total report length: 0x4A0 = 1184 bytes.
pub const SNP_REPORT_LEN: usize = 0x4A0;
/// Signed region: bytes [0, 0x2A0) = [0, 672).
pub const SIGNED_LEN: usize = 0x2A0;
/// Offset of POLICY (u64 LE).
pub const OFF_POLICY: usize = 0x008;
/// Offset of VMPL (u32 LE).
pub const OFF_VMPL: usize = 0x030;
/// Offset of SIGNATURE_ALGORITHM (u32 LE); 1 = ECDSA P-384/SHA-384.
pub const OFF_SIG_ALGS: usize = 0x034;
/// Offset of REPORT_DATA (64 bytes).
pub const OFF_REPORT_DATA: usize = 0x050;
/// Offset of MEASUREMENT / LAUNCH_DIGEST (48 bytes).
pub const OFF_MEASUREMENT: usize = 0x090;
/// Offset of REPORTED_TCB (TCB_VERSION, 8 bytes LE).
pub const OFF_REPORTED_TCB: usize = 0x180;
/// Offset of CHIP_ID (64 bytes).
pub const OFF_CHIP_ID: usize = 0x1A0;
/// Offset of SIGNATURE field (r at +0, s at +72; 72-byte LE each).
pub const OFF_SIGNATURE: usize = 0x2A0;

/// Highest accepted report format version (headroom above the observed v5 —
/// same posture as the reference stack).
pub const SNP_REPORT_MAX_VERSION: u32 = 8;

/// SIGNATURE_ALGORITHM == 1: ECDSA with curve P-384 and SHA-384.
pub const SIG_ALG_ECDSA_P384_SHA384: u32 = 1;

// Policy bit positions (AMD SEV-SNP Firmware ABI / go-sev-guest abi):
/// Bit 19: debug — must be 0 (no confidentiality guarantee with debug on).
pub const POLICY_DEBUG_BIT: u32 = 19;
/// Bit 18: migrate (migration agent can decrypt memory) — must be 0.
pub const POLICY_MIGRATE_MA_BIT: u32 = 18;

// ---------------------------------------------------------------------------
// AMD root pins (sha256 of the ARK DER, per CPU family) — same pins as
// verifiedUniqueAliases/verify.html
// ---------------------------------------------------------------------------

/// sha256(ARK DER) hex pins: [Genoa, Turin-Dense, Turin, Milan].
pub const ARK_PINS: [&str; 4] = [
    "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1", // Genoa (OCI E5/E6)
    "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a", // Turin
    "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd", // Milan (KDS)
    "00e7040d7c71ba48530ec1aa7bcbc9f491c360fb1e58284e36ce3b49cb422998", // Milan legacy
];

// ---------------------------------------------------------------------------
// GHCB extended-report certificate table (same GUIDs as oci_snp.rs)
// ---------------------------------------------------------------------------

pub const GUID_VCEK: [u8; 16] = [0x63,0xda,0x75,0x8d,0xe6,0x64,0x45,0x64,0xad,0xc5,0xf4,0xb9,0x3b,0xe8,0xac,0xcd];
pub const GUID_VLEK: [u8; 16] = [0xa8,0x07,0x4b,0xc2,0xa2,0x5a,0x48,0x3e,0xaa,0xe6,0x39,0xc0,0x45,0xa0,0xb8,0xa1];
pub const GUID_ASK:  [u8; 16] = [0x4a,0xb7,0xb3,0x79,0xbb,0xac,0x4f,0xe4,0xa0,0x2f,0x05,0xae,0xf3,0x27,0xc7,0x82];
pub const GUID_ARK:  [u8; 16] = [0xc0,0xb4,0x06,0xa4,0xa8,0x03,0x49,0x52,0x97,0x43,0x3f,0xb6,0x01,0x4c,0xd0,0xae];

/// Report + PSP certificate blob from `SNP_GET_EXT_REPORT` (see the
/// enclave-evidence binary; same shape as the reference stack's ExtReport).
#[derive(Clone, Debug)]
pub struct ExtReport {
    pub report: Vec<u8>,
    pub certs: Vec<u8>,
}

/// Certificates pulled from the PSP alongside the report (extended request).
#[derive(Clone, Debug, Default)]
pub struct PspCertTable {
    pub vcek: Option<Vec<u8>>,
    pub vlek: Option<Vec<u8>>,
    pub ask: Option<Vec<u8>>,
    pub ark: Option<Vec<u8>>,
}

/// Parse the GHCB extended-report certificate table: repeated 24-byte
/// `{GUID[16], offset: u32 LE, length: u32 LE}` entries, all-zero terminated,
/// cert bytes at `blob[offset..offset+length]`.
pub fn parse_snp_cert_table(certs: &[u8]) -> PspCertTable {
    let mut out = PspCertTable::default();
    const ENTRY: usize = 24;
    let mut idx = 0usize;
    while idx + ENTRY <= certs.len() {
        let e = &certs[idx..idx + ENTRY];
        let guid: [u8; 16] = e[0..16].try_into().unwrap();
        if guid == [0u8; 16] {
            break;
        }
        let off = u32::from_le_bytes(e[16..20].try_into().unwrap()) as usize;
        let len = u32::from_le_bytes(e[20..24].try_into().unwrap()) as usize;
        if off >= certs.len() || len == 0 || off.saturating_add(len) > certs.len() {
            break;
        }
        let der = certs[off..off + len].to_vec();
        if guid == GUID_VCEK && out.vcek.is_none() {
            out.vcek = Some(der);
        } else if guid == GUID_VLEK && out.vlek.is_none() {
            out.vlek = Some(der);
        } else if guid == GUID_ASK && out.ask.is_none() {
            out.ask = Some(der);
        } else if guid == GUID_ARK && out.ark.is_none() {
            out.ark = Some(der);
        }
        idx += ENTRY;
    }
    out
}

// ---------------------------------------------------------------------------
// Parsed report view
// ---------------------------------------------------------------------------

/// Borrowed view over a raw 1184-byte SNP attestation report.
#[derive(Clone, Copy, Debug)]
pub struct SnpReport<'a> {
    raw: &'a [u8],
}

impl<'a> SnpReport<'a> {
    /// Parse + structural checks (length, version range, signature algorithm).
    pub fn parse(raw: &'a [u8]) -> Result<Self, AttestError> {
        if raw.len() != SNP_REPORT_LEN {
            return Err(AttestError::Structure(format!(
                "expected {SNP_REPORT_LEN} bytes, got {}",
                raw.len()
            )));
        }
        let version = u32::from_le_bytes(raw[0..4].try_into().unwrap());
        if !(2..=SNP_REPORT_MAX_VERSION).contains(&version) {
            return Err(AttestError::Structure(format!(
                "report format version {version} outside 2..={SNP_REPORT_MAX_VERSION}"
            )));
        }
        let sig_algs =
            u32::from_le_bytes(raw[OFF_SIG_ALGS..OFF_SIG_ALGS + 4].try_into().unwrap());
        if sig_algs != SIG_ALG_ECDSA_P384_SHA384 {
            return Err(AttestError::Structure(format!(
                "SIGNATURE_ALGORITHM {sig_algs} != {SIG_ALG_ECDSA_P384_SHA384} (ECDSA P-384/SHA-384)"
            )));
        }
        Ok(SnpReport { raw })
    }

    pub fn version(&self) -> u32 {
        u32::from_le_bytes(self.raw[0..4].try_into().unwrap())
    }
    pub fn policy(&self) -> u64 {
        u64::from_le_bytes(self.raw[OFF_POLICY..OFF_POLICY + 8].try_into().unwrap())
    }
    pub fn vmpl(&self) -> u32 {
        u32::from_le_bytes(self.raw[OFF_VMPL..OFF_VMPL + 4].try_into().unwrap())
    }
    pub fn report_data(&self) -> [u8; 64] {
        self.raw[OFF_REPORT_DATA..OFF_REPORT_DATA + 64].try_into().unwrap()
    }
    pub fn measurement(&self) -> [u8; 48] {
        self.raw[OFF_MEASUREMENT..OFF_MEASUREMENT + 48].try_into().unwrap()
    }
    pub fn reported_tcb(&self) -> [u8; 8] {
        self.raw[OFF_REPORTED_TCB..OFF_REPORTED_TCB + 8].try_into().unwrap()
    }
    pub fn chip_id(&self) -> [u8; 64] {
        self.raw[OFF_CHIP_ID..OFF_CHIP_ID + 64].try_into().unwrap()
    }
    pub fn signature_r_s(&self) -> ([u8; 48], [u8; 48]) {
        let sig = &self.raw[OFF_SIGNATURE..OFF_SIGNATURE + 144];
        (
            le72_to_be48(sig[0..72].try_into().unwrap()),
            le72_to_be48(sig[72..144].try_into().unwrap()),
        )
    }
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// Policy checks for "specific software and nothing else": no debug
    /// (bit 19), no migration agent (bit 18), VMPL 0.
    pub fn check_policy(&self) -> Result<(), AttestError> {
        let policy = self.policy();
        if (policy >> POLICY_DEBUG_BIT) & 1 != 0 {
            return Err(AttestError::Policy(
                "debug bit set — no confidentiality".into(),
            ));
        }
        if (policy >> POLICY_MIGRATE_MA_BIT) & 1 != 0 {
            return Err(AttestError::Policy(
                "migration-agent bit set — memory can be exported".into(),
            ));
        }
        if self.vmpl() != 0 {
            return Err(AttestError::Policy(format!("VMPL {} != 0", self.vmpl())));
        }
        Ok(())
    }
}

/// AMD stores r and s as 72-byte little-endian; ECDSA wants 48-byte
/// big-endian (same conversion as oci_snp.rs `to_bignum`, fixed-size).
pub fn le72_to_be48(le: &[u8; 72]) -> [u8; 48] {
    let mut be = [0u8; 48];
    let mut tmp = [0u8; 72];
    for i in 0..72 {
        tmp[i] = le[71 - i];
    }
    // tmp is now big-endian; keep the low 48 bytes of the 72-byte scalar.
    be.copy_from_slice(&tmp[24..]);
    be
}

// ---------------------------------------------------------------------------
// Certificates: OIDs, raw TBS extraction, P-384 keys
// ---------------------------------------------------------------------------

fn oid(dotted: &str) -> const_oid::ObjectIdentifier {
    const_oid::ObjectIdentifier::new(dotted).expect("valid OID string")
}

/// id-ecPublicKey (1.2.840.10045.2.1)
fn oid_ec_public_key() -> const_oid::ObjectIdentifier {
    oid("1.2.840.10045.2.1")
}
/// secp384r1 (1.3.132.0.34)
fn oid_secp384r1() -> const_oid::ObjectIdentifier {
    oid("1.3.132.0.34")
}
/// ecdsa-with-SHA384 (1.2.840.10045.4.3.3)
fn oid_ecdsa_sha384() -> const_oid::ObjectIdentifier {
    oid("1.2.840.10045.4.3.3")
}
/// rsaEncryption (1.2.840.113549.1.1.1) — AMD ARK/ASK key type
fn oid_rsa_encryption() -> const_oid::ObjectIdentifier {
    oid("1.2.840.113549.1.1.1")
}
/// RSASSA-PSS (1.2.840.113549.1.1.10) — how AMD signs ASK<-ARK and VCEK<-ASK
fn oid_rsassa_pss() -> const_oid::ObjectIdentifier {
    oid("1.2.840.113549.1.1.10")
}
/// sha384WithRSAEncryption (1.2.840.113549.1.1.12)
fn oid_sha384_rsa() -> const_oid::ObjectIdentifier {
    oid("1.2.840.113549.1.1.12")
}

/// Extract the exact TBS bytes an issuer signed (first inner TLV of the
/// outer SEQUENCE) — byte-for-byte, no re-encoding.
pub fn tbs_bytes(cert_der: &[u8]) -> Result<&[u8], AttestError> {
    fn read_tlv(d: &[u8]) -> Result<(&[u8], &[u8]), AttestError> {
        if d.len() < 2 {
            return Err(AttestError::AmdChain("truncated TLV".into()));
        }
        let (hdr, body_len) = if d[1] < 0x80 {
            (2usize, d[1] as usize)
        } else {
            let n = (d[1] & 0x7F) as usize;
            if n == 0 || n > 4 || d.len() < 2 + n {
                return Err(AttestError::AmdChain("bad length encoding".into()));
            }
            let mut l = 0usize;
            for i in 0..n {
                l = (l << 8) | d[2 + i] as usize;
            }
            (2 + n, l)
        };
        let total = hdr + body_len;
        if d.len() < total {
            return Err(AttestError::AmdChain("TLV overruns buffer".into()));
        }
        Ok((&d[..total], &d[total..]))
    }
    fn body_len(hdr0: u8, rest: &[u8]) -> Result<usize, AttestError> {
        if hdr0 < 0x80 {
            Ok(hdr0 as usize)
        } else {
            let n = (hdr0 & 0x7F) as usize;
            if n == 0 || n > 4 || rest.len() < n {
                return Err(AttestError::AmdChain("bad outer length".into()));
            }
            let mut v = 0usize;
            for i in 0..n {
                v = (v << 8) | rest[i] as usize;
            }
            Ok(v)
        }
    }
    let (outer, rest) = read_tlv(cert_der)?;
    if !rest.is_empty() {
        return Err(AttestError::AmdChain("trailing bytes after certificate".into()));
    }
    if outer[0] != 0x30 {
        return Err(AttestError::AmdChain("certificate is not a SEQUENCE".into()));
    }
    let hdr_len = match outer[1] {
        l if l < 0x80 => 2,
        l => 2 + (l & 0x7F) as usize,
    };
    let inner = &outer[hdr_len..];
    let blen = body_len(outer[1], &outer[2..])?;
    if inner.len() != blen {
        return Err(AttestError::AmdChain("outer length mismatch".into()));
    }
    // The TBS is the first inner TLV; the signature AlgorithmIdentifier and
    // the signature BIT STRING legitimately follow it inside the outer
    // SEQUENCE — we only need the exact bytes the issuer signed.
    let (tbs, _rest) = read_tlv(inner)?;
    Ok(tbs)
}

fn cert_of(der: &[u8]) -> Result<x509_cert::Certificate, AttestError> {
    use x509_cert::der::Decode;
    x509_cert::Certificate::from_der(der)
        .map_err(|e| AttestError::AmdChain(format!("X.509 parse: {e}")))
}

/// P-384 verification key from an X.509 certificate's SPKI.
pub fn p384_key_from_cert(cert_der: &[u8]) -> Result<p384::ecdsa::VerifyingKey, AttestError> {
    let cert = cert_of(cert_der)?;
    let spki = &cert.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid != oid_ec_public_key() {
        return Err(AttestError::AmdChain("SPKI is not id-ecPublicKey".into()));
    }
    // parameters must be the secp384r1 OID
    let params = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| AttestError::AmdChain("SPKI missing parameters".into()))?;
    use x509_cert::der::Encode;
    if params.to_der().map_err(|e| AttestError::AmdChain(format!("{e}")))?
        != oid_secp384r1()
            .to_der()
            .map_err(|e| AttestError::AmdChain(format!("{e}")))?
    {
        return Err(AttestError::AmdChain("SPKI is not secp384r1".into()));
    }
    let point = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| AttestError::AmdChain("SPKI not a BIT STRING".into()))?;
    p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
        .map_err(|e| AttestError::AmdChain(format!("bad P-384 point: {e}")))
}

/// RSA (PKCS#1) public key from an X.509 certificate's SPKI.
pub fn rsa_key_from_cert(cert_der: &[u8]) -> Result<rsa::RsaPublicKey, AttestError> {
    let cert = cert_of(cert_der)?;
    let spki = &cert.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid != oid_rsa_encryption() {
        return Err(AttestError::AmdChain("issuer SPKI is not rsaEncryption".into()));
    }
    use rsa::pkcs8::DecodePublicKey;
    use x509_cert::der::Encode;
    let spki_der = spki
        .to_der()
        .map_err(|e| AttestError::AmdChain(format!("SPKI encode: {e}")))?;
    rsa::RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| AttestError::AmdChain(format!("RSA SPKI parse: {e}")))
}

/// Verify `leaf_der`'s signature with `issuer_der`'s key, dispatching on the
/// issuer key type and the leaf signature algorithm:
///   * EC issuer (secp384r1): ECDSA P-384 / SHA-384 (leaf = VCEK/VLEK)
///   * RSA issuer (rsaEncryption): RSASSA-PSS / SHA-384 (what AMD uses for
///     ASK <- ARK and VCEK <- ASK — verify.html lines 520-611), with
///     sha384WithRSAEncryption accepted as fallback
/// Salt length is Auto (AMD uses 48, hash-len; the PSS encoding binds the
/// hash regardless).
pub fn verify_cert_signature(leaf_der: &[u8], issuer_der: &[u8]) -> Result<(), AttestError> {
    let leaf = cert_of(leaf_der)?;
    let issuer = cert_of(issuer_der)?;
    let leaf_tbs = tbs_bytes(leaf_der)?;
    let leaf_sig = leaf
        .signature
        .as_bytes()
        .ok_or_else(|| AttestError::AmdChain("leaf signature not a BIT STRING".into()))?
        .to_vec();
    let leaf_alg = &leaf.signature_algorithm.oid;

    let issuer_spki = &issuer.tbs_certificate.subject_public_key_info;
    if issuer_spki.algorithm.oid == oid_ec_public_key() {
        if *leaf_alg != oid_ecdsa_sha384() {
            return Err(AttestError::AmdChain(
                "EC issuer but leaf sig alg is not ecdsa-with-SHA384".into(),
            ));
        }
        let vk = p384_key_from_cert(issuer_der)?;
        let sig = p384::ecdsa::Signature::from_der(&leaf_sig)
            .map_err(|e| AttestError::AmdChain(format!("sig decode: {e}")))?;
        use p384::ecdsa::signature::hazmat::PrehashVerifier;
        vk.verify_prehash(&Sha384::digest(leaf_tbs), &sig)
            .map_err(|e| AttestError::AmdChain(format!("signature invalid: {e}")))
    } else if issuer_spki.algorithm.oid == oid_rsa_encryption() {
        let pk = rsa_key_from_cert(issuer_der)?;
        if *leaf_alg == oid_rsassa_pss() {
            use rsa::pss::VerifyingKey;
            use rsa::signature::hazmat::PrehashVerifier;
            // salt length = digest output size (48) — matches AMD's params
            let vk = VerifyingKey::<Sha384>::new(pk);
            let sig = rsa::pss::Signature::try_from(leaf_sig.as_slice())
                .map_err(|e| AttestError::AmdChain(format!("PSS sig decode: {e}")))?;
            vk.verify_prehash(&Sha384::digest(leaf_tbs), &sig)
                .map_err(|e| AttestError::AmdChain(format!("RSASSA-PSS invalid: {e}")))
        } else if *leaf_alg == oid_sha384_rsa() {
            use rsa::pkcs1v15::VerifyingKey as Pkcs1v15VerifyingKey;
            use rsa::signature::hazmat::PrehashVerifier;
            let vk = Pkcs1v15VerifyingKey::<Sha384>::new(pk);
            let sig = rsa::pkcs1v15::Signature::try_from(leaf_sig.as_slice())
                .map_err(|e| AttestError::AmdChain(format!("PKCS1 sig decode: {e}")))?;
            vk.verify_prehash(&Sha384::digest(leaf_tbs), &sig)
                .map_err(|e| AttestError::AmdChain(format!("RSASSA-PKCS1-v1_5 invalid: {e}")))
        } else {
            Err(AttestError::AmdChain(format!(
                "unsupported RSA signature algorithm {leaf_alg}"
            )))
        }
    } else {
        Err(AttestError::AmdChain("unsupported issuer key type".into()))
    }
}

/// Full chain check: leaf <- ASK <- ARK by real signatures + issuer/subject
/// linkage (not name strings alone), plus ARK fingerprint in the pin set.
pub fn validate_amd_chain(
    leaf_der: &[u8],
    ask_der: &[u8],
    ark_der: &[u8],
    ark_pins: &[&str],
) -> Result<(), AttestError> {
    use x509_cert::der::Encode;
    let leaf = cert_of(leaf_der)?;
    let ask = cert_of(ask_der)?;
    let ark = cert_of(ark_der)?;

    let name_der = |n: &x509_cert::name::Name| -> Vec<u8> { n.to_der().unwrap_or_default() };
    if name_der(&ask.tbs_certificate.issuer) != name_der(&ark.tbs_certificate.subject) {
        return Err(AttestError::AmdChain("ASK issuer != ARK subject".into()));
    }
    if name_der(&leaf.tbs_certificate.issuer) != name_der(&ask.tbs_certificate.subject) {
        return Err(AttestError::AmdChain("leaf issuer != ASK subject".into()));
    }
    verify_cert_signature(ask_der, ark_der)?;
    verify_cert_signature(leaf_der, ask_der)?;

    let ark_fp = hex_str(&Sha256::digest(ark_der));
    if !ark_pins.contains(&ark_fp.as_str()) {
        return Err(AttestError::AmdChain(format!(
            "ARK fingerprint {ark_fp} not in pin set"
        )));
    }
    Ok(())
}

/// Verify the ECDSA P-384/SHA-384 report signature against the leaf cert
/// (same math as oci_snp.rs `verify_report_signature`).
pub fn verify_report_signature(
    report: &SnpReport<'_>,
    cert_der: &[u8],
) -> Result<(), AttestError> {
    let vk = p384_key_from_cert(cert_der)?;
    let (r, s) = report.signature_r_s();
    let mut rs = [0u8; 96];
    rs[..48].copy_from_slice(&r);
    rs[48..].copy_from_slice(&s);
    let sig = p384::ecdsa::Signature::from_slice(&rs)
        .map_err(|e| AttestError::Signature(format!("r/s decode: {e}")))?;
    use p384::ecdsa::signature::hazmat::PrehashVerifier;
    vk.verify_prehash(&Sha384::digest(&report.raw()[..SIGNED_LEN]), &sig)
        .map_err(|e| AttestError::Signature(format!("report not signed by this VCEK: {e}")))
}

// ---------------------------------------------------------------------------
// report_data binding
// ---------------------------------------------------------------------------

/// Software binding pre-image: sha256(binary_sha256 || manifest_sha256).
/// Both digests are the enclave's OWN hashes of the exact bytes it runs
/// (verbatim file hashes — no JSON canonicalization trap).
pub fn software_binding(binary_sha256: &[u8; 32], manifest_sha256: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(binary_sha256);
    h.update(manifest_sha256);
    h.finalize().into()
}

/// Expected report_data[0..32]:
/// sha256(challenge || channel_pub || measurement(48) || software_binding).
/// report_data[32..64] must be zero ("and nothing else" — same discipline as
/// the reference v155 pre-image with zero tail).
pub fn expected_report_data(
    challenge: &[u8; 32],
    channel_pub: &[u8; 32],
    measurement: &[u8; 48],
    software: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(challenge);
    h.update(channel_pub);
    h.update(measurement);
    h.update(software);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Top-level verification
// ---------------------------------------------------------------------------

/// Everything the verifier must believe before signing a release.
pub struct VerifierConfig {
    /// sha256(ARK DER) pins to accept (defaults to ARK_PINS).
    pub ark_pins: Vec<String>,
    /// Allowed LAUNCH_DIGEST measurements (48 bytes each).
    pub measurements: Vec<[u8; 48]>,
    /// Optional allowlist of reported_tcb values (8 bytes each).
    pub allowed_tcb: Option<Vec<[u8; 8]>>,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        VerifierConfig {
            ark_pins: ARK_PINS.iter().map(|s| s.to_string()).collect(),
            measurements: Vec::new(),
            allowed_tcb: None,
        }
    }
}

/// A fully verified report, plus the extracted identities.
#[derive(Debug)]
pub struct VerifiedEvidence {
    pub measurement: [u8; 48],
    pub reported_tcb: [u8; 8],
    pub chip_id: [u8; 64],
}

/// Run every hardware check on one evidence bundle. Fail-closed: any error
/// means DO NOT SIGN.
pub fn verify_evidence(
    report_raw: &[u8],
    vcek: &[u8],
    ask: &[u8],
    ark: &[u8],
    challenge: &[u8; 32],
    channel_pub: &[u8; 32],
    software: &[u8; 32],
    cfg: &VerifierConfig,
) -> Result<VerifiedEvidence, AttestError> {
    // 1. structure
    let report = SnpReport::parse(report_raw)?;
    // 2. AMD chain
    let pins: Vec<&str> = cfg.ark_pins.iter().map(|s| s.as_str()).collect();
    validate_amd_chain(vcek, ask, ark, &pins)?;
    // 3. report signature
    verify_report_signature(&report, vcek)?;
    // 4. policy
    report.check_policy()?;
    // 5. measurement allowlist
    let measurement = report.measurement();
    if !cfg.measurements.contains(&measurement) {
        return Err(AttestError::Measurement(format!(
            "LAUNCH_DIGEST {} not in allowlist",
            hex_str(&measurement)
        )));
    }
    // 6. TCB allowlist (optional)
    let reported_tcb = report.reported_tcb();
    if let Some(allowed) = &cfg.allowed_tcb {
        if !allowed.contains(&reported_tcb) {
            return Err(AttestError::Tcb(format!(
                "reported_tcb {} not in allowlist",
                hex_str(&reported_tcb)
            )));
        }
    }
    // 7. report_data binding
    let rd = report.report_data();
    let expected = expected_report_data(challenge, channel_pub, &measurement, software);
    if rd[0..32] != expected {
        return Err(AttestError::Binding(format!(
            "report_data[0..32] = {}, expected {}",
            hex_str(&rd[0..32]),
            hex_str(&expected)
        )));
    }
    if rd[32..64] != [0u8; 32] {
        return Err(AttestError::Binding("report_data[32..64] not zero".into()));
    }

    Ok(VerifiedEvidence {
        measurement,
        reported_tcb,
        chip_id: report.chip_id(),
    })
}

// ---------------------------------------------------------------------------
// Tests: synthetic P-384 chain built in-test, no checked-in key material
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod testutil {
    //! Hand-built minimal DER certificates (P-384, ecdsa-with-SHA384) so the
    //! chain/signature logic is exercised against real DER, deterministically.
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
    use sha2::{Digest, Sha384};

    pub fn fixed_key(scalar_tail: u8) -> SigningKey {
        let mut fb = [0u8; 48];
        fb[47] = scalar_tail;
        SigningKey::from_bytes(&fb.into()).expect("valid scalar")
    }

    pub fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let n = body.len();
        if n < 0x80 {
            out.push(n as u8);
        } else if n < 0x100 {
            out.push(0x81);
            out.push(n as u8);
        } else {
            out.push(0x82);
            out.push((n >> 8) as u8);
            out.push(n as u8);
        }
        out.extend_from_slice(body);
        out
    }

    pub fn name_cn(cn: &str) -> Vec<u8> {
        let atv = tlv(
            0x30,
            &[tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0C, cn.as_bytes())].concat(),
        );
        let set = tlv(0x31, &atv);
        tlv(0x30, &set)
    }

    fn alg_id_ec_pubkey_p384() -> Vec<u8> {
        tlv(
            0x30,
            &[
                tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]),
                tlv(0x06, &[0x2B, 0x81, 0x04, 0x00, 0x22]),
            ]
            .concat(),
        )
    }

    fn alg_id_ecdsa_sha384() -> Vec<u8> {
        // ecdsa-with-SHA384 = 1.2.840.10045.4.3.3 — OID body is
        // 2A | 86 48 | CE 3D | 04 | 03 | 03 (8 bytes)
        tlv(0x30, &tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03]))
    }

    /// AlgorithmIdentifier for RSASSA-PSS with SHA-384, MGF1-SHA-384, salt 48
    /// (what AMD uses on ASK/ARK certs).
    pub fn pss_sig_alg() -> Vec<u8> {
        let oid_sha384 = tlv(0x06, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]);
        let hash_alg = tlv(0x30, &oid_sha384);
        let mgf_alg = tlv(
            0x30,
            &[
                tlv(0x06, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08]),
                hash_alg.clone(),
            ]
            .concat(),
        );
        let params = tlv(
            0x30,
            &[
                tlv(0xA0, &hash_alg),       // hashAlgorithm
                tlv(0xA1, &mgf_alg),        // maskGenAlgorithm
                tlv(0xA2, &tlv(0x02, &[48])), // saltLength = 48
            ]
            .concat(),
        );
        tlv(
            0x30,
            &[tlv(0x06, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A]), params].concat(),
        )
    }

    /// Fresh RSA-2048 key (test-only, generated per run).
    pub fn rsa_key() -> rsa::RsaPrivateKey {
        let mut rng = p384::elliptic_curve::rand_core::OsRng;
        rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen")
    }

    pub fn ec_spki(key: &SigningKey) -> Vec<u8> {
        let vk = VerifyingKey::from(key);
        let point = vk.to_encoded_point(false);
        let mut body = alg_id_ec_pubkey_p384();
        let mut bit = vec![0x00]; // zero unused bits
        bit.extend_from_slice(point.as_bytes());
        body.extend(tlv(0x03, &bit));
        tlv(0x30, &body)
    }

    /// Full SPKI DER (rsaEncryption + PKCS#1 RSAPublicKey BIT STRING) straight
    /// from the rsa crate's pkcs8 encoder — no hand-rolled ASN.1 here.
    pub fn rsa_spki(key: &rsa::RsaPrivateKey) -> Vec<u8> {
        use rsa::pkcs8::EncodePublicKey;
        rsa::RsaPublicKey::from(key)
            .to_public_key_der()
            .expect("rsa spki der")
            .as_ref()
            .to_vec()
    }

    /// TBS certificate DER (v3, serial 1, 2025-2035 validity).
    pub fn tbs_common(spki_body: Vec<u8>, sig_alg: &[u8], subject_cn: &str, issuer_cn: &str) -> Vec<u8> {
        let utctime = |st: &str| tlv(0x17, st.as_bytes());
        let validity = tlv(
            0x30,
            &[utctime("250101000000Z"), utctime("350101000000Z")].concat(),
        );
        let serial = tlv(0x02, &[0x01]);
        let version = tlv(0xA0, &tlv(0x02, &[0x02])[..]); // v3
        let mut body = Vec::new();
        body.extend(version);
        body.extend(serial);
        body.extend_from_slice(sig_alg);
        body.extend(name_cn(issuer_cn));
        body.extend(validity);
        body.extend(name_cn(subject_cn));
        body.extend(spki_body);
        tlv(0x30, &body)
    }

    fn int_from_be(b: &[u8]) -> Vec<u8> {
        let mut v = b.to_vec();
        while v.len() > 1 && v[0] == 0 {
            v.remove(0);
        }
        if v[0] & 0x80 != 0 {
            v.insert(0, 0);
        }
        tlv(0x02, &v)
    }

    /// Finish an EC-signed cert (DER ECDSA-Sig-Value in the BIT STRING).
    pub fn finish_cert_ec(tbs: &[u8], issuer_key: &SigningKey) -> Vec<u8> {
        let sig: Signature = issuer_key.sign_prehash(&Sha384::digest(tbs)).expect("sign");
        let bytes = sig.to_bytes();
        let (r, s) = bytes.split_at(48);
        let sig_der = tlv(0x30, &[int_from_be(r), int_from_be(s)].concat());
        let mut bit = vec![0x00];
        bit.extend(sig_der);
        let mut body = tbs.to_vec();
        body.extend(alg_id_ecdsa_sha384());
        body.extend(tlv(0x03, &bit));
        tlv(0x30, &body)
    }

    /// Finish an RSASSA-PSS-signed cert (raw signature bytes in the BIT
    /// STRING — RSA sigs are not wrapped in a DER SEQUENCE).
    pub fn finish_cert_pss(tbs: &[u8], issuer_key: &rsa::RsaPrivateKey) -> Vec<u8> {
        use rsa::pss::SigningKey as PssSigningKey;
        use rsa::signature::{SignatureEncoding, Signer};
        let signing = PssSigningKey::<Sha384>::new(issuer_key.clone());
        let sig: rsa::pss::Signature = signing.sign(tbs); // Signer::sign panics only on RNG/range failure
        let mut bit = vec![0x00];
        bit.extend_from_slice(&sig.to_vec());
        let mut body = tbs.to_vec();
        body.extend(pss_sig_alg());
        body.extend(tlv(0x03, &bit));
        tlv(0x30, &body)
    }

    /// Build an all-EC self-signed-chain cert (ECDSA-SHA384 issuer).
    pub fn build_cert(
        key: &SigningKey,
        issuer_key: &SigningKey,
        subject_cn: &str,
        issuer_cn: &str,
    ) -> Vec<u8> {
        let tbs = tbs_common(ec_spki(key), &alg_id_ecdsa_sha384(), subject_cn, issuer_cn);
        finish_cert_ec(&tbs, issuer_key)
    }

    /// Build a synthetic 1184-byte report signed by the VCEK. Signature r/s
    /// are stored the AMD way: 72-byte little-endian each.
    pub fn build_report(
        vcek: &SigningKey,
        policy: u64,
        vmpl: u32,
        sig_algs: u32,
        version: u32,
        report_data: &[u8; 64],
        measurement: &[u8; 48],
        reported_tcb: &[u8; 8],
    ) -> Vec<u8> {
        let mut r = vec![0u8; 0x4A0];
        r[0..4].copy_from_slice(&version.to_le_bytes());
        r[0x8..0x10].copy_from_slice(&policy.to_le_bytes());
        r[0x30..0x34].copy_from_slice(&vmpl.to_le_bytes());
        r[0x34..0x38].copy_from_slice(&sig_algs.to_le_bytes());
        r[0x50..0x90].copy_from_slice(report_data);
        r[0x90..0xC0].copy_from_slice(measurement);
        r[0x180..0x188].copy_from_slice(reported_tcb);
        for (i, b) in r[0x1A0..0x1E0].iter_mut().enumerate() {
            *b = i as u8;
        }

        let sig: Signature = vcek
            .sign_prehash(&Sha384::digest(&r[..0x2A0]))
            .expect("sign");
        let bytes = sig.to_bytes();
        let (rb, sb) = bytes.split_at(48);
        // store as 72-byte little-endian: BE-48 reversed, then 24 zero bytes
        // are the high bytes of the 72-byte LE field
        for (base, part) in [(0x2A0usize, rb), (0x2E8usize, sb)] {
            let mut seg = part.to_vec();
            seg.reverse(); // 48-byte LE scalar
            seg.extend_from_slice(&[0u8; 24]); // high bytes
            r[base..base + 72].copy_from_slice(&seg);
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    const POLICY_OK: u64 = 0x0003_0000; // bits 16/17 set; debug(19)=0, migrate(18)=0

    struct Fixture {
        ark: Vec<u8>,
        ask: Vec<u8>,
        vcek: Vec<u8>,
        vcek_key: p384::ecdsa::SigningKey,
        measurement: [u8; 48],
        challenge: [u8; 32],
        channel: [u8; 32],
        software: [u8; 32],
        tcb: [u8; 8],
    }

    fn fixture() -> Fixture {
        // Real AMD shape: RSA-PSS ARK -> RSA-PSS ASK -> EC VCEK (PSS-signed
        // by the ASK), VCEK signs the report with ECDSA P-384/SHA-384.
        let ark_key = rsa_key();
        let ask_key = rsa_key();
        let vcek_key = fixed_key(3);
        let ark = finish_cert_pss(
            &tbs_common(rsa_spki(&ark_key), &pss_sig_alg(), "Test ARK", "Test ARK"),
            &ark_key,
        );
        let ask = finish_cert_pss(
            &tbs_common(rsa_spki(&ask_key), &pss_sig_alg(), "Test ASK", "Test ARK"),
            &ark_key,
        );
        let vcek = finish_cert_pss(
            &tbs_common(ec_spki(&vcek_key), &pss_sig_alg(), "Test VCEK", "Test ASK"),
            &ask_key,
        );
        let measurement = [0xA5; 48];
        let challenge = [0x11; 32];
        let channel = [0x22; 32];
        let software = software_binding(&[0x01; 32], &[0x02; 32]);
        let tcb = [0x07, 0, 0, 0, 0, 0, 0, 0];
        Fixture {
            ark,
            ask,
            vcek,
            vcek_key,
            measurement,
            challenge,
            channel,
            software,
            tcb,
        }
    }

    fn good_report(f: &Fixture) -> Vec<u8> {
        let mut rd = [0u8; 64];
        rd[..32].copy_from_slice(&expected_report_data(
            &f.challenge,
            &f.channel,
            &f.measurement,
            &f.software,
        ));
        build_report(
            &f.vcek_key,
            POLICY_OK,
            0,
            SIG_ALG_ECDSA_P384_SHA384,
            5,
            &rd,
            &f.measurement,
            &f.tcb,
        )
    }

    fn cfg_for(f: &Fixture) -> VerifierConfig {
        use sha2::Digest;
        let ark_fp = hex_str(&Sha256::digest(&f.ark));
        VerifierConfig {
            ark_pins: vec![ark_fp],
            measurements: vec![f.measurement],
            allowed_tcb: Some(vec![f.tcb]),
        }
    }

    #[test]
    fn end_to_end_accepts_honest_evidence() {
        let f = fixture();
        let report = good_report(&f);
        let v = verify_evidence(
            &report, &f.vcek, &f.ask, &f.ark, &f.challenge, &f.channel, &f.software, &cfg_for(&f),
        )
        .expect("honest evidence verifies");
        assert_eq!(v.measurement, f.measurement);
        assert_eq!(v.reported_tcb, f.tcb);
        assert_eq!(v.chip_id[0], 0); // deterministic fill
    }

    #[test]
    fn rejects_debug_policy() {
        let f = fixture();
        let mut rd = [0u8; 64];
        rd[..32].copy_from_slice(&expected_report_data(
            &f.challenge, &f.channel, &f.measurement, &f.software,
        ));
        let report = build_report(
            &f.vcek_key,
            POLICY_OK | (1 << POLICY_DEBUG_BIT),
            0,
            SIG_ALG_ECDSA_P384_SHA384,
            5,
            &rd,
            &f.measurement,
            &f.tcb,
        );
        let err = verify_evidence(
            &report, &f.vcek, &f.ask, &f.ark, &f.challenge, &f.channel, &f.software, &cfg_for(&f),
        )
        .unwrap_err();
        assert!(matches!(err, AttestError::Policy(_)), "{err}");
    }

    #[test]
    fn rejects_migration_agent_policy() {
        let f = fixture();
        let mut rd = [0u8; 64];
        rd[..32].copy_from_slice(&expected_report_data(
            &f.challenge, &f.channel, &f.measurement, &f.software,
        ));
        let report = build_report(
            &f.vcek_key,
            POLICY_OK | (1 << POLICY_MIGRATE_MA_BIT),
            0,
            SIG_ALG_ECDSA_P384_SHA384,
            5,
            &rd,
            &f.measurement,
            &f.tcb,
        );
        let err = verify_evidence(
            &report, &f.vcek, &f.ask, &f.ark, &f.challenge, &f.channel, &f.software, &cfg_for(&f),
        )
        .unwrap_err();
        assert!(matches!(err, AttestError::Policy(_)), "{err}");
    }

    #[test]
    fn rejects_nonzero_vmpl() {
        let f = fixture();
        let mut rd = [0u8; 64];
        rd[..32].copy_from_slice(&expected_report_data(
            &f.challenge, &f.channel, &f.measurement, &f.software,
        ));
        let report = build_report(
            &f.vcek_key, POLICY_OK, 1, SIG_ALG_ECDSA_P384_SHA384, 5, &rd, &f.measurement, &f.tcb,
        );
        let err = verify_evidence(
            &report, &f.vcek, &f.ask, &f.ark, &f.challenge, &f.channel, &f.software, &cfg_for(&f),
        )
        .unwrap_err();
        assert!(matches!(err, AttestError::Policy(_)), "{err}");
    }

    #[test]
    fn rejects_unknown_measurement() {
        let f = fixture();
        let report = good_report(&f);
        let mut cfg = cfg_for(&f);
        cfg.measurements = vec![[0x5A; 48]]; // pinned to something else
        let err = verify_evidence(
            &report, &f.vcek, &f.ask, &f.ark, &f.challenge, &f.channel, &f.software, &cfg,
        )
        .unwrap_err();
        assert!(matches!(err, AttestError::Measurement(_)), "{err}");
    }

    #[test]
    fn rejects_bad_tcb() {
        let f = fixture();
        let report = good_report(&f);
        let mut cfg = cfg_for(&f);
        cfg.allowed_tcb = Some(vec![[0x08, 0, 0, 0, 0, 0, 0, 0]]);
        let err = verify_evidence(
            &report, &f.vcek, &f.ask, &f.ark, &f.challenge, &f.channel, &f.software, &cfg,
        )
        .unwrap_err();
        assert!(matches!(err, AttestError::Tcb(_)), "{err}");
    }

    #[test]
    fn rejects_wrong_challenge_binding() {
        let f = fixture();
        let report = good_report(&f);
        let wrong = [0x99; 32];
        let err = verify_evidence(
            &report, &f.vcek, &f.ask, &f.ark, &wrong, &f.channel, &f.software, &cfg_for(&f),
        )
        .unwrap_err();
        assert!(matches!(err, AttestError::Binding(_)), "{err}");
    }

    #[test]
    fn rejects_wrong_channel_binding() {
        let f = fixture();
        let report = good_report(&f);
        let wrong = [0x99; 32];
        let err = verify_evidence(
            &report, &f.vcek, &f.ask, &f.ark, &f.challenge, &wrong, &f.software, &cfg_for(&f),
        )
        .unwrap_err();
        assert!(matches!(err, AttestError::Binding(_)), "{err}");
    }

    #[test]
    fn rejects_nonzero_report_data_tail() {
        let f = fixture();
        let mut rd = [0u8; 64];
        rd[..32].copy_from_slice(&expected_report_data(
            &f.challenge, &f.channel, &f.measurement, &f.software,
        ));
        rd[63] = 1; // "something else" smuggled into the tail
        let report = build_report(
            &f.vcek_key, POLICY_OK, 0, SIG_ALG_ECDSA_P384_SHA384, 5, &rd, &f.measurement, &f.tcb,
        );
        let err = verify_evidence(
            &report, &f.vcek, &f.ask, &f.ark, &f.challenge, &f.channel, &f.software, &cfg_for(&f),
        )
        .unwrap_err();
        assert!(matches!(err, AttestError::Binding(_)), "{err}");
    }

    #[test]
    fn rejects_tampered_report() {
        let f = fixture();
        let mut report = good_report(&f);
        report[0x60] ^= 0xFF; // flip a byte inside the signed region
        let err = verify_evidence(
            &report, &f.vcek, &f.ask, &f.ark, &f.challenge, &f.channel, &f.software, &cfg_for(&f),
        )
        .unwrap_err();
        assert!(matches!(err, AttestError::Signature(_)), "{err}");
    }

    #[test]
    fn rejects_broken_chain() {
        let f = fixture();
        let report = good_report(&f);
        // ASK signed by a stranger key
        let stranger = fixed_key(9);
        let bad_ask = build_cert(&fixed_key(2), &stranger, "Test ASK", "Stranger ARK");
        let err = verify_evidence(
            &report, &f.vcek, &bad_ask, &f.ark, &f.challenge, &f.channel, &f.software, &cfg_for(&f),
        )
        .unwrap_err();
        assert!(matches!(err, AttestError::AmdChain(_)), "{err}");
    }

    #[test]
    fn rejects_unpinned_ark() {
        let f = fixture();
        let report = good_report(&f);
        let mut cfg = cfg_for(&f);
        cfg.ark_pins = vec!["00".repeat(32)];
        let err = verify_evidence(
            &report, &f.vcek, &f.ask, &f.ark, &f.challenge, &f.channel, &f.software, &cfg,
        )
        .unwrap_err();
        assert!(matches!(err, AttestError::AmdChain(_)), "{err}");
    }

    #[test]
    fn rejects_wrong_version_and_sigalg() {
        let f = fixture();
        let mut rd = [0u8; 64];
        rd[..32].copy_from_slice(&expected_report_data(
            &f.challenge, &f.channel, &f.measurement, &f.software,
        ));
        let r1 = build_report(&f.vcek_key, POLICY_OK, 0, SIG_ALG_ECDSA_P384_SHA384, 1, &rd, &f.measurement, &f.tcb);
        assert!(matches!(
            verify_evidence(&r1, &f.vcek, &f.ask, &f.ark, &f.challenge, &f.channel, &f.software, &cfg_for(&f)),
            Err(AttestError::Structure(_))
        ));
        let r2 = build_report(&f.vcek_key, POLICY_OK, 0, 2, 5, &rd, &f.measurement, &f.tcb);
        assert!(matches!(
            verify_evidence(&r2, &f.vcek, &f.ask, &f.ark, &f.challenge, &f.channel, &f.software, &cfg_for(&f)),
            Err(AttestError::Structure(_))
        ));
        let short = vec![0u8; 100];
        assert!(matches!(
            verify_evidence(&short, &f.vcek, &f.ask, &f.ark, &f.challenge, &f.channel, &f.software, &cfg_for(&f)),
            Err(AttestError::Structure(_))
        ));
    }

    #[test]
    fn le72_roundtrip() {
        let mut le = [0u8; 72];
        le[0] = 0x01; // LE: least significant byte first
        let be = le72_to_be48(&le);
        assert_eq!(be[47], 0x01);
        assert_eq!(be[..47], [0u8; 47]);
        // Most significant byte of the kept 48-byte window (index 47)
        let mut le2 = [0u8; 72];
        le2[47] = 0x7F;
        let be2 = le72_to_be48(&le2);
        assert_eq!(be2[0], 0x7F);
        // A byte beyond the 48-byte window (index 48) is dropped: real P-384
        // scalars are < n so bytes 48..72 are always zero.
        let mut le3 = [0u8; 72];
        le3[48] = 0x01;
        let be3 = le72_to_be48(&le3);
        assert_eq!(be3[0], 0x00);
    }

    #[test]
    fn cert_table_parse() {
        fn entry(guid: &[u8; 16], off: u32, len: u32) -> Vec<u8> {
            let mut e = guid.to_vec();
            e.extend_from_slice(&off.to_le_bytes());
            e.extend_from_slice(&len.to_le_bytes());
            e
        }
        let vcek = vec![0xAA; 10];
        let ark = vec![0xBB; 12];
        let mut blob = entry(&GUID_VCEK, 72, 10);
        blob.extend(entry(&GUID_ARK, 82, 12));
        blob.extend([0u8; 24]);
        blob.extend(&vcek);
        blob.extend(&ark);
        let t = parse_snp_cert_table(&blob);
        assert_eq!(t.vcek, Some(vcek));
        assert_eq!(t.ark, Some(ark));
        assert!(t.ask.is_none() && t.vlek.is_none());
    }

    #[test]
    fn all_ec_chain_still_verifies() {
        // Some future/alternative KDS provisioning could use EC ARK/ASK;
        // the dispatch must accept that shape too.
        let ark_key = fixed_key(4);
        let ask_key = fixed_key(5);
        let vcek_key = fixed_key(6);
        let ark = build_cert(&ark_key, &ark_key, "EC ARK", "EC ARK");
        let ask = build_cert(&ask_key, &ark_key, "EC ASK", "EC ARK");
        let vcek = build_cert(&vcek_key, &ask_key, "EC VCEK", "EC ASK");
        let measurement = [0xA5; 48];
        let challenge = [0x11; 32];
        let channel = [0x22; 32];
        let software = software_binding(&[0x01; 32], &[0x02; 32]);
        let tcb = [0x07, 0, 0, 0, 0, 0, 0, 0];
        let mut rd = [0u8; 64];
        rd[..32].copy_from_slice(&expected_report_data(&challenge, &channel, &measurement, &software));
        let report = build_report(&vcek_key, POLICY_OK, 0, SIG_ALG_ECDSA_P384_SHA384, 5, &rd, &measurement, &tcb);
        let ark_fp = hex_str(&Sha256::digest(&ark));
        let cfg = VerifierConfig {
            ark_pins: vec![ark_fp],
            measurements: vec![measurement],
            allowed_tcb: Some(vec![tcb]),
        };
        verify_evidence(&report, &vcek, &ask, &ark, &challenge, &channel, &software, &cfg)
            .expect("all-EC chain verifies");
    }

    #[test]
    fn rejects_tampered_pss_ask() {
        let f = fixture();
        let mut ask = f.ask.clone();
        let n = ask.len();
        ask[n - 5] ^= 0xFF; // flip a byte inside the PSS signature
        let report = good_report(&f);
        let err = verify_evidence(
            &report, &f.vcek, &ask, &f.ark, &f.challenge, &f.channel, &f.software, &cfg_for(&f),
        )
        .unwrap_err();
        assert!(matches!(err, AttestError::AmdChain(_)), "{err}");
    }

    #[test]
    fn tbs_bytes_are_first_inner_tlv() {
        let f = fixture();
        let tbs = tbs_bytes(&f.vcek).expect("tbs");
        assert_eq!(tbs[0], 0x30);
        // TBS + sigalg + sig == whole cert length
        assert!(tbs.len() < f.vcek.len());
    }
}
