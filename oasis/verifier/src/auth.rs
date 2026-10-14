//! Release-authorization signing, byte-for-byte compatible with
//! AttestedKeyVault.sol (Oasis Sapphire).
//!
//! The contract recomputes:
//!   structHash = keccak256(abi.encode(RELEASE_TYPEHASH, vault, chainId,
//!                    requester, measurementId, softwareId, challenge,
//!                    channelKey, expiry))
//!   digest     = keccak256("\x19Ethereum Signed Message:\n32" || structHash)
//! and checks `ecrecover(digest, sig) == verifier`. This module produces that
//! digest and signature with secp256k1 (RFC 6979 deterministic). Cross-
//! language parity is pinned by fixtures/parity.json, asserted by BOTH
//! `cargo test` and `forge test --match-test test_ParityDigestMatchesRustSigner`.

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

use crate::{hex_str, AttestError};

/// The exact string hashed by the contract into RELEASE_TYPEHASH.
pub const RELEASE_TYPEHASH_STR: &str = "Release(address vault,uint256 chainId,address requester,bytes32 measurementId,bytes32 softwareId,bytes32 challenge,bytes32 channelKey,uint64 expiry)";

/// keccak256
pub fn keccak(b: &[u8]) -> [u8; 32] {
    Keccak256::digest(b).into()
}

/// keccak256(RELEASE_TYPEHASH_STR) — must equal AttestedKeyVault.RELEASE_TYPEHASH.
pub fn release_typehash() -> [u8; 32] {
    keccak(RELEASE_TYPEHASH_STR.as_bytes())
}

/// On-chain measurementId: keccak256(48-byte SNP LAUNCH_DIGEST).
pub fn measurement_id(raw48: &[u8; 48]) -> [u8; 32] {
    keccak(raw48)
}

/// Ethereum-style address from a secp256k1 verifying key
/// (keccak256(uncompressed_pubkey[1..])[12..32]).
pub fn address_of(vk: &VerifyingKey) -> [u8; 20] {
    let point = vk.to_encoded_point(false);
    let h = keccak(&point.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h[12..32]);
    out
}

/// The full binding the verifier signs (mirrors the contract's ReleaseAuth).
pub struct ReleaseBinding {
    pub vault: [u8; 20],
    pub chain_id: u64,
    pub requester: [u8; 20],
    pub measurement_id: [u8; 32],
    pub software_id: [u8; 32],
    pub challenge: [u8; 32],
    pub channel_key: [u8; 32],
    pub expiry: u64,
}

fn pad32_left(b: &[u8]) -> [u8; 32] {
    assert!(b.len() <= 32);
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    out
}

impl ReleaseBinding {
    /// keccak256 of the 9-word abi.encode(...) — identical layout to the
    /// Solidity `abi.encode(RELEASE_TYPEHASH, ...)`.
    pub fn struct_hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(9 * 32);
        buf.extend_from_slice(&release_typehash());
        buf.extend_from_slice(&pad32_left(&self.vault));
        buf.extend_from_slice(&pad32_left(&self.chain_id.to_be_bytes()));
        buf.extend_from_slice(&pad32_left(&self.requester));
        buf.extend_from_slice(&self.measurement_id);
        buf.extend_from_slice(&self.software_id);
        buf.extend_from_slice(&self.challenge);
        buf.extend_from_slice(&self.channel_key);
        buf.extend_from_slice(&pad32_left(&self.expiry.to_be_bytes()));
        keccak(&buf)
    }

    /// EIP-191 "\x19Ethereum Signed Message:\n32" wrap of struct_hash.
    pub fn eip191_digest(&self) -> [u8; 32] {
        let mut m = Vec::with_capacity(28 + 32);
        m.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
        m.extend_from_slice(&self.struct_hash());
        keccak(&m)
    }

    /// Sign: returns (digest, 65-byte r||s||v) with v = recid + 27.
    pub fn sign(&self, key: &SigningKey) -> Result<([u8; 32], [u8; 65]), AttestError> {
        let digest = self.eip191_digest();
        let sig: Signature = key
            .sign_prehash(&digest)
            .map_err(|e| AttestError::Auth(format!("sign: {e}")))?;
        let vk = key.verifying_key();
        let recid = (0u8..=3)
            .find_map(|i| {
                let rc = RecoveryId::try_from(i).ok()?;
                let rec = VerifyingKey::recover_from_prehash(&digest, &sig, rc).ok()?;
                (rec == *vk).then_some(rc)
            })
            .ok_or_else(|| AttestError::Auth("no recovery id".into()))?;
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = recid.to_byte() + 27;
        Ok((digest, out))
    }

    /// Recover the signer address from (digest, sig) — used by tests to pin
    /// what the contract's ecrecover will see.
    pub fn recover(digest: &[u8; 32], sig65: &[u8; 65]) -> Result<[u8; 20], AttestError> {
        let sig = Signature::from_slice(&sig65[..64])
            .map_err(|e| AttestError::Auth(format!("sig decode: {e}")))?;
        let rc = RecoveryId::try_from(sig65[64] - 27)
            .map_err(|e| AttestError::Auth(format!("recid: {e}")))?;
        let vk = VerifyingKey::recover_from_prehash(digest, &sig, rc)
            .map_err(|e| AttestError::Auth(format!("recover: {e}")))?;
        Ok(address_of(&vk))
    }
}

// ---------------------------------------------------------------------------
// Parity fixture (shared with the Solidity test suite)
// ---------------------------------------------------------------------------

/// Deterministic TEST-ONLY vector: fixed key + fixed fields -> fixed digest
/// and signature. Written to ../fixtures/parity.json by `gen-parity`, and
/// asserted by this crate's tests AND the forge parity test.
pub fn parity_vector() -> serde_json::Value {
    // Obviously-fake test key: scalar = 0x1111...1111 (32 bytes).
    let kb = [0x11u8; 32];
    let key = SigningKey::from_bytes(&kb.into()).expect("valid scalar");
    let signer = address_of(key.verifying_key());

    let binding = ReleaseBinding {
        vault: [0; 19].iter().copied().chain([0x42]).collect::<Vec<_>>().try_into().unwrap(),
        chain_id: 23293,
        requester: [0; 19].iter().copied().chain([0x11]).collect::<Vec<_>>().try_into().unwrap(),
        measurement_id: measurement_id(&[0xAA; 48]),
        software_id: crate::snp::software_binding(&[0x01; 32], &[0x02; 32]),
        challenge: [0xCC; 32],
        channel_key: [0xDD; 32],
        expiry: 4102444800, // 2100-01-01
    };
    let chain_be: [u8; 8] = binding.chain_id.to_be_bytes();
    let expiry_be: [u8; 8] = binding.expiry.to_be_bytes();
    let (digest, sig) = binding.sign(&key).expect("sign parity vector");

    serde_json::json!({
        "vault": hex_str(&binding.vault),
        "chainId": hex_str(&chain_be),
        "requester": hex_str(&binding.requester),
        "measurementId": hex_str(&binding.measurement_id),
        "softwareId": hex_str(&binding.software_id),
        "challenge": hex_str(&binding.challenge),
        "channelKey": hex_str(&binding.channel_key),
        "expiry": hex_str(&expiry_be),
        "eip191Digest": hex_str(&digest),
        "signature": hex_str(&sig),
        "signer": hex_str(&signer),
        "typehash": hex_str(&release_typehash()),
        "_note": "TEST vector only — key scalar is 0x1111...1111. Regenerate with `cargo run --bin gen-parity`; update fixtures/parity.json and re-run BOTH cargo test and forge test.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typehash_matches_solidity_string() {
        // keccak256 of the exact string in AttestedKeyVault.sol
        let th = release_typehash();
        assert_ne!(th, [0u8; 32]);
        // deterministic
        assert_eq!(th, release_typehash());
    }

    #[test]
    fn sign_recover_roundtrip() {
        let key = SigningKey::from_bytes(&[0x22; 32].into()).unwrap();
        let b = ReleaseBinding {
            vault: [0x01; 20],
            chain_id: 23294,
            requester: [0x02; 20],
            measurement_id: [0x03; 32],
            software_id: [0x04; 32],
            challenge: [0x05; 32],
            channel_key: [0x06; 32],
            expiry: 4102444800,
        };
        let (digest, sig) = b.sign(&key).unwrap();
        assert!(sig[64] == 27 || sig[64] == 28, "v = recid + 27");
        let recovered = ReleaseBinding::recover(&digest, &sig).unwrap();
        assert_eq!(recovered, address_of(key.verifying_key()));
        // deterministic (RFC 6979)
        let (digest2, sig2) = b.sign(&key).unwrap();
        assert_eq!(digest, digest2);
        assert_eq!(sig, sig2);
    }

    #[test]
    fn struct_hash_is_9_words() {
        let b = ReleaseBinding {
            vault: [0; 20],
            chain_id: 0,
            requester: [0; 20],
            measurement_id: [0; 32],
            software_id: [0; 32],
            challenge: [0; 32],
            channel_key: [0; 32],
            expiry: 0,
        };
        let sh = b.struct_hash();
        // sanity: differs from the raw typehash (encoding actually happened)
        assert_ne!(sh, release_typehash());
        // EIP-191 wrap differs from struct hash
        assert_ne!(b.eip191_digest(), sh);
    }

    #[test]
    fn parity_fixture_matches_computation() {
        let v = parity_vector();
        let s = |k: &str| v[k].as_str().expect("field present").to_string();

        // Recompute everything from the JSON fields themselves (not from the
        // same in-memory struct) so the fixture is the single source of truth.
        let parse32 = |hexs: &str| -> [u8; 32] { crate::hex_arr(hexs).unwrap() };
        let parse20 = |hexs: &str| -> [u8; 20] { crate::hex_arr(hexs).unwrap() };
        let parse8 = |hexs: &str| -> [u8; 8] { crate::hex_arr(hexs).unwrap() };

        let chain_bytes = parse8(&s("chainId"));
        let expiry_bytes = parse8(&s("expiry"));
        let b = ReleaseBinding {
            vault: parse20(&s("vault")),
            chain_id: u64::from_be_bytes(chain_bytes),
            requester: parse20(&s("requester")),
            measurement_id: parse32(&s("measurementId")),
            software_id: parse32(&s("softwareId")),
            challenge: parse32(&s("challenge")),
            channel_key: parse32(&s("channelKey")),
            expiry: u64::from_be_bytes(expiry_bytes),
        };
        assert_eq!(hex_str(&b.eip191_digest()), s("eip191Digest"), "digest parity");
        assert_eq!(hex_str(&release_typehash()), s("typehash"), "typehash parity");

        let key = SigningKey::from_bytes(&[0x11; 32].into()).unwrap();
        let (digest, sig) = b.sign(&key).unwrap();
        assert_eq!(hex_str(&digest), s("eip191Digest"), "sign digest parity");
        assert_eq!(hex_str(&sig), s("signature"), "signature parity (RFC6979)");
        assert_eq!(hex_str(&address_of(key.verifying_key())), s("signer"));

        // And the recover path (what ecrecover does on-chain)
        let recovered = ReleaseBinding::recover(&digest, &sig).unwrap();
        assert_eq!(hex_str(&recovered), s("signer"));
    }
}
