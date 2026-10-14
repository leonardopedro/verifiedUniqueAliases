//! Regenerate ../fixtures/parity.json — the cross-language test vector
//! shared by `cargo test` (auth::tests::parity_fixture_matches_computation)
//! and `forge test --match-test test_ParityDigestMatchesRustSigner`.
//!
//!     cargo run --bin gen-parity
//!
//! After regenerating, re-run BOTH test suites; they pin the same bytes.

fn main() {
    let v = snp_vault_verifier::auth::parity_vector();
    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/parity.json");
    let s = serde_json::to_string_pretty(&v).expect("serialize");
    std::fs::write(&out, format!("{s}\n")).expect("write fixture");
    println!("wrote {}", out.display());
}
