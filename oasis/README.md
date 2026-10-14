# oasis/ — SEV-SNP-attested key vault on Oasis Sapphire

A key vault, in the spirit of [`oasisprotocol/kmaas`](https://github.com/oasisprotocol/kmaas),
that releases a stored private key **only** to an OCI Confidential VM
(AMD SEV-SNP, `VM.Standard.E5.Flex`) which proves through remote attestation
that it is running **specific software and nothing else**.

Two components:

| Piece | Path | Role |
|---|---|---|
| `AttestedKeyVault` | `contracts/` | Sapphire contract (encrypted state) holding the key; releases it against a verifier-signed authorization |
| `snp-vault-verifier` | `verifier/` | Off-chain AMD-rooted verifier + release-authorization signer + on-CVM evidence collector |

Everything here derives from the live-validated OCI SEV-SNP stack in this repo
(`../src/oci_snp.rs`, `../verify.html`) — report offsets, AMD cert handling,
ARK pins, policy bits, and the report_data binding discipline are all reused.

## Why this shape (and not Oasis-native key manager / ROFL)

Oasis's own key manager releases keys to runtimes whose **SGX/TDX** quote
matches an on-chain policy ([key manager docs](https://docs.oasis.io/core/dive-into/keymanager);
[oasis-core](https://github.com/oasisprotocol/oasis-core) registry verifies
SGX/TDX evidence), and [ROFL](https://docs.oasis.io/build/rofl/) components
are Intel-TDX-oriented. There is **no SEV-SNP quote verification in the Oasis
network stack**, so an OCI SNP CVM cannot be a first-class attested runtime.
What Sapphire *does* give us is exactly what the vault needs:

1. **Encrypted contract state** (validators never see the secret — the kmaas
   model), and
2. confidential precompiles (view-call encryption, X25519, authenticated
   symmetric encryption) to seal the release to the enclave.

So verification of the SNP evidence happens **off-chain against AMD roots**
(in this repo's verifier), and the on-chain gate is a **signature by the
registered verifier** over a binding that pins the vault, chain, requester,
measurement, software identity, a contract-issued challenge, an enclave
sealing key, and an expiry — checked by the contract before release.

## Release protocol

```
 enclave (OCI SEV-SNP CVM)              Sapphire chain                verifier (off-chain)
 ─────────────────────────              ─────────────                ───────────────────
 1. issueChallenge()          ──────►  stores live challenge
 2. enclave-evidence:                       ◄── challenge
      SNP_GET_EXT_REPORT twice
      (report_data binds challenge +
       x25519 channel pub + measurement +
       sha256(binary‖manifest))     ───────────────────────────►  3. snp-vault-attest verify:
                                                                      structure, VCEK←ASK←ARK
                                                                      (RSASSA-PSS, ARK pinned),
                                                                      report sig (P-384/SHA-384),
                                                                      policy bits, measurement
                                                                      allowlist, report_data
                                                                      binding — all must pass
                                                                  4. signs ReleaseAuth (EIP-191)
 5. release(auth, sig)        ──────►  ecrecover == verifier,
                                       challenge live + single-use,
                                       measurement/software approved,
                                       unexpired → seals secret to the
                                       channel key (X25519 ECDH +
                                       Sapphire encrypt), emits KeyReleased
 6. enclave opens the seal with its channel private key
```

### "Specific software and nothing else"

* **Hardware identity**: `LAUNCH_DIGEST` allowlist + SHA-256 pin of the AMD
  ARK DER (Genoa/Turin/Milan pins from `../verify.html`) + full signature-chain
  verification (AMD signs ASK/ARK with **RSASSA-PSS**, VCEK with ECDSA
  P-384/SHA-384) + policy bits: debug **off** (bit 19), migration agent
  **off** (bit 18), VMPL 0, optional `reported_tcb` allowlist.
* **Software identity**: per AMD SEC-02, on OCI E5 the LAUNCH_DIGEST measures
  only the OVMF launch path — identical for every instance — so the code
  identity must ride in the hardware-signed `report_data` (same lesson as the
  reference repo's v155 160-byte pre-image):

  ```
  software_binding = SHA256(binary_sha256 ‖ manifest_sha256)   // verbatim file hashes
  report_data[0:32] = SHA256(challenge ‖ channel_pub ‖ LAUNCH_DIGEST(48) ‖ software_binding)
  report_data[32:64] = 0
  ```

  The verifier recomputes this and refuses anything else. Upgrade path (not
  implemented here): GitHub artifact-attestation provenance for the binary,
  exactly like `../verify.html` does.
* **Only that enclave**: the authorization binds the enclave's x25519 channel
  public key; the contract seals the secret to it (ECIES via Sapphire
  precompiles), so only the attested enclave's channel private key can open
  the delivery — even though the ciphertext is public.

## Layout

```
oasis/
├── contracts/
│   ├── foundry.toml              # solc 0.8.28, via_ir, fs_permissions for parity fixture
│   ├── src/AttestedKeyVault.sol  # the vault (kmaas-style + attestation gate)
│   ├── src/Sapphire.sol          # vendored @oasisprotocol/sapphire-contracts (Apache-2.0)
│   └── test/AttestedKeyVault.t.sol
├── verifier/
│   ├── src/snp.rs                # report parse, AMD chain (EC+RSA-PSS), policy, binding
│   ├── src/auth.rs               # EIP-191 digest + secp256k1 signing, parity vector
│   └── src/bin/
│       ├── snp-vault-attest.rs   # verify evidence + sign authorization (fail-closed)
│       ├── enclave-evidence.rs   # run inside the CVM: /dev/sev-guest ioctl, evidence JSON
│       └── gen-parity.rs         # regenerate ../fixtures/parity.json
└── fixtures/parity.json          # cross-language vector pinned by BOTH test suites
```

## Testing

```
cd verifier && cargo test          # 22 tests: synthetic AMD-shaped chain (RSA-PSS
                                   # ARK/ASK + EC VCEK), report sig, policy/binding
                                   # negatives, EIP-191 sign/recover, parity vector
cd contracts && forge test         # 17 tests: authorization gate negatives, replay,
                                   # governance, Sapphire-chain guard, parity digest
```

The parity fixture is the single source of truth shared by both suites
(Rust signs it, Solidity recomputes the digest and ecrecovers it). After any
change to the binding format: `cargo run --bin gen-parity`, then re-run **both**
suites — same discipline as `../verify.html` vs `../src/oci_snp.rs`.

## Deploying (Sapphire testnet)

1. **Contract** (chain id 23294, RPC `https://testnet.sapphire.oasis.io`):
   deploy `AttestedKeyVault(owner, verifierAddr, enforceSapphireChainId=true,
   burnOnRelease=true)`, then
   `setApprovedMeasurement(keccak256(<48-byte LAUNCH_DIGEST>), true)` and
   `setApprovedSoftware(keccak256(<software_binding>), true)`, then
   `setSecret(<key bytes>)`.
2. **Verifier** (`verifier.json`): `verifierKey` = secp256k1 scalar whose
   address was passed as `verifierAddr`; `measurements` = the same pinned
   LAUNCH_DIGESTs; optional `arkPins`/`allowedTcb`.
3. **Enclave flow**: inside the CVM, generate an x25519 channel keypair, call
   `issueChallenge()`, run `enclave-evidence` (needs `/dev/sev-guest`;
   `REQUESTER_ADDRESS` = the enclave's Sapphire account), send
   `evidence.json` to the verifier, get `auth.json` back, call
   `release(auth, sig)` from the requester account, open the seal.

## Trust assumptions & limits (read before deploying)

* **Verifier key custody**: the verifier key is a signing oracle for release
  authorizations. Anyone holding it can authorize any *chain-valid* claim —
  but every claim still has to name an approved measurement + software id
  that the vault owner registered. Rotate via `setVerifier` (a trust re-root).
* **Allowlist governance**: whoever can call `setApprovedMeasurement`/
  `setApprovedSoftware` effectively controls trust. That is the owner key.
* **Not audited.** This is R&D code; the Solidity has not been professionally
  reviewed.
* **Not hardware-tested in this tree**: verification logic and the ioctl path
  are ported from the reference stack's live-validated code, and the crypto
  (DER/P-384/RSA-PSS/EIP-191) is exercised end-to-end in tests with
  real structures, but no run against a live OCI E5 CVM or Sapphire node has
  been performed from here.
* **Side channels**: SNP protects memory confidentiality/integrity, not
  microarchitectural side channels. No cache-timing mitigations here.
* **Availability**: no DoS protection; a paused vault is a dead vault.
* **Sapphire-only**: storage confidentiality depends on Sapphire's encrypted
  state. Deploying on a plaintext EVM chain exposes the secret; hence
  `enforceSapphireChainId` (chain ids 23293/23294).

## References

* Oasis: [kmaas](https://github.com/oasisprotocol/kmaas) (on-chain key vault
  pattern), [sapphire-contracts](https://github.com/oasisprotocol/sapphire-contracts)
  (precompile library), [key manager](https://docs.oasis.io/core/dive-into/keymanager),
  [ROFL](https://docs.oasis.io/build/rofl/), [oasis-core](https://github.com/oasisprotocol/oasis-core),
  [Sapphire docs](https://docs.oasis.io/build/sapphire/).
* AMD SEV-SNP: firmware ABI spec (report layout, policy bits, TCB versions),
  [google/go-sev-guest](https://github.com/google/go-sev-guest) (policy-bit
  positions, cert-table GUIDs), RSASSA-PSS chain semantics per `../verify.html`.
* This repo: `../src/oci_snp.rs` (ioctl path, offsets, LE→BE conversion, live
  captures), `../verify.html` (ARK pins, measurement pins, sub-check discipline).
