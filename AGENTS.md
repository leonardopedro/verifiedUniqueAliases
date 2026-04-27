# AGENTS.md - Status Guidelines for GCP Confidential Auth VM

## Project Overview
`paypal-auth-vm` is a hardware-attested Rust service on **GCP Confidential VM** (AMD SEV-SNP). It provides a secure bridge for PayPal OAuth tokens, ensuring the integrity of the computing environment before secrets are accessible.

### 🏆 Current Accomplishments (v145)
- **Correct GCP vTPM Architecture**: Resolved a fundamental architectural misunderstanding about GCP Confidential VM TPM attestation. The enclave now uses the correct two-key model (see below).
- **Full EK Certificate Retrieval**: The 1560-byte Google EK/AK CA Certificate is retrieved from NVRAM index `0x01c00002` without truncation using an unbounded `tpm2 nvread`.
- **Hardened TPM Quote Verification**: Full binary parsing of `TPMS_ATTEST` in the auditor verifies the hardware-signed nonce directly from the raw TPM quote message, neutralizing session replay and forgery attacks.
- **PCR 15 Software Binding**: Strict verification of the `disk_manifest` hash against hardware PCR 15, ensuring the code running on the silicon matches the GitHub provenance.
- **PCR Composite Digest**: The auditor manually reconstructs the expected SHA-256 hash of all quoted PCRs (0, 4, 8, 9, 15) and verifies it against the value in the signed `TPMS_ATTEST` structure.
- **Egress & Metadata Hardening**: Eliminated hypervisor-controlled environment injection and enforced TLS pinning (embedded `google_ca.pem` and `paypal.pem`) for all sensitive configuration and time synchronization fetches.
- **Secure Time Synchronization**: Pinned HTTPS-based time fetching with RTC pre-seeding to the build epoch (April 6, 2026) prevents TLS rollback and clock spoofing attacks.
- **Stable OS (Trixie)**: Build system, kernel, and initramfs pinned to **Debian 13 (Trixie)** using snapshot.debian.org.

## ⚠️ Critical Architectural Knowledge: GCP vTPM Two-Key Model

This is the single most important piece of knowledge for any agent working on this project.

### The Two-Key Model
On GCP Confidential VMs, TPM attestation uses **two intentionally different keys**:

| Key | Source | Purpose |
|-----|--------|---------|
| **Google EK Certificate** | NVRAM `0x01c00002` (permanent, Google-signed) | **Silicon Identity Proof** — proves this is real GCP Confidential VM hardware |
| **Session Signing AK** | Created fresh via `tpm2_createprimary` on each attestation | **Quote Signer** — signs the TPM Quote containing PCR values + nonce |

These keys are **never the same**. A check that compares the EK cert public key to the session AK public key will **always fail** — this is not a forgery, it is correct behavior.

### Why No Persistent AK Handle?
GCP Confidential VMs (n2d with AMD SEV-SNP) **do not pre-provision persistent Attestation Key handles** in TPM NVRAM (`0x81010001`, `0x81010002`, etc. are all empty). The tools `tpm2_getcap handles-persistent` returns an empty list. Attempts to `tpm2_readpublic -c 0x81010001` will fail with error `0x18b` ("handle is not correct for the use").

### What The Auditor Must Do
The correct verification chain is:
1. **AMD SEV-SNP Report**: The auditor must extract the native `snp_report_b64` and verify its cryptographic binding to the TPM session via the `report_data` field (`SHA-256(AK_PUB + Nonce)`).
2. **AMD VCEK Verification**: The auditor must verify the ECDSA signature of the SNP report against the AMD Versioned Chip Endorsement Key (VCEK), completely bypassing Google's infrastructure.
3. **TPM Quote** (signed by session AK): Verify the `TPMS_ATTEST` structure, PCR composite, and nonce → proves measurement integrity for this session.

**CRITICAL RULE: DO NOT TRUST GOOGLE'S EK CERTIFICATE.** Using `google_ak_cert_pem` as a fallback or primary anchor is prohibited. We must rely exclusively on the hardware-signed AMD report.

### What Does NOT Work on This Platform
- **`/dev/sev-guest`**: Missing. GCP abstracts AMD SEV-SNP behind the vTPM interface.
- **ConfigFS TSM path**: Times out; the vTPM does not expose this interface reliably.
- **GCP Compute Metadata API for attestation**: Do not use. Hypervisor-controlled; not trustworthy for hardware attestation.

## Unified Synthesis Pipeline (v145)
To ensure 100% bitwise reproducibility regardless of the host build environment, the project uses a multi-stage Docker synthesis engine (`Dockerfile.repro`).
1. **Phase 0: EAB Rotation**: `deploy-gcp.sh` rotates ACME credentials before the build.
2. **Stage 1: Rust Builder**: Compiles the source for `x86_64-unknown-linux-gnu` using stable Rust toolchains on Debian Trixie.
3. **Stage 2: Image Builder**: Uses a fixed Debian snapshot to bundle the kernel, bootloaders, and initramfs.
4. **Verification**: Compares local synthesis hashes against the GitHub provenance ledger.

## Security Architecture
- **Hardware-Anchored Trust (Two-Key Model)**:
  - **Google EK Certificate** (NVRAM `0x01c00002`): DER X.509 cert issued by `EK/AK CA Intermediate` under Google's CA. Proves this is a real GCP Confidential VM instance running on AMD SEV-SNP silicon.
  - **Session Signing AK**: Created fresh per-attestation via `tpm2_createprimary`. Signs the TPM Quote containing PCR values and the session nonce.
  - **Measured Boot**: PCRs 0, 4, 8, 9, 15 provide full-stack coverage verified by TPM quote.
  - **Embedded TLS Pinning**: `google_ca.pem` and `paypal.pem` are compiled directly into the binary via `include_bytes!`, preventing filesystem-level tampering.
- **Resource Isolation**: Connection dropping and bandwidth throttling at entry points protect the native Rust state.
- **PID 1 Isolation**: No shell, no userspace utilities except specifically whitelisted binaries.

## Cryptographic Chain of Trust
```
GitHub Provenance
    └─► PCR 15 (disk_manifest SHA-256 measured into TPM at boot)
            └─► PCR Composite Hash (SHA-256 of all quoted PCRs 0,4,8,9,15)
                    └─► TPMS_ATTEST binary (signed by Session AK over PCR composite + session nonce)
                            └─► Session Nonce (SHA-256[PayPal User Hash ∥ Enclave PubKey Hash])

Google EK Certificate (NVRAM 0x01c00002)
    └─► Issued by: Google LLC / EK/AK CA Intermediate
            └─► Proves: this TPM is inside a real GCP Confidential VM (AMD SEV-SNP)
                    └─► Verified by: auditor checking Google CA issuer chain
```

Note: The EK Certificate and the TPM Quote signing key (Session AK) are separate keys. This is the **correct** TPM 2.0 attestation model.

## Verification Workflow (v145 Auditor)
The system provides a signed **Remote Attestation Report** on the OAuth callback page.
1. **Local verification**: Users are encouraged to download the report and `verify.html` for local, air-gapped verification to eliminate web-vector trust.
2. **GitHub Audit**: Automatically fetches Sigstore provenance from GitHub and verifies the **Atomic Run ID** across all components (binary, kernel, initramfs, bootloader).
3. **Silicon Audit**: Retrieves `google_ak_cert_pem` from the report and verifies:
   - Issuer contains `EK/AK CA Intermediate` or `Google Cloud Confidential Computing OS Root CA`
   - Displays decoded subject identity (instance name, zone, project)
   - Does **not** compare EK cert key to session AK key (they are intentionally different)
4. **Disk Audit**: Compares the live `disk_manifest` (SHA-256 of every EFI file) against signed CI hashes. Verifies the expected PCR 15 value matches hardware.
5. **TPM Proof**: Binary-parses `TPMS_ATTEST` (magic `0xFF544347`, type `0x8018`) to extract `extraData` (nonce) and `pcrDigest`. Verifies the session AK RSA-2048 signature over the raw quote message using WebCrypto.

## Known Constraints & Notes
- **EK Certificate ≠ Session AK** (by design): `google_ak_cert_pem` is the Google-issued EK Certificate proving hardware identity. `ak_pub_pem` is the fresh session signing key used for the TPM Quote. These keys will never match and that is correct.
- **No persistent AK handles**: `tpm2_getcap handles-persistent` returns empty on GCP Confidential VMs. The enclave creates a session AK via `tpm2_createprimary` per attestation.
- **NVRAM buffer must be unbounded**: `tpm2 nvread -s <size>` truncates the cert. Always use `tpm2 nvread` without `-s` to get the full 1560-byte EK certificate.
- **Nonce Binding**: The session nonce is `SHA-256(SHA-256(PayPal user JSON) ∥ SHA-256(enclave public key DER))`. The TPM quote's `extraData` field must contain this nonce for the audit to pass.
- **`tpm2_getcap` standalone binary**: May not be present in the minimal initramfs. Use the unified `tpm2` binary (`tpm2 getcap handles-persistent`).
