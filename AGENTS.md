# AGENTS.md - Status Guidelines for GCP Confidential Auth VM

## Project Overview
`paypal-auth-vm` is a hardware-attested Rust service on **GCP Confidential VM** (AMD SEV-SNP). It provides a secure bridge for PayPal OAuth tokens, ensuring the integrity of the computing environment before secrets are accessible.

### 🏆 Current Accomplishments (v119-FIXED)
- **Hardened TPM Quote Verification**: Implemented full binary parsing of `TPMS_ATTEST` in the auditor to verify the nonce (`extraData`), neutralizing session replay and forgery attacks.
- **PCR 15 Software Binding**: Restored strict verification of the `disk_manifest` hash against hardware PCR 15, ensuring the code running on the silicon matches the GitHub provenance.
- **AK Root of Trust**: Implemented cryptographic verification of the Attestation Key (AK) against the hardware Endorsement Key (EK) certificate and trusted manufacturer roots.
- **Egress & Metadata Hardening**: Eliminated hypervisor-controlled environment injection and enforced TLS pinning (hardened client) for all sensitive configuration and time synchronization fetches.
- **Secure Time Synchronization**: Transitioned from plaintext metadata headers to pinned HTTPS-based time fetching to prevent TLS rollback and clock spoofing attacks.
- **Stable OS Migration (Trixie)**: Transitioned the entire build system, kernel, and initramfs to **Debian 13 (Trixie)** using pinned snapshots.

## Unified Synthesis Pipeline (v119)
To ensure 100% bitwise reproducibility regardless of the host build environment, the project uses a multi-stage Docker synthesis engine (`Dockerfile.repro`).
1.  **Phase 0: EAB Rotation**: `deploy-gcp.sh` rotates ACME credentials before the build.
2.  **Stage 1: Rust Builder**: Compiles the source for `x86_64-unknown-linux-gnu` using stable toolchains on Debian Trixie.
3.  **Stage 2: Image Builder**: Uses a fixed Debian Snapshot to bundle the kernel, bootloaders, and initramfs.
4.  **Verification**: Compares local synthesis hashes against the GitHub provenance ledger.

## Security Architecture
- **Hardware-Anchored Trust**: 
  - **SNP Launch Measurement**: Verified against the physical AMD SEV-SNP signature.
  - **Measured Boot**: PCRs 0, 4, 8, 9, 15 provide full-stack coverage.
- **Resource Isolation**: Connection dropping and bandwidth throttling are performed at the entry points to protect the native Rust state.
- **PID 1 Isolation**: No shell, no userspace utilities except specifically white-listed binaries.

## Verification Workflow (v119 Auditor)
The system provides a signed **Remote Attestation Report** on the callback page.
1. **Local verification**: Users are encouraged to download the report and `verify.html` for local, air-gapped verification to eliminate web-vector trust.
2. **GitHub Audit**: Automatically fetches Sigstore provenance from GitHub and verifies the **Atomic Run ID** across all components.
3. **Silicon Audit**: Verifies the platform is a genuine AMD SEV-SNP processor or a verified Google Confidential VM via AK Certificate signature.
4. **Disk Audit**: Compares the live `disk_manifest` against signed CI hashes.
5. **TPM Proof**: Verifies the hardware quote against the CPU-signed Attestation Key (AK) using WebCrypto.
