# AGENTS.md - Status Guidelines for GCP Confidential Auth VM

## Project Overview
`paypal-auth-vm` is a hardware-attested Rust service on **GCP Confidential VM** (AMD SEV-SNP). It provides a secure bridge for PayPal OAuth tokens, ensuring the integrity of the computing environment before secrets are accessible.

### 🏆 Current Accomplishments (v118-PROD)
- **Hardware-Isolated TLS Private Key**: Transitioned to a "Minimalist Sealing" model where only the TLS private key is TPM-bound and measurement-locked. The certificate and ACME credentials are RAM-resident but not sealed, optimizing for security-sensitive recovery (v118).
- **Hardened Hardware Binding**: Implemented a "Triple-Lock" nonce (sha256 of User Profile + Enclave Public Key) injected into both TPM Quotes and SEV-SNP reports. This cryptographically binds the identity of the signer to the physical silicon.
- **PCR-Policy Sealed Secrets**: Transitioned from simple TPM sealing to strict PCR-policy binding (0, 4, 8, 9, 15). Secrets (TLS cache) are now cryptographically un-extractable if the kernel, bootloader, or enclave binary is modified.
- **Asymmetric Auditor Verification**: Upgraded the `verify.html` auditor to perform full cryptographic signature verification of TPM quotes using WebCrypto, moving beyond simple string-matching.
- **Egress Hardening & CA Pinning**: Implemented a custom `reqwest` client with bit-perfect pinning of PayPal and Google Root CAs, neutralizing hypervisor-level Man-in-the-Middle attacks via certificate substitution.
- **DoS Mitigation**: Added a background session reaper and memory-resident TTL for pending attestations, preventing OOM attacks from uncompleted OAuth flows.

## Unified Synthesis Pipeline (v116)
To ensure 100% bitwise reproducibility regardless of the host build environment, the project uses a multi-stage Docker synthesis engine (`Dockerfile.repro`).
1.  **Phase 0: EAB Rotation**: `deploy-gcp.sh` rotates ACME credentials before the build.
2.  **Stage 1: Rust Builder**: Compiles the source for `x86_64-unknown-linux-gnu` using stable toolchains.
3.  **Stage 2: Image Builder**: Uses a fixed Debian Snapshot to bundle the kernel, bootloaders, and initramfs.
4.  **Verification**: Compares local synthesis hashes against the GitHub provenance ledger.

## Security Architecture
- **Hardware-Anchored Trust**: 
  - **SNP Launch Measurement**: Verified against the physical AMD SEV-SNP signature.
  - **Measured Boot**: PCRs 0, 4, 8, 9, 15 provide full-stack coverage.
- **Resource Isolation**: Connection dropping and bandwidth throttling are performed at the entry points to protect the native Rust state.
- **PID 1 Isolation**: No shell, no userspace utilities except specifically white-listed binaries.

## Verification Workflow (v118 Auditor)
The system provides a signed **Remote Attestation Report** on the callback page.
1. **Local verification**: Users are encouraged to download the report and `verify.html` for local, air-gapped verification to eliminate web-vector trust.
2. **GitHub Audit**: Automatically fetches Sigstore provenance from GitHub and verifies the **Atomic Run ID**.
3. **Silicon Audit**: Parsons the AMD SNP hardware report to verify the **Firmware Launch Measurement**.
4. **Disk Audit**: Compares the live `disk_manifest` against signed CI hashes.
5. **TPM Proof**: Verifies the hardware quote against the CPU-signed Attestation Key (AK).
