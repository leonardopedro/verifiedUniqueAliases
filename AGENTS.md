# AGENTS.md - Status Guidelines for GCP Confidential Auth VM

## Project Overview
`paypal-auth-vm` is a hardware-attested Rust service on **GCP Confidential VM** (AMD SEV-SNP). It provides a secure bridge for PayPal OAuth tokens, ensuring the integrity of the computing environment before secrets are accessible.

### 🏆 Current Accomplishments (v119-STABLE)
- **Stable OS Migration (Trixie)**: Transitioned the entire build system, kernel, and initramfs to **Debian 13 (Trixie)** using pinned snapshots. This ensures long-term support for modern Confidential Computing drivers while maintaining bit-perfect reproducibility.
- **Hardware-Isolated TLS Private Key**: Transitioned to a "Minimalist Sealing" model where only the TLS private key is TPM-bound and measurement-locked. The certificate and ACME credentials are RAM-resident but not sealed, optimizing for security-sensitive recovery.
- **Hardened Hardware Binding**: Implemented a "Triple-Lock" nonce (sha256 of User Profile + Enclave Public Key) injected into both TPM Quotes and SEV-SNP reports. This cryptographically binds the identity of the signer to the physical silicon.
- **Set-Intersection Image Atomicity**: Upgraded the auditor to use set-intersection logic for GitHub Run IDs. This ensures that even when components (like kernels) are reused across builds, the final image is verified as a single, consistent atomic unit.
- **Asymmetric Auditor Verification**: Upgraded the `verify.html` auditor to perform full cryptographic signature verification of TPM quotes using WebCrypto, moving beyond simple string-matching.
- **GCP Silicon Root Fallback**: Implemented support for Google Attestation Key (AK) certificates in the Silicon Audit. This allows the auditor to verify the chain of trust on GCP even when raw SNP devices are abstracted, using the TPM Quote as a hardware anchor.
- **Egress Hardening & CA Pinning**: Implemented a custom `reqwest` client with bit-perfect pinning of PayPal and Google Root CAs, neutralizing hypervisor-level Man-in-the-Middle attacks via certificate substitution.

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
