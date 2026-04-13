# AGENTS.md - Status Guidelines for GCP Confidential Auth VM

## Project Overview
`paypal-auth-vm` is a hardware-attested Rust service on **GCP Confidential Space** (AMD SEV-SNP). It provides a secure bridge for PayPal OAuth tokens, ensuring the integrity of the computing environment before secrets are accessible.

### 🏆 Current Accomplishments (v60)
- **Bitwise Reproducibility**: Achieved across the entire disk image stack (`disk.raw`, `disk.tar.gz`, `qcow2`). Using deterministic normalization of the EFI System Partition (ESP) and fixed GPT UUIDs.
- **Native PID 1 Rust Integration**: Control is handed directly from the BIOS/shim to our Rust binary `/init`. It bypasses `systemd` and standard init scripts, performing early-boot bootstrapping natively.
- **Glibc-Based Runtime**: Transitioned from `musl` to `glibc` to support advanced crate dependencies while maintaining a tiny initramfs footprint.
- **Pure-Rust Networking**: Custom DHCP implementation via raw sockets, applying lease configuration via `iproute2`.
- **Hardened Attestation**: 
  - Uses the **Kernel Resource Manager** (`/dev/tpmrm0`) to prevent transient handle exhaustion and object leaks.
  - Dynamically provisions a dedicated **Attestation Key (AK)** with `sign|fixedtpm` attributes for secure hardware-rooted signing of TPM Quotes.
- **TPM Sealing & Persistence**: Certificates and ACME accounts are sealed to vTPM PCRs (0,2,4,7,8,9,15). Unsealing only succeeds on an untampered hardware platform with the correct firmware and binary identity.

## Unified Synthesis Pipeline (v60+)
To ensure 100% bitwise reproducibility regardless of the host build environment, the project uses a multi-stage Docker synthesis engine (`Dockerfile.repro`).
1.  **Stage 1: Rust Builder**: Compiles the source for `x86_64-unknown-linux-gnu` using stable toolchains.
2.  **Stage 2: Image Builder**: Uses a Debian 13 (Trixie) environment to bundle the cloud kernel, signed shim/grub, and the native Rust initramfs.
3.  **Synthesis**: Executes `build-initramfs-tools.sh` and `build-gcp-gpt-image.sh` within the container, producing the finalized `disk.tar.gz`.
4.  **Automation**: The `deploy-gcp.sh` script orchestrates the local build, GCS upload, image registration, and SEV-SNP instance provisioning.

## Security Architecture
- **PID 1 Isolation**: No shell, no userspace utilities except specifically white-listed binaries (tpm2-tools, ip, curl).
- **Secrets in RAM**: No secrets on disk; configuration and primary credentials retrieved via GCP Secret Manager at runtime, verified by TPM attestation.
- **Hardware-Anchored Trust**: 
  - **Measured Boot**: PID 1 identity extended into PCR 15.
  - **Binding**: PayPal login sessions are bound to the hardware quote, preventing credential relay attacks outside the enclave.

## Verification Workflow
The system provides a `/report` endpoint which returns a signed TPM Quote.
1. **Nonce Binding**: The quote's `extraData` is the SHA256 hash of the sensitive user record.
2. **Platform Identity**: The signature proves the quote came from the hardware vTPM.
3. **Integrity**: Verify PCR values (especially 15) to confirm the exact Rust binary version is executing.
