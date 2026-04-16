# AGENTS.md - Status Guidelines for GCP Confidential Auth VM

## Project Overview
`paypal-auth-vm` is a hardware-attested Rust service on **GCP Confidential VM** (AMD SEV-SNP). It provides a secure bridge for PayPal OAuth tokens, ensuring the integrity of the computing environment before secrets are accessible.

### 🏆 Current Accomplishments (v65)
- **Resolved Secret Corruption**: Implemented a robust `clean_input` pipeline in `upload-secrets.sh` to strip ANSI escape codes and null bytes. This prevents the "control character" JSON parsing errors previously observed during Confidential VM initialization.
- **Hardened Main Binary**: Added null-byte stripping and logging within `main.rs`'s `fetch_secret_direct` to gracefully handle potentially malformed secret payloads retrieved from Secret Manager.
- **Bitwise Reproducibility**: Achieved across the entire disk image stack (`disk.raw`, `disk.tar.gz`, `qcow2`). Using deterministic normalization of the EFI System Partition (ESP) and fixed GPT UUIDs.
- **Native PID 1 Rust Integration**: Control is handed directly from the BIOS/shim to our Rust binary `/init`. It bypasses `systemd` and standard init scripts.
- **Verified End-to-End ACME**: The enclave successfully retrieves and validates TLS certificates from Google Public CA upon first boot using automated EAB rotation.
- **Unified OAuth Abstraction**: Both "Verified" and "Full Data" flows now share a single, hardened code path.

## Unified Synthesis Pipeline (v60+)
To ensure 100% bitwise reproducibility regardless of the host build environment, the project uses a multi-stage Docker synthesis engine (`Dockerfile.repro`).
1.  **Phase 0: EAB Rotation**: `deploy-gcp.sh` rotates ACME credentials before the build starts.
2.  **Stage 1: Rust Builder**: Compiles the source for `x86_64-unknown-linux-gnu` using stable toolchains.
3.  **Stage 2: Image Builder**: Uses a Debian 13 (Trixie) environment to bundle the cloud kernel, signed shim/grub, and the native Rust initramfs.
4.  **Synthesis**: Executes `build-initramfs-tools.sh` and `build-gcp-gpt-image.sh` within the container, producing the finalized `disk.tar.gz`.
5.  **Automation**: The `deploy-gcp.sh` script orchestrates the local build, GCS upload, image registration, and SEV-SNP instance provisioning.

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
