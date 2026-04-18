# AGENTS.md - Status Guidelines for GCP Confidential Auth VM

## Project Overview
`paypal-auth-vm` is a hardware-attested Rust service on **GCP Confidential VM** (AMD SEV-SNP). It provides a secure bridge for PayPal OAuth tokens, ensuring the integrity of the computing environment before secrets are accessible.

### 🏆 Current Accomplishments (v69)
- **Identity-Enriched Attestation**: Integrated a high-fidelity JSON attestation format that binds the PayPal user identity, the server's TLS certificate, and environment configuration into a single signed report.
- **Asymmetric Enclave Signing**: Implemented report signing via RSA-4096. The system retrieves its signing key from the Vault or generates an ephemeral one at boot, ensuring all hardware evidence is tied to a specific enclave instance.
- **TLS Reboot Recovery**: Implemented a robust TLS cache recovery mechanism using deterministic TPM primary keys and Measured Boot (PCR 15).
- **Verified End-to-End ACME**: The enclave successfully retrieves and validates TLS certificates from Google Public CA upon first boot using automated EAB rotation.
- **Bitwise Reproducibility**: Achieved across the entire disk image stack (`disk.raw`, `disk.tar.gz`, `qcow2`). 
- **Native PID 1 Rust Integration**: Control is handed directly from the BIOS/shim to our Rust binary `/init`. It bypasses `systemd` and standard init scripts.

## Unified Synthesis Pipeline (v60+)
To ensure 100% bitwise reproducibility regardless of the host build environment, the project uses a multi-stage Docker synthesis engine (`Dockerfile.repro`).
1.  **Phase 0: EAB Rotation**: `deploy-gcp.sh` rotates ACME credentials before the build starts.
2.  **Stage 1: Rust Builder**: Compiles the source for `x86_64-unknown-linux-gnu` using stable toolchains.
3.  **Stage 2: Image Builder**: Uses a Debian 13 (Trixie) environment to bundle the cloud kernel, signed shim/grub, and the native Rust initramfs.
4.  **Synthesis**: Executes synthesis scripts within the container, producing the finalized `disk.tar.gz`.
5.  **Automation**: The `deploy-gcp.sh` script orchestrates the local build, GCS upload, image registration, and SEV-SNP instance provisioning.

## Security Architecture
- **PID 1 Isolation**: No shell, no userspace utilities except specifically white-listed binaries (tpm2-tools, ip).
- **Secrets in RAM**: No secrets on disk; configuration and secrets are retrieved from GCP Secret Manager at runtime, verified by TPM attestation.
- **Hardware-Anchored Trust**: 
  - **Measured Boot**: PID 1 identity is measured into PCR 15 at startup.
  - **Identity Binding**: The hash of the PayPal user record acts as the nonce for the hardware TPM Quote.
  - **TLS Binding**: The server's own certificate is included in the signed attestation to prevent session-mitm substitution.

## Verification Workflow
The system provides a signed **Remote Attestation Report** on the callback page.
1. **JSON Payload**: Contains full identity data, timestamps, enclave config, and the hardware quote.
2. **Asymmetric Signature**: The entire JSON payload is signed by the enclave's RSA key.
3. **TPM Proof**: Verify the nested TPM Quote (SHA256 signature against the AK) to confirm the report originated from a genuine Confidential Space instance with PCR 15 matching the expected binary.
