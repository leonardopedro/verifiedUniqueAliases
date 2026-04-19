# AGENTS.md - Status Guidelines for GCP Confidential Auth VM

## Project Overview
`paypal-auth-vm` is a hardware-attested Rust service on **GCP Confidential VM** (AMD SEV-SNP). It provides a secure bridge for PayPal OAuth tokens, ensuring the integrity of the computing environment before secrets are accessible.

### 🏆 Current Accomplishments (v74)
- **AMD Silicon Root of Trust**: Integrated direct hardware **SNP Attestation Reports** (via `/dev/sev-guest` ioctl). The launch measurement (Firmware/OVMF) is now cryptographically verified, ensuring the environment is anchored exclusively in AMD hardware, independent of the Cloud Provider.
- **Whole-Disk Manifest verification**: Implemented recursive SHA-256 hashing of the entire EFI System Partition (ESP). The resulting manifest (Kernel, Initrd, GRUB Config, Bootloaders) is included in the signed enclave report, proving 100% bitwise identity of the boot volume.
- **GitHub Actions Image Atomicity**: Transitioned the supply chain into an atomic ledger. The Auditor (`verify.html`) now extracts the **GitHub Run ID** from Sigstore bundles and confirms that every component (Binary, Kernel, Initrd) was built in the same, authenticated CI session.
- **TPM Hardware Bridging**: Expanded the hardware quote to include **PCR 0 (Firmware)**, **PCR 4 (Bootloader)**, **PCR 8 (Kernel Cmdline)**, and **PCR 9 (Kernel/Initrd)**, creating a seamless audit trail from silicon to software.
- **Bitwise Reproducibility Confirmed**: Achieved consistent `disk.tar.gz` hashes across local Podman and GitHub Actions runners, proving the environment is 100% deterministic and verifiable.

## Unified Synthesis Pipeline (v74+)
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

## Verification Workflow (v74 Auditor)
The system provides a signed **Remote Attestation Report** on the callback page.
1. **GitHub Audit**: Automatically fetches Sigstore provenance from GitHub and verifies the **Atomic Run ID**.
2. **Silicon Audit**: Parsons the AMD SNP hardware report to verify the **Firmware Launch Measurement**.
3. **Disk Audit**: Compares the live `disk_manifest` against signed CI hashes.
4. **TPM Proof**: Verifies the hardware quote against the CPU-signed Attestation Key (AK).
