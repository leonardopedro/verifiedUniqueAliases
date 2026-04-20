# AGENTS.md - Status Guidelines for GCP Confidential Auth VM

## Project Overview
`paypal-auth-vm` is a hardware-attested Rust service on **GCP Confidential VM** (AMD SEV-SNP). It provides a secure bridge for PayPal OAuth tokens, ensuring the integrity of the computing environment before secrets are accessible.

### 🏆 Current Accomplishments (v116-PROD)
- **Decentralized Transparency Hub**: Migrated all static policies, auditing instructions, and the frontend auditor (`verify.html`) off the enclave and onto a publicly hosted GitHub Pages deployment. The enclave now acts purely as a headless backend API, vastly reducing its attack surface.
- **Custom Nonce Injection**: Implemented an explicit 2-step OAuth process where users are shown a secondary confirmation page to input an optional custom string (nonce) before the one-time Attestation Certificate is permanently bound to their PayPal Identity and generated.
- **Strict Kernel Egress Firewall**: Hand-rolled `nftables` via `PID 1` using bare kernel modules (`nft_chain_filter`, `nft_ct`, etc.). Enforces a strict `drop` policy, permitting *only* DHCP broadcasts (`udp 67`, `udp 68`), DNS (`udp/tcp 53`), GCP Metadata (`169.254.169.254`), and strictly required HTTPS traffic (`tcp 443`).
- **AMD Silicon Root of Trust**: Integrated direct hardware **SNP Attestation Reports** (via `/dev/sev-guest` ioctl). The launch measurement (Firmware/OVMF) is now cryptographically verified.
- **Whole-Disk Manifest verification**: Implemented recursive SHA-256 hashing of the entire EFI System Partition (ESP), proving 100% bitwise identity of the boot volume.
- **Bitwise Reproducibility Confirmed**: Achieved consistent `disk.tar.gz` hashes across local Podman and GitHub Actions runners, proving the environment is 100% deterministic and verifiable.

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

## Verification Workflow (v74 Auditor)
The system provides a signed **Remote Attestation Report** on the callback page.
1. **GitHub Audit**: Automatically fetches Sigstore provenance from GitHub and verifies the **Atomic Run ID**.
2. **Silicon Audit**: Parsons the AMD SNP hardware report to verify the **Firmware Launch Measurement**.
3. **Disk Audit**: Compares the live `disk_manifest` against signed CI hashes.
4. **TPM Proof**: Verifies the hardware quote against the CPU-signed Attestation Key (AK).
