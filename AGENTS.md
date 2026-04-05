# AGENTS.md - Status Guidelines for GCP Confidential Auth VM

## Project Overview
`paypal-auth-vm` is a hardware-attested Rust service on **GCP Confidential Space** (AMD SEV-SNP). 

### 🏆 Current Accomplishments (v28+)
- **Bitwise Reproducibility**: achieved across the entire disk stack (`disk.raw`, `disk.tar.gz`, `qcow2`). 
  - Uses `sfdisk` with fixed Disk/Partition GUIDs.
  - Uses `mkfs.vfat --invariant` for deterministic ESP metadata.
  - Employs an **extract → normalize → rebuild** pipeline for the ESP image.
  - **Initramfs Reproducibility**: achieved via `SOURCE_DATE_EPOCH` + `zz-reproducible.sh` hook (removes `.random-seed`).
  - Processed with `add-det` for final header normalization on all artifacts.
- **Boot Isolation**: Migrated to `initramfs-tools` (native Ubuntu). Uses a custom `init-premount` script to bypass `systemd` and standard root-switching, keeping the enclave purely in RAM.
- **Network Integrity**: Native GQI GVNIC support via `ipconfig` (klibc) in the initramfs environment.
- **Platform Integrity**: Validated for **Secure Boot** using pre-signed Canonical binaries.
- **Build Efficiency**: Optimized Docker layers for incremental compilation and low-RAM compliance (`-j 1`).

## Build & Run Workflow

```bash
# 1. Reproducible Artifact Build
docker build -t paypal-builder-v28 .

# 2. Disk Synthesis
./build-gcp-gpt-image.sh

# 3. GCP Deployment
sh deploy_final.sh
```

## Architecture Details
- **Base OS**: Ubuntu 25.10 (Plucky Puffin)
- **Kernel**: `linux-image-gcp` (supporting GVNIC + SEV-SNP)
- **Initramfs**: `initramfs-tools` (native Ubuntu, systemd omitted)
- **Attestation**: Measures into PCR 15; secrets fetched via `tee-env-*` metadata.

## Security Guidelines
- **Reproducibility is Mandatory**: Ensure all synthesis scripts maintain bitwise identity.
- **Secrets Management**: No secrets on disk; RAM-only via GCP Metadata server.
- **Attestation**: PCR 15 contains the hash of the immutable initramfs and binary.
