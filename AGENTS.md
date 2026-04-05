# AGENTS.md - Status Guidelines for GCP Confidential Auth VM

## Project Overview
`paypal-auth-vm` is a hardware-attested Rust service on **GCP Confidential Space** (AMD SEV-SNP). 

### 🏆 Current Accomplishments (v28+)
- **Bitwise Reproducibility**: achieved across the entire disk stack (`disk.raw`, `disk.tar.gz`, `qcow2`). 
  - Uses `sfdisk` with fixed Disk/Partition GUIDs.
  - Uses `mkfs.vfat --invariant` for deterministic ESP metadata.
  - Employs an **extract → normalize → rebuild** pipeline for the ESP image.
  - **Initramfs Reproducibility**: achieved via `SOURCE_DATE_EPOCH` + `zz-reproducible.sh` hook (removes `.random-seed`).
- **Native PID 1 Rust Integration**: The entire bootloader hands control directly to our Rust binary `/init` which synchronously mounts `/proc`, `/sys`, `/dev` via the `nix` crate. It bypasses `systemd` and any other fragile init scripts completely.
- **Pure-Rust Early Boot Network**: Dropped all `klibc` dependencies. A custom Rust module broadcasts raw UDP DHCP tokens (bypassing the routing table using `libc::setsockopt` with `SO_BINDTODEVICE`), parses the binary lease, applies GCP `/32` gateway host-routes to establish standard GVE paths, and brings up the interface before the `tokio` runtime even starts.
- **Native Kernel Logging**: Bypasses standard `eprint!`/`/dev/console` stdout and writes exact boot progress directly into the kernel ring buffer via `/dev/kmsg` for persistent GCP Serial Logs.
- **Platform Integrity**: Validated for **Secure Boot** using pre-signed Canonical binaries.
- **Attestation Framework Ready**: `initramfs-tools` hook integrates `tpm2-tools` into the RAM disk for dynamic fetching of GCP SecretManager encrypted payloads.

## Hybrid Build Architecture
To maintain exact EFI/Kernel Secure Boot signatures matching GCP infrastructure, disk synthesis cannot occur locally.
1. **Local Compilation**: The Rust binary is compiled locally for `x86_64-unknown-linux-gnu` via standard Cargo.
2. **Remote Synthesis**: The binary is `scp`'d to a GCP Confidential Build VM (`build-vm-paypal-n2d`), where `build-initramfs-tools.sh` and `build-gcp-gpt-image.sh` are executed. This ensures the correct `shimx64.efi` and `linux-image-gcp` packages from the target OS are utilized in the GPT image.
3. **Deployment**: The resulting `disk.tar.gz` is retrieved locally and deployed via standard `gcloud` logic over the user's local credentials to ensure IAM permissions for GCS upload are valid.


## Architecture Details
- **Base OS**: Ubuntu 25.10 (Plucky Puffin) components.
- **Kernel**: `linux-image-gcp` (supporting GVNIC + SEV-SNP)
- **Initramfs Engine**: Standard `mkinitramfs` utilizing `copy_exec` directly into `DESTDIR/init`. We eliminated the entire post-processing unmkrd extraction block because the hook places the `paypal-auth-vm` binary natively. 
- **Dependencies**: Uses `nix` and `libc` directly from Cargo to wrap Linux syscalls. Uses standard `iproute2` for network settings.

## Security Guidelines for Future Developers
- **Reproducibility is Mandatory**: Ensure any changes to the hook or build scripts maintain bitwise identity.
- **Secrets Management**: No secrets on disk; RAM-only via GCP Metadata server.
- **Next Steps**:
  - Hook into `axum` routing for the precise OAuth callback URL endpoints.
  - Test unsealing dynamic Secret Manager data securely utilizing the properly mounted `tpm2_unseal` binary during the early Tokio phases.
