# GCP Confidential Auth VM — Reproducible & Attested

Hardware-attested PayPal OAuth service on **GCP Confidential Space** (AMD SEV-SNP).
Built for 100% bit-by-bit reproducibility and maximum security.

---
## 🚀 Current Status (v59-final)

| Component | Status |
|---|---|
| Bitwise Reproducibility (`disk.raw`, `disk.tar.gz`, `qcow2`) | ✅ Achieved |
| Native PID 1 Rust Integration | ✅ Achieved |
| Glibc-based Runtime stability | ✅ Achieved |
| Hardened Attestation (TPM Resource Management) | ✅ Achieved |
| TPM-Sealed TLS Cache Persistence | ✅ Achieved |
| PayPal OAuth Sandbox Flow | ✅ Achieved |

### Architectural Breakthrough: Native PID 1 Rust Integration
The service takes complete control of the OS from the very first instruction. It runs perfectly isolated on GCP Confidential Space without any classic `/sbin/init` or shell requirements:
- **No `systemd` or standard shell scripts**: Control is handed from the bootloader directly to our Rust binary.
- **Bootstrapping**: Rust uses the `nix` crate to natively mount `/proc`, `/sys`, and `/dev`.
- **Drivers**: Performs `modprobe` for the `gve` (GCP Virtual Ethernet) and `virtio_net` drivers.
- **Network Stack**: Performs a complete DHCP exchange via raw UDP sockets, applying the lease via `iproute2` (`ip` command).
- **Hardened Attestation**:
  - **Resource Management**: Communicates via `/dev/tpmrm0` (Kernel resource manager) to prevent transient object leaks and handle exhaustion.
  - **Dynamic AK Provisioning**: Automatically provisions a dedicated Attestation Key (AK) with `sign|fixedtpm` attributes for hardware-rooted signing of TPM Quotes.
- **Native Logging**: Writes diagnostics directly to `/dev/kmsg` for persistent GCP Serial Console visibility.

### Glibc Transition (v59)
Initially planned as `musl` static, the project successfully transitioned to `glibc` to support broader dynamic library requirements while maintaining a minimal footprint. The `initramfs-tools` hook handles the deterministic mapping of shared objects to the rootfs.

---

## 🏗️ Build Architecture & Workflow

To maintain exact EFI/Kernel Secure Boot signatures matching GCP infrastructure, the build process is split:

1. **Phase 1: Local Docker Build**: The Rust binary is compiled inside a controlled Docker environment (`Dockerfile.build-rust`) targeting `x86_64-unknown-linux-gnu`.
2. **Phase 2: Remote Synthesis**: The binary is `scp`'d to a GCP build VM (`build-vm-paypal-n2d`) where `build-initramfs-tools.sh` and `build-gcp-gpt-image.sh` are executed. This ensures the correct `shimx64.efi`, `grubx64.efi` and kernel are utilized for the GPT image.

### Build Commands:
```bash
# 1. Build and extract binary
docker build -f Dockerfile.build-rust -t paypal-auth-vm-builder .
docker create --name tmp_bin paypal-auth-vm-builder
docker cp tmp_bin:/paypal-auth-vm-bin ./paypal-auth-vm-bin-local
docker rm tmp_bin

# 2. Upload and Remote Build
gcloud compute scp paypal-auth-vm-bin-local build-vm-paypal-n2d:~/paypal-auth-vm-bin
gcloud compute scp build-initramfs-tools.sh build-gcp-gpt-image.sh build-vm-paypal-n2d:~/
gcloud compute ssh build-vm-paypal-n2d --command="sudo ./build-initramfs-tools.sh && sudo ./build-gcp-gpt-image.sh"
```

## 📂 Repository Structure

| File | Purpose |
|---|---|
| `src/main.rs` | Core Rust logic (PID 1 handler + Axum web logic + TPM operations) |
| `hooks/paypal-auth` | `initramfs-tools` hook that bundles the Rust app as `/init` |
| `Dockerfile.build-rust` | Reproducible glibc-based Rust build environment |
| `build-gcp-gpt-image.sh` | Deterministic GPT disk synthesis (Normalization pipeline) |
| `build-initramfs-tools.sh` | Initramfs synthesis using native Ubuntu tooling |
| `AGENTS.md` | Detailed implementation state, hardware-rooting details, and GCP image registration + VM launch |