# GCP Confidential Auth VM — Reproducible & Attested

Hardware-attested PayPal OAuth service on **GCP Confidential Space** (AMD SEV-SNP).
Built for 100% bit-by-bit reproducibility and maximum security.

---
## 🚀 Current Status (v60)

| Component | Status |
|---|---|
| Bitwise Reproducibility (`disk.raw`, `disk.tar.gz`, `qcow2`) | ✅ Achieved |
| Native PID 1 Rust Integration | ✅ Achieved |
| Glibc-based Runtime stability | ✅ Achieved |
| Hardened Attestation (TPM Resource Management) | ✅ Achieved |
| TPM-Sealed TLS Cache Persistence | ✅ Achieved |
| PayPal OAuth Sandbox Flow | ✅ Achieved |
| End-to-End Automated Deployment | ✅ Achieved (v60) |

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

The project has moved from a hybrid manual build to a fully containerized, reproducible synthesis pipeline.

### 1. Unified Containerized Build (Recommended)
The entire OS synthesis—including the Rust binary compilation, initramfs generation, and GPT disk construction—is performed inside a multi-stage Docker environment. This ensures that the resulting `disk.tar.gz` is bitwise identical regardless of the host OS.

```bash
# Build the disk image entirely within Docker
docker build -f Dockerfile.repro -t paypal-auth-vm-repro .

# Extract the reproducible artifact
docker create --name tmp_disk paypal-auth-vm-repro
docker cp tmp_disk:/disk.tar.gz ./disk.tar.gz
docker rm tmp_disk
```

### 2. Automated Deployment: `deploy-gcp.sh`
The `deploy-gcp.sh` script automates the full lifecycle for v60+:
1.  **Local Build**: Invokes the `Dockerfile.repro` pipeline.
2.  **Cloud Upload**: Transfers the bit-perfect `disk.tar.gz` to Google Cloud Storage.
3.  **Image Registration**: Creates a custom GCP image with `SEV_SNP_CAPABLE` and `GVNIC` flags.
4.  **Enclave Launch**: Provisions the Confidential N2D instance with the correct TPM metadata and sealed secret bindings.

```bash
./deploy-gcp.sh
```

---

## 📂 Repository Structure

| File | Purpose |
|---|---|
| `src/main.rs` | Core Rust logic (PID 1 handler + Axum web logic + TPM operations) |
| `deploy-gcp.sh` | **(v60)** End-to-end deployment automation (Build -> Upload -> Launch) |
| `hooks/paypal-auth` | `initramfs-tools` hook that bundles the Rust app as `/init` |
| `Dockerfile.repro` | **(v60)** Multi-stage build for 100% bitwise-reproducible disk images |
| `build-gcp-gpt-image.sh` | Deterministic GPT disk synthesis (Normalization pipeline) |
| `build-initramfs-tools.sh` | Initramfs synthesis using native Debian/Ubuntu tooling |
| `AGENTS.md` | Detailed implementation state and security architecture guidelines |