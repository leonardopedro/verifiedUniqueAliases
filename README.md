# GCP Confidential Auth VM — Reproducible & Attested

Hardware-attested PayPal OAuth service on **GCP Confidential VM** (AMD SEV-SNP).
Built for 100% bit-by-bit reproducibility and maximum security.

---
## 🚀 Current Status (v69)

| Component | Status |
|---|---|
| Bitwise Reproducibility (`disk.raw`, `disk.tar.gz`, `qcow2`) | ✅ Achieved |
| Native PID 1 Rust Integration | ✅ Achieved |
| Identity-Enriched Remote Attestation (JSON) | ✅ Achieved (v69) |
| Asymmetric Enclave Signing (RSA-4096) | ✅ Achieved (v69) |
| TPM-Sealed TLS Cache Persistence | ✅ Achieved |
| Unified PayPal OAuth Flow (Full & Verified) | ✅ Achieved |
| Automated EAB Key Rotation | ✅ Achieved |
| End-to-End Automated Deployment | ✅ Achieved |

### Architectural Breakthrough: Native PID 1 Rust Integration
The service takes complete control of the OS from the very first instruction. It runs perfectly isolated on GCP Confidential VM without any classic `/sbin/init` or shell requirements:
- **No `systemd` or standard shell scripts**: Control is handed from the bootloader directly to our Rust binary.
- **Bootstrapping**: Rust uses the `nix` crate to natively mount `/proc`, `/sys`, and `/dev`.
- **Drivers**: Performs `modprobe` for the `gve` (GCP Virtual Ethernet) and `virtio_net` drivers.
- **Network Stack**: Performs a complete DHCP exchange via raw UDP sockets.
- **Hardened Attestation**:
  - **Identity Binding**: The identity of the authenticated user (PayPal) is cryptographically bound to the server instance via a compound signed report.
  - **Asymmetric Signature**: Reports are signed by an enclave-specific RSA-4096 key (Vault-stored or auto-generated at boot).
  - **Hardware Quote**: Includes a real-time vTPM Quote (PCR 15) ensuring the integrity of the binary state.
- **Native Logging**: Writes diagnostics directly to `/dev/kmsg` for persistent GCP Serial Console visibility.

---

## 🏗️ Build Architecture & Workflow

The project uses a fully containerized, reproducible synthesis pipeline.

### 1. Unified Containerized Build
The entire OS synthesis—including the Rust binary compilation, initramfs generation, and GPT disk construction—is performed inside a multi-stage Docker environment. 

```bash
# Build the disk image entirely within Docker
docker build -f Dockerfile.repro -t paypal-auth-vm-repro .

# Extract the reproducible artifact
docker create --name tmp_disk paypal-auth-vm-repro
docker cp tmp_disk:/disk.tar.gz ./disk.tar.gz
docker rm tmp_disk
```

### 2. Automated Deployment: `deploy-gcp.sh`
The `deploy-gcp.sh` script automates the full lifecycle:
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
| `src/main.rs` | Core Rust logic (PID 1 handler + Axum web logic + TPM operations + Signing) |
| `deploy-gcp.sh` | End-to-end deployment automation (Build -> Upload -> Launch) |
| `hooks/paypal-auth` | `initramfs-tools` hook that bundles the Rust app as `/init` |
| `Dockerfile.repro` | Multi-stage build for 100% bitwise-reproducible disk images |
| `build-gcp-gpt-image.sh` | Deterministic GPT disk synthesis (Normalization pipeline) |
| `AGENTS.md` | Detailed implementation state and security architecture guidelines |