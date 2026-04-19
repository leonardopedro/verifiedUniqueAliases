# GCP Confidential Auth VM — Reproducible & Attested

Hardware-attested PayPal OAuth service on **GCP Confidential VM** (AMD SEV-SNP).
Built for 100% bit-by-bit reproducibility and maximum security.

---
## 🚀 Current Status (v74)

| Component | Status |
|---|---|
| **Silicon Root of Trust (AMD SEV-SNP)** | ✅ Achieved (v74) |
| **Atomic Image Verification (GitHub Sigstore)** | ✅ Achieved (v74) |
| **Whole-Disk Manifest Audit (100% Volume Hash)** | ✅ Achieved (v74) |
| Bitwise Reproducibility (Local vs GitHub Actions) | ✅ Achieved |
| Native PID 1 Rust Integration | ✅ Achieved |
| Hardened Resource Boundaries | ✅ Achieved |
| Compact JSON Remote Attestation (RFC 8785) | ✅ Achieved |
| TPM-Sealed TLS Cache Persistence | ✅ Achieved |
| Automated Key & EAB Credential Provisioning | ✅ Achieved |

### Architectural Breakthrough: Silicon-to-App Verifiable Chain
The service now provides a continuous, cryptographically-anchored chain of trust that starts at the physical AMD CPU and extends to the application logic:
- **Silicon Anchor (v74)**: Direct hardware **SNP Attestation Reports** provide a launch measurement of the firmware (OVMF), ensuring the root of trust is exclusively the AMD hardware, independent of GCP or the hypervisor.
- **Image Atomicity (v74)**: Every executable component (Binary, Kernel, Initrd, Bootloader) is individually attested via GitHub Sigstore. The auditor (`verify.html`) ensures all components share the same **GitHub Run ID**, proving they come from a single, atomic build session.
- **Total Disk Audit (v74)**: The enclave performs a recursive SHA-256 scan of the entire boot partition. This **Disk Manifest** is included in the hardware-signed report, guaranteeing that not a single byte of configuration (`grub.cfg`) or code was altered on the disk image.
- **Resource Hardening**: Includes 50-connection concurrency limits, 512MB/hour egress caps, and DDoS-resistant IP tracking.
- **Native PID 1 Rust**: Hand-off directly from BIOS to Rust. No `systemd`, no shell, no userspace bloat.

---

## 🏗️ Build & Verifiability Workflow
The workflow is designed for "Audit First" security.

### 1. Atomic Reproducible Build
The entire stack is built in a deterministic multi-stage Docker pipeline. The output is a bit-perfect `disk.tar.gz` that matches the GitHub Actions provenance.

```bash
# Build and verify local reproducibility
podman build -f Dockerfile.repro -t paypal-auth-vm .
```

### 2. High-Fidelity Audit: `verify.html`
The browser-based Auditor performs a 4-stage validation:
1. **Signature Check**: Validates the enclave's RSA-4096 signature via Web Crypto.
2. **Silicon Check**: Parsons the AMD SNP hardware report to verify the **Firmware Measurement**.
3. **Supply Chain Check**: Queries GitHub for Sigstore attestations and confirms **Image Atomicity** (Run ID match).
4. **Hardware Bind**: Confirms the TPM PCR state (0, 4, 8, 9, 15) matches the verified software components.

---

## 📂 Repository Structure

| File | Purpose |
|---|---|
| `src/main.rs` | Core Rust logic (PID 1 handler + SNP Audit + Resource Guarding) |
| `verify.html` | Browser-based Multi-Stage Auditor (Github API + WebCrypto + SNP Parser) |
| `deploy-gcp.sh` | End-to-end deployment automation (Key Provisioning -> Build -> Launch) |
| `.github/workflows/build-attest.yml` | Atomic Supply Chain Attestation (Sigstore provenance for all artifacts) |
| `Dockerfile.repro` | Multi-stage build for 100% bitwise-reproducible disk images |
| `AGENTS.md` | Detailed implementation state and security architecture guidelines |