[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/leonardopedro/verifiedUniqueAliases)

# GCP Confidential Auth VM — Reproducible & Attested

Hardware-attested PayPal OAuth service on **GCP Confidential VM** (AMD SEV-SNP).
Built for 100% bit-by-bit reproducibility and maximum security.

---
## 🚀 Current Status (v118-PROD)

| Component | Status |
|---|---|
| **TPM-Bound TLS Private Key** | ✅ Hardened (v118) |
| **Decentralized Hub & Static Frontend** | ✅ Achieved (v116) |
| **Custom Attestation Nonce Injection** | ✅ Achieved (v116) |
| **Kernel Egress Firewalling (nftables)** | ✅ Achieved (v116) |
| **Silicon Root of Trust (AMD SEV-SNP)** | ✅ Achieved (v115) |
| **Atomic Image Verification (GitHub Sigstore)** | ✅ Achieved (v115) |
| **Whole-Disk Manifest Audit (100% Volume Hash)** | ✅ Achieved (v115) |
| **Enclave Identity Signature (Alphabetical Determinisim)**| ✅ Resolved (v115) |
| Bitwise Reproducibility (Local vs GitHub Actions) | ✅ Achieved |
| Native PID 1 Rust Integration | ✅ Achieved |
| Hardened Resource Boundaries | ✅ Achieved |
| Compact JSON Remote Attestation (RFC 8785) | ✅ Achieved |
| TPM-Sealed TLS Cache Persistence | ✅ Achieved |
| Automated Key & EAB Credential Provisioning | ✅ Achieved |

### Architectural Breakthrough: Silicon-to-App Verifiable Chain
The service now provides a continuous, cryptographically-anchored chain of trust that starts at the physical AMD CPU and extends to the application logic:
- **Decentralized Transparency (v116)**: Web Auditor and legal policies decoupled from the enclave and hosted natively on GitHub Pages to eliminate web-vector attack surfaces.
- **Custom Hardware Binding (v116)**: Supports 2-phase secure session processing allowing users to inject a custom, cryptographically-bound nonce strictly mapped to their verified PayPal identity.
- **Kernel-Level Dropping (v116)**: Zero-trust `nftables` baseline directly in `PID 1` guaranteeing network isolation beyond VPC semantics.
- **Silicon Anchor (v74)**: Direct hardware **SNP Attestation Reports** provide a launch measurement of the firmware (OVMF), ensuring the root of trust is exclusively the AMD hardware, independent of GCP or the hypervisor.
- **Image Atomicity (v74)**: Every executable component (Binary, Kernel, Initrd, Bootloader) is individually attested via GitHub Sigstore. The auditor (`verify.html`) ensures all components share the same **GitHub Run ID**, proving they come from a single, atomic build session.
- **Total Disk Audit (v115)**: The enclave performs a recursive SHA-256 scan of the entire boot partition. This **Disk Manifest** is included in the hardware-signed report, guaranteeing that not a single byte of configuration (`grub.cfg`) or code was altered on the disk image.
- **Alphabetical Determinism (v115)**: Resolved cross-platform JSON serialization discrepancies (V8 vs Rust) by implementing strictly alphabetical `BTreeMap` structures and string-prefixed PCR keys (`pcr_0`, `pcr_15`, etc.), ensuring the Enclave Identity Signature verifies 100% of the time.
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

---

## 🛠️ Verification Workflow (Recommended)
For maximum security, do not trust the hosted web auditor. Verify the enclave locally:

1. **Download the Report**: After a successful PayPal login, click **"Download Report (.json)"** on the attestation page.
2. **Download the Auditor**: Click **"Download Auditor (.html)"** to get a local copy of the `verify.html` tool.
3. **Capture TLS Evidence**: 
   - Use `openssl` to capture the server's public certificate:
   ```bash
   echo | openssl s_client -connect login.airma.de:443 -showcerts | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > cert.pem
   ```
4. **Run Local Audit**:
   - Open your local `verify.html` in a web browser.
   - Upload the `attestation_report.json`.
   - Upload the `cert.pem`.
   - Click **"Perform Cryptographic Audit"**.
   - Verify all green checks: Identity, TPM, Silicon, GitHub, and TLS Binding.