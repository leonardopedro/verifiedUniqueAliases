[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/leonardopedro/verifiedUniqueAliases)

# GCP Confidential Auth VM — Reproducible & Attested

Hardware-attested PayPal OAuth service on **GCP Confidential VM** (AMD SEV-SNP).
Built for 100% bit-by-bit reproducibility and maximum security.

---
## 🚀 Current Status (v119-FIXED)

| Component | Status |
|---|---|
| **Base OS (Debian 13 Trixie)** | ✅ Migrated (v119) |
| **TPM Quote Hardware Binding** | ✅ Hardened (v119-FIXED) |
| **PCR 15 Software Manifest Binding**| ✅ Restored (v119-FIXED) |
| **Pinned TLS Egress & Time Sync** | ✅ Hardened (v119-FIXED) |
| **Set-Intersection Image Atomicity** | ✅ Achieved (v119) |
| **GCP Silicon Root Fallback (AK Cert)** | ✅ Achieved (v119) |
| **TPM-Bound TLS Private Key** | ✅ Hardened (v118) |
| **Decentralized Hub & Static Frontend** | ✅ Achieved (v116) |

### Architectural Breakthrough: v119-FIXED Hardening
The service has reached a production-hardened state with the elimination of critical hypervisor-level vulnerabilities:
- **Hardened TPM Verification (v119-FIXED)**: Implemented full binary parsing of the hardware-signed `TPMS_ATTEST` structure in the auditor. This ensures the attestation nonce is cryptographically bound to the hardware silicon, neutralizing session replay and report forgery attacks.
- **PCR 15 Manifest Binding (v119-FIXED)**: Restored the cryptographic link between the hardware state and the software manifest. The auditor now strictly verifies that the 100% volume hash matches the hardware-signed PCR 15 value.
- **Egress Hardening & Secure Time (v119-FIXED)**: Eliminated hypervisor-controlled metadata environment injection. Time synchronization and secret retrieval are now performed over pinned TLS connections (hardened client), neutralizing hypervisor-level time-rollback and Man-in-the-Middle attacks.
- **Debian Trixie (v119)**: Transitioned to the latest stable Debian architecture for enhanced hardware support and long-term reproducibility using pinned snapshots.

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