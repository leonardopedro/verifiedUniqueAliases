[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/leonardopedro/verifiedUniqueAliases)

# GCP Confidential Auth VM — Reproducible & Attested

Hardware-attested PayPal OAuth service on **GCP Confidential VM** (AMD SEV-SNP).
Built for 100% bit-by-bit reproducibility and a mathematically unbroken chain of trust from AMD silicon to GitHub provenance.

**Live endpoint**: `https://login.airma.de`

---

## 🚀 Current Status (v145)

| Component | Status |
|---|---|
| **Base OS (Debian 13 Trixie, pinned snapshot)** | ✅ Stable |
| **Binary TPM `TPMS_ATTEST` Parsing** | ✅ Fully Verified |
| **PCR Composite Digest Verification** | ✅ Fully Verified |
| **PCR 15 Software Manifest Binding** | ✅ Fully Verified |
| **Google EK Certificate (NVRAM, 1560 bytes)** | ✅ Fully Retrieved |
| **Silicon Anchor: EK Cert Issuer Verification** | ✅ Fully Verified |
| **Embedded TLS Pinning (no filesystem trust)** | ✅ Hardened |
| **Pinned HTTPS Time Sync + RTC Pre-seed** | ✅ Hardened |
| **Atomic Reproducible Build** | ✅ Achieved |
| **GitHub Sigstore Supply Chain Provenance** | ✅ Achieved |

### v145 — GCP vTPM Two-Key Architecture

All cryptographic audit checks pass end-to-end in `verify.html`:

1. **✅ Enclave Identity Signature** — RSA-4096 signature over canonicalized JSON report
2. **✅ PayPal Identity Binding** — Session nonce = `SHA-256(user_hash ∥ pubkey_hash)`
3. **✅ TPM Hardware Proof** — Binary `TPMS_ATTEST` parsed; session AK signature, nonce, and PCR composite hash all verified
4. **✅ Silicon Root of Trust** — Google EK Certificate retrieved from NVRAM `0x01c00002`; issuer verified as `EK/AK CA Intermediate` under Google's CA hierarchy; instance identity decoded from subject fields
5. **✅ GitHub Build Provenance** — Sigstore attestation confirms binary + image atomicity + PCR 15 binding
6. **✅ TLS Certificate Binding** — Optional: confirms browser connection matches signed report

---

## 🔐 Cryptographic Chain of Trust

```
GitHub Sigstore Provenance
    └─► disk_manifest SHA-256
            └─► PCR 15 (measured at boot into hardware TPM)
                    └─► PCR Composite Hash (SHA-256 of PCRs 0,4,8,9,15)
                            └─► TPMS_ATTEST (Session AK-signed: PCR composite + session nonce)
                                    └─► Session Nonce
                                            └─► PayPal Identity + Enclave Public Key

Google EK Certificate (NVRAM 0x01c00002, Google-signed, permanent)
    └─► Proves: this is a real GCP Confidential VM running AMD SEV-SNP silicon
```

> **Key insight**: The Google EK Certificate and the TPM Quote signing key (session AK) are **two separate keys**. The EK cert proves *hardware identity*; the session AK proves *measurement integrity* for this specific session. This is the correct TPM 2.0 attestation model.

---

## 🏗️ Build & Verifiability Workflow

### 1. Atomic Reproducible Build
The entire stack is built in a deterministic multi-stage Docker pipeline producing a bit-perfect `disk.tar.gz` that matches GitHub Actions provenance.

```bash
docker build -f Dockerfile.repro -t paypal-auth-vm-repro .
```

### 2. Full Deployment
```bash
bash deploy-gcp.sh
```
This script: rotates EAB keys → builds the image locally → uploads to GCS → registers GCP custom image → tears down old VM → provisions new SEV-SNP Confidential VM.

### 3. High-Fidelity Audit: `verify.html`

The browser-based auditor performs a 6-stage cryptographic validation entirely in-browser using WebCrypto — no server trust required.

**Recommended: local air-gapped verification**

```bash
# 1. Capture TLS certificate from the live endpoint
echo | openssl s_client -connect login.airma.de:443 -showcerts \
  | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > cert.pem

# 2. After PayPal login, download the attestation report from the callback page

# 3. Open verify.html locally, upload report + cert, click Audit
```

---

## 📂 Repository Structure

| File | Purpose |
|---|---|
| `src/main.rs` | Rust PID 1: DHCP, TPM attestation, ACME TLS, PayPal OAuth, report signing |
| `src/google_ca.pem` | Embedded Google Root CA (compiled into binary via `include_bytes!`) |
| `src/paypal.pem` | Embedded PayPal Root CA (compiled into binary via `include_bytes!`) |
| `verify.html` | Browser auditor: binary TPM parser, DER cert decoder, WebCrypto, GitHub API |
| `deploy-gcp.sh` | End-to-end deployment (EAB rotation → build → GCS → GCP VM) |
| `Dockerfile.repro` | Multi-stage reproducible build (Debian Trixie pinned snapshots) |
| `build-initramfs-tools.sh` | Initramfs construction with kernel module selection |
| `build-gcp-gpt-image.sh` | GPT disk image assembly (ESP + GRUB + measured boot) |
| `.github/workflows/` | Sigstore provenance attestation for all build artifacts |
| `AGENTS.md` | Security architecture, chain of trust, known constraints, and implementation notes |

---

## 🛡️ Security Architecture Highlights

- **PID 1 Isolation**: The Rust binary is the only process. No shell, no cron, no systemd. All whitelisted binaries (TPM tools, `nft`, `ip`) are statically resolved at build time.
- **Embedded TLS Roots**: `google_ca.pem` and `paypal.pem` compiled directly into the binary with `include_bytes!`. No filesystem CA store is trusted.
- **Kernel Egress Firewall**: `nftables` ruleset loaded at boot; only DNS (53), metadata (169.254.169.254), and HTTPS (443) egress permitted.
- **TPM-Sealed DEK**: A random Data Encryption Key is sealed to PCR policy (0,4,8,9,15) using the owner-hierarchy primary. Any modification to measured boot components breaks the seal.
- **One-Shot Attestation**: Each attestation report is signed with a freshly-generated RSA-4096 key (loaded from GCP Secret Manager). The nonce cryptographically binds the report to one specific PayPal session.
- **Two-Key Silicon Anchor**: The hardware identity (Google EK Certificate, permanent, NVRAM) is decoupled from the session signing key (session AK, ephemeral, created per-attestation). Neither key alone is sufficient; both are required to pass the audit.

---

## 🔍 Verification Output (expected green state)

```
✅ Enclave Identity Signature   — Report signature verified.
✅ PayPal Identity Binding      — Identity cryptographically hashed.
✅ TPM Hardware Proof           — TPM Quote, Nonce, and PCR Digest verified.
✅ Silicon Root of Trust        — Google Confidential Hardware Verified
                                   EK Cert Issuer: EK/AK CA Intermediate (Google LLC)
                                   Hardware Identity: europe-west4-a · paypal-auth-vm-v60
✅ GitHub Build Provenance      — Binary + Image Atomicity + PCR 15 hardware binding
✅ TLS Certificate Binding      — TLS channel bound.
```