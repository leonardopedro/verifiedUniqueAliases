[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/leonardopedro/verifiedUniqueAliases)

# Confidential Auth VM — Reproducible & Attested (GCP + Oracle Cloud)

Hardware-attested PayPal OAuth service on **confidential compute** — a single codebase targeting two AMD SEV-SNP platforms:

| Target | Shape | Root of Trust | Build flag |
|---|---|---|---|
| GCP Confidential VM | n2d (vTPM) | Google EK Cert + Session AK (TPM quote) | *(default)* |
| Oracle Cloud | `VM.Standard.E5.Flex` (spot) | AMD VCEK + SNP report (`/dev/sev-guest`) | `--features oci` |

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

### 2. GCP Deployment
```bash
bash upload-secrets.sh   # update PayPal credentials (GCP: Secret Manager + reset)
```
Build the image with `bash build-vm-image.sh` / `Dockerfile.repro`, register it as a GCP custom image, then provision the SEV-SNP Confidential VM.

### 3. Oracle Cloud Deployment (cheapest confidential spot VM)

```bash
# 0. Stage OL10 boot binaries from the OCI "Oracle Linux 10" platform image
#    (short-lived 1-OCPU spot instance, copied then terminated). Optional —
#    without it the build falls back to pinned NEVRAs from Oracle's yum repos.
export OCI_COMPARTMENT_ID=ocid1.compartment...
export OCI_SUBNET_ID=ocid1.subnet...
bash extract-ol10-platform.sh     # → ./ol10

# 1. Build bootable QCOW2 (docker or rootless podman)
bash build-oci-docker.sh          # → paypal-auth-vm-oci.qcow2

# 2. Import as OCI custom image (QCOW2 only; raw is rejected by the API).
#    Also attaches the image capability schema (UEFI firmware + AMD SEV/SNP) —
#    imported images have none by default and cannot launch without it.
export OCI_COMPARTMENT_ID=ocid1.compartment...
export OCI_BUCKET_NAME=paypal-auth-vm
bash import-oci-image.sh          # → prints ocid1.image... (polls until AVAILABLE)

# 3. Launch the cheapest confidential instance (defaults are already minimal)
export OCI_SUBNET_ID=ocid1.subnet...
export OCI_IMAGE_ID=ocid1.image...
export PAYPAL_CLIENT_ID=... PAYPAL_CLIENT_SECRET=... DOMAIN=your.domain.example.com
bash deploy-oci.sh

# Later credential rotation — user_data is immutable on OCI, so this
# relaunches the instance from the same image with the new config
# (verified before the old instance is terminated; public IP changes):
bash upload-secrets.sh
```

Defaults target the **cheapest possible** confidential VM:

| Knob | Default | Notes |
|---|---|---|
| Shape | `VM.Standard.E5.Flex` | `platformConfig: {type: AMD_VM, isMemoryEncryptionEnabled: true}` → SEV-SNP |
| OCPUs | `1` (`OCI_OCPUS`) | minimum |
| Memory | `1 GB` (`OCI_MEM_GB`) | minimum |
| Boot volume | `50 GB` | OCI's **hard** minimum — `--boot-volume-size-in-gbs` rejects anything below 50; thin-provisioned (our image uses < 1 GB of it) |
| Capacity | On-demand (default); `OCI_PREEMPTIBLE=true` attempts spot with automatic on-demand fallback | OCI forbids preemptible + confidential (docs: "Confidential computing" is not available with preemptible instances). Observed in FRA: `platformConfig AMD_VM` instances are rejected as preemptible on E4/E5 ("not supported for VM preemptible"), so the script retries on-demand — the cheapest *available* confidential config |

Config reaches the enclave through instance `user_data` (the OCI CLI base64-encodes `--user-data-file`); the enclave reads `/opc/v2/instance/metadata/user_data` with `Authorization: Bearer Oracle` — **no cloud-init**.

In-VM verification: `bash verify_enclave.sh` — it auto-detects the platform: strict TPM checks on GCP, and on OCI a TPM-less branch that skips EK/NVRAM/PCR 15 and instead verifies `/dev/sev-guest` + IMDS + (optionally, `EXPECTED_HOST=your.domain`) a live SNP report from `/debug/attestation`.

### 4. High-Fidelity Audit: `verify.html`

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
| `upload-secrets.sh` | Update PayPal credentials: OCI → relaunch from same image with new `user_data` (old instance kept until `/login` redirect verifies); GCP → Secret Manager + reset |
| `build-oci-docker.sh` | OCI image build (binary `--features oci` + initramfs + QCOW2) via docker/podman |
| `extract-ol10-platform.sh` | Stage OL10 boot binaries from the OCI Oracle Linux 10 platform image |
| `import-oci-image.sh` | Upload QCOW2 to Object Storage + `oci compute image import` |
| `deploy-oci.sh` | OCI launch: cheapest spot SEV-SNP VM, config via `user_data` |
| `Dockerfile.oci` | OL10/UEK8 + Debian Trixie pinned OCI build pipeline |
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