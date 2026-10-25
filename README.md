# Alibaba Cloud Confidential Auth VM — Reproducible & Attested

Hardware-attested PayPal OAuth service on **Alibaba Cloud ECS** (Intel TDX confidential compute).
Built for bit-by-bit reproducibility and an unbroken chain of trust from **Intel silicon** to **GitHub CI provenance**, then audited **in your browser** — no server trust required.

**Live endpoint**: `https://login.airma.de`

---

## 🚀 Current Status (v181)

| Component | Status |
|---|---|
| **Base OS (Debian 13 Trixie, pinned snapshot)** | ✅ Stable |
| **Intel TDX hardware quote (PCK chain → Intel SGX Root CA)** | ✅ Fully Verified |
| **MRTD + RTMR0–3 golden silicon pins** | ✅ Hard gates (fail-closed) |
| **SEC-02 session nonce (5-component, 160-byte binding)** | ✅ Fully Verified |
| **Client-session binding (both `report_data` slots, every audit mode)** | ✅ No wildcard slots (v182) |
| **E2EE report blob (sealed to your browser's throwaway key)** | ✅ One-time vault claim, 600 s TTL |
| **Auditor isolation (enclave-origin copy refuses keys)** | ✅ Web Auditor Tampering defense |
| **Embedded TLS Pinning (`src/paypal.pem`, no filesystem trust)** | ✅ Hardened |
| **Atomic Reproducible Build (Docker/CI pipeline only)** | ✅ Achieved |
| **GitHub Sigstore Supply Chain Provenance** | ✅ Achieved |

The former GCP (AMD SEV-SNP / vTPM) and Oracle paths were **permanently deleted** in v180
(audit.md §3.1): Intel TDX is compiled unconditionally, and the multi-cloud quote
dispatch is gone — a report with no hardware-signed Intel TDX quote is rejected
outright (cross-cloud quote substitution closed at the first gate).

---

## 🔐 Cryptographic Chain of Trust

```
GitHub Actions CI attestation (Sigstore, per-commit)
    └─► independent golden MRTD/RTMR0–3 pins (computed in CI, not by the enclave)
            └─► Intel-signed TD Quote (ECDSA P-256 over header+TDREPORT;
                attestation key bound into the QE report; QE report signed
                by the PCK leaf → chain to the PINNED Intel SGX Root CA)
                    └─► REPORTDATA[0..32] = SEC-02 session nonce
                        (SHA-256 over [paypal_identity ∥ P_enc ∥ custom_info
                         ∥ binary_sha256 ∥ canonical-manifest_hash])
                    └─► REPORTDATA[32..64] = SHA-256(P_client ∥ Nonce_client)
                        (client-session binding — enforced in EVERY audit mode)
                            └─► report signed by the enclave's RSA-2048 key (S_enc)
                                    └─► report sealed end-to-end (ECDH+AES-GCM)
                                        to the throwaway key born in YOUR browser
```

> **Key insight**: an Intel-signed quote proves *silicon*; the golden MRTD/RTMR pins prove
> the silicon launched *the audited boot chain*; the two `report_data` slots bind the quote
> to *this PayPal session* and *this browser's* client key. Self-reported fields
> (e.g. `boot.binary_sha256`) never gate anything — code identity is decided exclusively
> by the silicon pins over the hardware quote.

---

## 🏗️ Build & Verifiability Workflow

### 1. The only ATTESTED build is the Docker/CI pipeline

A plain host build (`cargo build --release`, e.g. under Nix) is **not** bit-identical to
the pipeline build and is never attested — deploy only Docker-built disks:

```bash
bash build-alibaba-docker.sh    # rootless podman works; reproduces CI bit-for-bit
```

### 2. Import & deploy

```bash
bash import-alibaba-image.sh     # OSS upload → ImportImage (NVMe-flagged)
bash deploy-alibaba.sh           # ecs.c9i.* spot, cn-beijing, config via user_data/IMDS
```

### 3. High-Fidelity Audit: `verify.html`

The browser-based auditor performs a multi-stage cryptographic validation entirely
in-browser using WebCrypto — no server trust required.

**Recommended: local air-gapped verification**

```bash
# 1. Save verify.html from this repository (NOT from login.airma.de — that copy
#    is untrusted by design and refuses key generation)
# 2. Open it via file://, enter https://login.airma.de, run the secure login
# 3. The report decrypts, audits and downloads in YOUR browser; audit it
#    offline in any copy afterwards
```

#### Verify the auditor itself first (out-of-band digest)

`verify.html` is the only thing between you and a tampered enclave, so it must
not be trusted on faith either. Its digest is published **here**, separate from
the file it describes:

| Artifact | Size | SHA-256 |
|---|---|---|
| `verify.html` | 163,208 bytes | `3030363a14046bc214336fd042b6e5297a6372e0025d88f28eaf57a3b892e5eb` |

```bash
sha256sum verify.html
# 3030363a14046bc214336fd042b6e5297a6372e0025d88f28eaf57a3b892e5eb  verify.html
```

- Rotate this hash in the **same reviewed commit** that changes `verify.html`;
  `node scripts/test-verify-security.mjs` fails when the README and the file
  disagree (Test 28), so a stale digest cannot be published silently.
- Compare against a second source when you can (release note, mirror, another
  checkout): this README lives in the same repository whose owner the threat
  model distrusts, so one source alone is a weak anchor.
- The copy served by the enclave itself (`https://login.airma.de/verify.html`)
  is untrusted by design — it refuses every key-generating flow (auditor
  isolation), so a tampered ESP copy cannot steal your keys. It also cannot
  prove anything: check the digest of the file you actually run.

---

## 📂 Repository Structure

| File | Purpose |
|---|---|
| `src/main.rs` | Rust PID 1: DHCP, Intel TDX attestation, ACME TLS, PayPal OAuth, E2EE vault, report signing |
| `src/intel_tdx.rs` | TDX evidence acquisition: DCAP quote, CCEL replay, PCK/TCB handling |
| `src/paypal.pem` | Embedded TLS trust root for the pinned PayPal API endpoints — **DigiCert Global Root G2** (SHA-256 `cb3ccbb7…ab1cb5f`, fingerprint pinned by test `paypal_api_root_is_digicert_g2_v179`) |
| `verify.html` | Browser auditor: TD Quote parser, PCK chain walk to the pinned Intel root, WebCrypto, GitHub attestation lookup |
| `build-alibaba-docker.sh` | The reproducible build (Debian Trixie pinned snapshots) |
| `build-initramfs-tools.sh` | Initramfs construction with kernel module selection |
| `build-alibaba-disk.sh` | **Retired (hard-fail stub)** — legacy non-bootable artifact; use `build-alibaba-docker.sh` |
| `import-alibaba-image.sh` / `deploy-alibaba.sh` | Image import and instance deployment (cn-beijing) |
| `.github/workflows/build-attest.yml` | Sigstore provenance + independent MRTD/RTMR golden pins |
| `scripts/` | Security harness (`test-verify-security.mjs`), E2E flows, golden-RTMR tooling |
| `AGENTS.md` · `audit.md` · `plan.md` · `HANDOVER.md` | Security architecture, audit trail, handover notes |

---

## 🛡️ Security Architecture Highlights

- **PID 1 Isolation**: The Rust binary is the only process. No shell, no cron, no systemd. All whitelisted binaries (`tpm2`, `nft`, `ip`) are statically resolved at build time.
- **Embedded TLS Root**: `paypal.pem` is compiled directly into the binary with `include_bytes!` and pinned at the transport layer. No filesystem CA store is trusted.
- **Kernel Egress Firewall**: `nftables` ruleset loaded at boot; only DNS (53), the Alibaba IMDS (`100.100.100.200:80`), ACME (80/443) and HTTPS (443) egress permitted; per-IP and global bandwidth budgets enforced in-process.
- **Fail-closed minting**: no silicon-signed TD Quote → HTTP 503, no report is ever emitted.
- **No pre-login quote** (v180): `/attest/login-session` is pure signed bookkeeping — a hardware quote is minted only *after* a PayPal-verified code exchange, so the attacker filter is the completed login itself.
- **E2EE report handoff**: the report is sealed (ECDH P-256 + AES-128-GCM) to a throwaway key that is born in and never leaves your trusted browser copy; the enclave's vault serves it **once**, to the matching claim hash, with a 600 s TTL.
- **Auditor isolation**: key generation, login and decryption run only on `file://` or the pinned GitHub Pages copy — the enclave-origin copy refuses all key-generating flows (Web Auditor Tampering defense).

---

## 🔍 Verification Output (expected green state)

```
✅ Intel TDX Silicon Root Verified
   Quote signature ECDSA P-256/SHA-256 valid · attestation key bound into the QE report
   PCK chain: … certs, leaf → Intel SGX Root CA pinned (44a0196b…)
   report_data == session nonce ∥ client-session binding — both slots bound ✓
   MRTD … pinned ✓ · RTMR0–3 hard pins … ✓ — running-code measurements match the audited golden build
✅ Enclave Identity Signature   — Report signature verified.
✅ PayPal Identity Binding      — Identity cryptographically hashed and environment-pinned (production).
✅ GitHub Build Provenance      — Binary + disk attested; silicon pins decide code identity.
✅ TLS Certificate Binding      — TLS channel bound.
```
