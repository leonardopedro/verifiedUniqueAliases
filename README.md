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
| `verify.html` | 265,825 bytes | `c4c7beb6bd7f3dca14c6f9249df60ef7021169fd36af390c48a7c8631758d372` |
| `zk.html` | 111,684 bytes | `1beb6b788aaf1247de6cb8951acd84b28f30fbba45fa26bc7c38de9bd457afa0` |
| `zk-rsa.html` | 100,001 bytes | `a6ef449546d42f24dfe0359411a647bf650fdff7f372cd828387f617ae0b2d40` |
| `privacy.html` | 4,673 bytes | `e570784f6d65f3af0efa99fcb0c803146a1c20b43ac6635bd30aac66d01ac7c8` |
| `terms.html` | 3,663 bytes | `9e8daa06da92308c19aa85b1cf33ee44d92be19b0daebe031eecc952002fb61f` |

```bash
sha256sum verify.html zk.html zk-rsa.html privacy.html terms.html
# c4c7beb6bd7f3dca14c6f9249df60ef7021169fd36af390c48a7c8631758d372  verify.html
# 1beb6b788aaf1247de6cb8951acd84b28f30fbba45fa26bc7c38de9bd457afa0  zk.html
# a6ef449546d42f24dfe0359411a647bf650fdff7f372cd828387f617ae0b2d40  zk-rsa.html
# e570784f6d65f3af0efa99fcb0c803146a1c20b43ac6635bd30aac66d01ac7c8  privacy.html
# 9e8daa06da92308c19aa85b1cf33ee44d92be19b0daebe031eecc952002fb61f  terms.html
```

**What the service serves (v206):** `https://login.airma.de/` is a minimal
landing only — the title, one paragraph on what this is, the two legal links
(GitHub Pages), a **Download `verify.html`** link to the repository copy, and
three short steps on what to do with it (open the saved file, log in there,
load the encrypted report back). There is no path box and no link builder on
the service: the browser owns the download location, so the page no longer asks
the visitor to type it. The enclave no
longer serves the auditor (`/` and `/verify.html` both render the landing), nor
`privacy.html`/`terms.html`, nor `zk.html`: the auditor and the ZK prover are
taken from the repository so the operator cannot rewrite them on the way out,
and the legal documents are linked, not copied. `verify.html` carries exactly
one "Legal:" line, at the top.

(`zk.html` is the standalone zero-knowledge prover — split out of
`verify.html` in v194 so the ZK layer can be debugged without rebuilding the
enclave image; a green audit in `verify.html` hands the audited identity over
to it via a pinned-origin postMessage, or you paste the report directly.
`zk-rsa.html` is the **alternative prover for RSA keys** — OpenPGP/GPG
whistleblower keys and S/MIME certificates: a zero-knowledge proof of
key possession (Guillou–Quisquater Fiat–Shamir over SHA-256, no trusted
setup, no circuit) with the identity escrowed RSA-OAEP+AES-GCM to a recipient
key — it makes zero network requests and never sees a passphrase.)

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

## 🧾 Attesting a sandbox PayPal page (prover walkthrough)

The TLSNotary proxy attested `api-m.sandbox.paypal.com` — the OAuth *API*. To
attest a page a person actually sees, commit to the sandbox **site** host:
`www.sandbox.paypal.com`. That name is in the default `relay_targets`, so no
config change is needed; enabling the service is (`"services": {"tls_proxy":
{"enabled": true}}`, see `docs/tls-proxy.md`).

Two details decide whether you get a page or a redirect:

- `sandbox.paypal.com` answers `301` to `www.sandbox.paypal.com`. One session
  attests one TLS connection and does not follow redirects, so commit to the
  `www` host to reach the page itself.
- The notary authorises a **host**, not a URL. The path is yours: point the
  prover at `/checkoutnow` and the transcript is that request and its response.

```bash
# one session against the sandbox site, path of your choosing
LIVE_NOTARY=101.200.178.251:8443 \
LIVE_SERVER=www.sandbox.paypal.com \
LIVE_PATH=/checkoutnow \
  cargo test --manifest-path tls-proxy/Cargo.toml --test live -- --ignored --nocapture
```

Observed against this deployment: `commit accepted — the notary is relaying TLS
to www.sandbox.paypal.com`, then `relayed response status: 302 Found`, transcript
`sent 108 B, received 3931 B`, and `presentation complete` in ~11 s. `302` is
correct for a checkout page without a real token — the attestation is about the
bytes that crossed the connection, not about the page being useful.

The notary stores what it relayed (`GET :8081/attestations` and
`/attestations/{id}` on loopback, i.e. from inside the VM). The signed body names
`server_name` and pins `sent_sha256`/`received_sha256` over the transcript; the
signing key is only trustworthy because the hardware quote covers the measured
initramfs that contains the proxy binary. Sandbox identity is synthetic: this
proves *transport and bytes*, never that a real account was involved — that is
what the production login report is for, and why the auditor marks sandbox
reports `sandbox` rather than green.

---

## 🔑 Rotating the Credentials (PayPal, ACME, DNS-01, heartbeat key)

### Where the secrets actually live

There is **no secret store**, and this is deliberate. The enclave's config
*is* the instance `user_data` — one base64 JSON blob the enclave reads at boot
from `http://100.100.100.200/latest/user-data`. Rotating a credential therefore
means: read the live config, merge the one change, write it back, reboot.

**Why not bake the secrets into the disk image?** Because then nobody else
could reproduce the measurement of that disk.

The entire audit rests on a third party recomputing the build from the public
repo and getting the same hashes (`.build-provenance`). The moment a secret is
written into the image, two things break at once:

1. **The reproduction stops being possible.** A stranger running the Docker
   synthesis engine has no access to your PayPal client secret, your ACME
   account key, or the DNS-01 token. They produce a different disk, therefore
   a different `disk_manifest`, therefore a different MRTD/RTMR0. The golden
   pins can no longer be recomputed by anyone but you — which is exactly the
   "trust me" model the project exists to eliminate.
2. **The measurement stops being meaningful.** Every credential rotation would
   change the disk hash, so a measurement match would attest *"this is the
   image plus whatever secrets were in it"* rather than *"this is the code you
   can verify"*. The auditor would have to trust that the delta was only a
   secret rotation.

So the split is: **public, measured, reproducible** (everything in the repo →
disk → MRTD/RTMR0) and **private, unmeasured, delivered at runtime**
(`user_data` → read over link-local IMDS before egress lockdown). Keeping the
second class out of the first is what preserves host-verifiability.

The build path enforces this mechanically rather than by convention: the
synthesis scripts take no credential inputs, `dist/config.json` is not staged
into the ESP, and the produced images contain no secret markers.

```bash
aliyun ecs DescribeInstances --RegionId cn-beijing \
  | jq -r '.Instances.Instance[] | "\(.InstanceId) \(.InstanceName) \(.Status)"'
aliyun ecs DescribeUserData --RegionId cn-beijing --InstanceId <ID> \
  | jq -r '.UserData' | base64 -d | jq .
```

Find the instance **by name** (`paypal-auth-vm`), never by id — the id changes
on every spot recreate. The live config carries: the two PayPal client pairs,
`staging`, `domain`, the ZeroSSL EAB pair, `acme_account_json`,
`attestation_signing_key`, `dns01_secret`, and the `self_report` heartbeat sink.

> A retired GCP version of `upload-secrets.sh` drove `gcloud secrets` and reset
> `paypal-auth-vm-v60` in `europe-west4-a`. Nothing about it can take effect on
> this stack; it was rewritten for Alibaba ECS user_data.

### The procedure

```bash
# 1. DRY RUN — reads the live config, merges your values, validates, prints a
#    change plan (secrets never printed). Nothing is pushed.
PAV_DRY_RUN=1 PAV_NONINTERACTIVE=1 \
  PAYPAL_CLIENT_ID=... PAYPAL_CLIENT_SECRET=... \
  PAYPAL_VERIFIED_CLIENT_ID=... PAYPAL_VERIFIED_CLIENT_SECRET=... \
  bash upload-secrets.sh

# 2. Read the plan. Every field should say `unchanged` except the ones you
#    meant to rotate. `self_report`, `attestation_signing_key`,
#    `acme_account_json` and `dns01_secret` MUST read `unchanged` — if one
#    says `CHANGED` or `absent`, stop.

# 3. Apply. Drops the dry-run flag; prints the same plan, then asks you to
#    type `yes` before it touches the instance.
bash upload-secrets.sh
```

Interactive use is just `bash upload-secrets.sh` — it offers five modes:

| Menu | What it does |
|---|---|
| **1 / 2** | Rotate credentials for staging / production |
| **3** | Flip `staging` only — **prompts for no credentials**, exactly as labelled |
| **4** | Rotate (or `clear`) the ZeroSSL EAB pair |
| **5** | Rotate the Cloudflare DNS-01 API token (and/or the DNS zone) only |

Mode **5** is the narrow path for an expired/revoked Cloudflare token: it
prompts for the token in a password field (twice) and an optional zone, touches
nothing else, and leaves `staging`, both PayPal pairs, the EAB pair and
`acme_account_json` alone — so the existing ACME account keeps working and only
the DNS-01 credential changes. `PAV_DNS01_ZONE=derived` drops a zone override
and goes back to deriving the zone from `domain`. Non-interactively:

```bash
PAV_NONINTERACTIVE=1 PAV_CHOICE=5 PAV_DNS01_TOKEN=... bash upload-secrets.sh
```

The token can **not** be verified from the operator host: it is source-IP
restricted to the reserved EIP, so a request from anywhere else answers
`9109 Cannot use the access token from location: …` regardless of whether the
token is good. The reboot that follows the push is the test (ACME runs once at
boot; a bad token surfaces as `ACME certificate failed: Cloudflare zone not
found` and a dark `:443`, and the rollback prompt then restores the previous
config from memory).

`staging: true` = PayPal **sandbox**; `staging: false` = PayPal **production**
(`main.rs` picks `PAYPAL_SANDBOX_AUTH` vs `PAYPAL_PRODUCTION_AUTH` from that one
boolean). To go live you must set mode 2 **and** supply the live client pair —
the boolean alone points production at sandbox credentials and the exchange
fails.

### Rules the script enforces, and why

1. **Merge, never rebuild.** The new config is `jq`-merged into the live one.
   Rebuilding from scratch is how `self_report` (the heartbeat RAM key),
   `attestation_signing_key`, `acme_account_json` and `dns01_secret` get
   silently dropped — a dropped sink made the boot channel go dark once before
   (HANDOVER §0.10). Absent keys are reported as loud warnings.
2. **Fail-closed validation mirrors `require_credentials` in `src/main.rs`.**
   Empty, `YOUR_*`, `MISSING_*` or truncated values are refused **before** the
   reboot, so you never find out from a dark `:443` that you pushed a
   placeholder. Exit 1, nothing pushed.
3. **EAB is a pair.** Half a ZeroSSL binding is refused; clear both to fall
   back to Let's Encrypt (no EAB required).
4. **Push order is Stop → Modify → Start.** `user_data` is **disk-bound**: a
   push is discarded by any later `ReplaceSystemDisk`, and a push while
   `Running` may be ignored. So: stop, wait `Stopped`, `ModifyInstanceAttribute
   --UserData`, start. `upload-secrets.sh` does this; doing it by hand means
   `Stop → [ReplaceSystemDisk if any] → UserData → Start`.
5. **No local copy is written.** The pre-rotation config stays in the
   script's memory and is used for rollback from memory if the new config
   fails to come up. Nothing containing a credential is written to disk on
   the operator machine. If you deliberately want a file, set
   `PAV_BACKUP_DIR=<path>` before running — it defaults to empty, and the
   script warns and tells you to `shred` it when set. (`~/.paypal-auth-backups`
   used to be written unconditionally; that was a plaintext credential store
   in your home directory.) Note the shell-history hazard: running
   `PAYPAL_CLIENT_SECRET=... bash upload-secrets.sh` records the secret in
   `~/.bash_history` — prefix the command with a space, or read the value
   from a descriptor instead of the command line.

### Verifying it actually took effect

`DescribeUserData` can return **0 bytes** right after a perfectly good push —
a known CLI quirk, not a failure. **The boot is the test.**

```bash
# serving?
curl -sI --max-time 20 https://login.airma.de/ | head -2      # HTTP/1.1 200 OK

# measurements and manifest intact?
curl -s https://login.airma.de/debug/envelope | jq -r \
  '.attestation_report.enclave_config.boot_measurements.binary_sha256'

# boot heartbeat (needs the endpoint flag; bare `ls` 403s, `-` form unsupported)
aliyun oss cat oss://paypal-tdx-relay-1792227992/boot/prod/latest.json \
  --endpoint oss-cn-hongkong.aliyuncs.com

# if it is dark, the serial console says how far it got
aliyun ecs GetInstanceConsoleOutput --RegionId cn-beijing --InstanceId <ID> \
  | jq -r '.ConsoleOutput' | base64 -d       # field is ConsoleOutput, not SerialConsoleOutput
```

Watch for `ACME certificate obtained in RAM successfully` — its absence is the
usual cause of a dark `:443`, and the retry ladder can hold it for over an hour
if the ZeroSSL directory is unreachable.

**The environment itself is only proven by a real login.** The signed report
carries `paypal_environment`; after a production rotation it must read
`production`. A sandbox report is a real hardware attestation of a synthetic
identity — anyone can mint `verified_account: true` there — so the auditor keeps
it non-green: it returns the verdict `sandbox` and says so, instead of refusing
the file outright (a hard refusal made every honest sandbox deployment
unauditable, and no refusal at all would let a sandbox report pass as
production).

```bash
CHROMIUM_PATH=$(command -v chromium) node scripts/e2e-login-download.mjs
```

> **STS trap:** OAuth credentials in `~/.aliyun/config.json` expire (~1 h) and
> presigned relay URLs embed them. An `InvalidAccessKeyId` or
> `SecurityTokenExpired` mid-procedure is not a config failure — run any
> `aliyun` command to re-mint, and regenerate presigns immediately before use.

---

## 📂 Repository Structure

| File | Purpose |
|---|---|
| `src/main.rs` | Rust PID 1: DHCP, Intel TDX attestation, ACME TLS, PayPal OAuth, E2EE vault, report signing |
| `src/intel_tdx.rs` | TDX evidence acquisition: DCAP quote, CCEL replay, PCK/TCB handling |
| `src/paypal.pem` | Embedded TLS trust root for the pinned PayPal API endpoints — **DigiCert Global Root G2** (SHA-256 `cb3ccbb7…ab1cb5f`, fingerprint pinned by test `paypal_api_root_is_digicert_g2_v179`) |
| `verify.html` | Browser auditor: TD Quote parser, PCK chain walk to the pinned Intel root, WebCrypto, GitHub attestation lookup |
| `zk.html` | Standalone ZK escrow prover/verifier (GitHub Pages origin): Groth16 prove + verify, authority-key handling, fail-closed identity handoff/paste gate |
| `zk-rsa.html` | Standalone RSA ZK escrow prover/verifier: OpenPGP/S-MIME/raw key parsing, Guillou–Quisquater Fiat–Shamir proof of key possession, hybrid escrow encryption, in-page verifier — zero network requests |
| `zk/rsa-test/` | TEST-ONLY fixture keys (PGP/X.509/PEM) + generators for the zk-rsa harness tests |
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
