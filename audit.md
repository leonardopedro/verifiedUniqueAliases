# Implementation Plan: Pure-Play Alibaba Cloud Intel TDX Hardware Verification (GRUB 2.12 + RTMR2 Anchoring)

## 1. Threat Model & Architectural Invariant

```
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│                                 COLLUSION THREAT BOUNDARY                                 │
├───────────────────────────────────────────────────────────────────────────────────────────┤
│ 1. Malicious Owner:       Controls PayPal Client Secrets, domain TLS certs, DNS tokens,    │
│                           and GitHub repository write access.                             │
│ 2. Malicious Host:        Alibaba Cloud hypervisor controls storage disks (ESP/GPT),      │
│                           virtual NIC, QGS (Quote Generation Service), and host memory.   │
│ 3. External Clouds (OCI): Hostile cloud partner attempting cross-cloud replay/confusion. │
│ 4. Intel Silicon Root:    Intel CPU silicon, TDX SEAM module, and Intel DCAP PCK PKI are  │
│                           GENUINE and UNCOMPROMISED (physical attacks out of scope).      │
├───────────────────────────────────────────────────────────────────────────────────────────┤
│ ARCHITECTURAL INVARIANT:                                                                  │
│ The relying party client mathematically rejects the enclave prior to releasing any data  │
│ unless Intel silicon certifies that the running memory image matches the audited RTMR2   │
│ golden baseline, and that all user data is E2EE-sealed to the user's ephemeral key.       │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

### Architectural Decisions (Branch Mandate)
1. **Dedicated to Alibaba Cloud Intel TDX**: All remnants of legacy Google Cloud Confidential VM (AMD SEV-SNP via vTPM) and Oracle Cloud (OCI SEV-SNP) are eliminated.
2. **Phase 3 (Monolithic UKI) Deferral Maintained**: The boot chain **retains the modular GRUB 2.12 EFI loader** [2]. Live deployments have proven that Debian’s GRUB 2.12 invokes the `EFI_CC_MEASUREMENT_PROTOCOL`, measuring `vmlinuz` + `initrd.img` (enclosing `/init`) + `/proc/cmdline` directly into **`RTMR2`** [1]. Live rotations confirmed that `RTMR2` moves deterministically with each new binary while `MRTD`, `RTMR0`, and `RTMR1` remain stable.
3. **Hardware Code Anchor**: Code identity is anchored **exclusively in `RTMR2`**. Self-reported strings (such as `boot.binary_sha256`) are never used as security gates.

---

## 2. Hardware Measurement Architecture (Intel TDX on Alibaba Cloud)

Under Alibaba Cloud's TDX implementation (per the official [Alibaba Cloud TDX Environment Guide](https://www.alibabacloud.com/help/en/ecs/user-guide/build-a-tdx-confidential-computing-environment)), the platform's measurement registers partition execution into distinct hardware layers [1]:

| Register | Measured By | Measured Entities | Stability & Rotation Trigger |
| :--- | :--- | :--- | :--- |
| **`MRTD`** | Hypervisor (at `TDH.MR.FINALIZE`) | Alibaba TDVF virtual firmware private memory image | Invariant across binary rebuilds |
| **`RTMR0`** | TDVF (EDK2) | ACPI tables, platform topology, shape config | Invariant unless instance shape changes (`c9i.large` vs `c9i.xlarge`) [2] |
| **`RTMR1`** | TDVF (via EFI CC Protocol) | EFI Boot applications: `shimx64.efi` + `grubx64.efi` | Invariant unless Debian packages are upgraded |
| **`RTMR2`** | **GRUB 2.12 (via EFI CC Protocol)** | **`vmlinuz` + `initrd.img` (holding `/init`) + `/proc/cmdline`** | **Dynamic: Rotates with every new `/init` binary build** |
| **`RTMR3`** | Enclave Application Runtime | Custom in-guest extensions (`TDCALL [TDG.MR.RTMR.EXTEND]`) | Zero-pinned ($0^{48}$, unextended) |

---

## 3. Implementation Steps

```
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│                           SYSTEM HARDENING & VERIFICATION STEPS                           │
├───────────────────────────────────────────────────────────────────────────────────────────┤
│ Step 1: Clean multi-cloud artifacts from documentation and scripts.                       │
│ Step 2: Enforce strict platform locking in verify.html (reject OCI/GCP quotes).           │
│ Step 3: Formalize GRUB 2.12 -> RTMR2 hardware gating in verify.html.                      │
│ Step 4: Disallow unverified wildcard slots (tdxBindingLoose32) during report audits.     │
│ Step 5: Sever host web auditor tampering (enforce local / GitHub Pages auditor execution).│
│ Step 6: Enforce post-boot network lockdown and in-memory secret zeroization.              │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

### Step 1: Pruning Multi-Cloud Remnants

Eliminate lingering multi-cloud references to simplify the codebase and prevent developer error:

1. **Clean Root Documentation & Example Configs**:
   - Update `README.md`, `privacy.html`, and `terms.html`: Remove references to GCP Confidential VMs and AMD SEV-SNP. State explicitly that the service runs exclusively on Alibaba Cloud Intel TDX.
   - In `config.example.json`: Ensure only Alibaba Cloud configuration fields (such as `self_report` pointing to the Hong Kong OSS relay) are present.
2. **Audit Build Scripts**:
   - Ensure `build-initramfs-tools.sh` packages only Alibaba Cloud kernel modules (`tdx-guest`, `tsm`, `virtio_*`, `nvme`, `vfat`, `nftables`, `configfs`). Verify that legacy AMD SEV-SNP modules (`sev_guest`, `amd_tsm`, `coco`, `virt_anchor`) remain purged.
   - Ensure `build-alibaba-docker.sh` and `build-alibaba-image.sh` build the reproducible ESP disk without invoking any external cloud tooling.

---

### Step 2: Cross-Cloud Quote Replay Defense in `verify.html`

In an attack where the webservice owner colludes with an external cloud (such as Oracle Cloud), they could generate an attestation quote from an attacker-controlled OCI AMD SEV-SNP instance and present it to an auditor expecting an Alibaba Cloud service.

1. **Reject Non-TDX Quotes Fail-Closed**:
   Ensure `verify.html` locks the acceptable evidence class strictly to Intel TDX:
   ```javascript
   // Inside runAudit() in verify.html:
   if (!claimsTdx || claimsOci || claimsGcp) {
       updateStatus('firmwareCheck', false,
           '❌ <b>Non-TDX Evidence Rejected</b> — this service exclusively runs on Alibaba Cloud Intel TDX. Foreign evidence (OCI AMD SEV-SNP / GCP vTPM) is refused.');
       throw new Error('REJECTED: Report contains no hardware-signed Intel TDX Quote. This service exclusively supports Alibaba Cloud Intel TDX.');
   }
   ```
2. **Pin Intel Root CA**:
   Verify that the quote's embedded PCK certificate chain strictly terminates at the pinned Intel SGX/TDX Root CA:
   `44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3`.
   Any certificate issued by an untrusted cloud provider's internal CA causes the verification to fail closed.

---

### Step 3: Anchoring Code Verification Strictly in `RTMR2`

Because GRUB 2.12 measures the kernel, initramfs, and command line into `RTMR2`, code verification is based entirely on the hardware quote rather than self-reported hashes [2].

1. **Immutable Kernel Command Line**:
   In `build-alibaba-image.sh`:
   - Keep the command line fixed in `grub.cfg`:
     ```text
     console=tty0 console=ttyS0,115200n8 net.ifnames=0 biosdevname=0 swiotlb=524288
     ```
   - In `src/main.rs`, `enclave_init::verify_cmdline()` reads `/proc/cmdline` and calls `poweroff()` on any mismatch. Because GRUB measures the command line into `RTMR2`, any modified argument also mutates `RTMR2`.
2. **Hard-Pin Registers in `verify.html`**:
   - Extract `MRTD` (offset `136..184`), `RTMR0` (`328..376`), `RTMR1` (`376..424`), `RTMR2` (`424..472`), and `RTMR3` (`472..520`) from `TDREPORT10` inside the quote [1].
   - Enforce exact equality:
     ```javascript
     const rtPins = [EXPECTED_RTMR0, EXPECTED_RTMR1, EXPECTED_RTMR2, EXPECTED_RTMR3];
     const rtMismatch = rtPins.map((p, i) => (p && qRtmrHex[i] !== p) ? i : -1).filter(i => i >= 0);
     if (qMrtdHex !== EXPECTED_MRTD || rtMismatch.length > 0) {
         throw new Error(`HARDWARE PIN VIOLATION: Quoted registers do not match golden pins. Tampering detected!`);
     }
     ```
   - The self-reported `boot.binary_sha256` string in the report remains an advisory diagnostic warning; pass/fail for code execution is determined exclusively by `RTMR2`.

---

### Step 4: Full Hardware Session Binding (No Wildcard Slots)

To prevent a colluding host from substituting a quote generated for another user's session, the quote must commit to client-generated entropy across all audit modes.

1. **Enclave Dual-Slot Commitment in `src/main.rs`**:
   At `/callback`, `/init` generates the hardware quote committing both slots into `REPORTDATA`:
   $$\text{REPORTDATA}[0..32] = \text{sec02\_nonce}(\text{paypal\_hash} \parallel P_{enc} \parallel \text{custom\_info} \parallel \text{binary\_sha256} \parallel \text{manifest\_hash})$$
   $$\text{REPORTDATA}[32..64] = \text{SHA-256}(P_{client} \parallel Nonce_{client})$$
2. **Eliminate `tdxBindingLoose32` Wildcard Verification in `verify.html`**:
   When auditing a saved or pasted report offline, `verify.html` must reconstruct `expectedTdxBindingHex` using `session_context.client_pub_b64` and `session_context.client_nonce_hex`. It must enforce **both 32-byte slots**, eliminating the path where `[32..64]` was previously skipped:
   ```javascript
   const expectedClientBinding = await clientSessionBindingHex(
       b64ToDer(report.session_context.client_pub_b64),
       report.session_context.client_nonce_hex
   );
   const fullExpectedReportData = expectedNonce + expectedClientBinding;

   if (qReportDataHex !== fullExpectedReportData) {
       throw new Error("HARDWARE BINDING MISMATCH: The quote does not commit to the active client session key and nonce!");
   }
   ```

---

### Step 5: Web Auditor Isolation & Host Tampering Defenses

Because the host controls the disk partition where `verify.html` sits (`/boot/efi/verify.html`), an attacker modifying the ESP on disk could alter client-side JavaScript.

1. **Mandate Out-of-Band Auditor Execution**:
   In `verify.html`, `trustedAuditorContext()` enforces that key generation, logins, and decryption run **exclusively** on trusted client origins:
   - `file:///path/to/verify.html` (Local Auditor Mode)
   - `https://leonardopedro.github.io/verifiedUniqueAliases/verify.html` (Pinned GitHub Pages)
2. **Disable Execution on Enclave Origin**:
   When accessed via `https://login.airma.de/`, key generation and login buttons are blocked, displaying an explicit security alert instructing the user to save `verify.html` and open it locally via `file://`.
3. **Out-of-Band Digest Verification**:
   The exact SHA-256 digest of `verify.html` is published in `README.md`. Test 28 in `scripts/test-verify-security.mjs` automatically fails the test suite if the published digest drifts from the file, providing an immutable reference for users downloading the auditor.

---

### Step 6: Post-Boot Network Egress Lockdown & Memory Scrubbing

Prevent any post-boot exfiltration of tokens by host hypervisor side-channels or malicious dependencies:

1. **Post-ACME Dynamic Firewall Lockdown**:
   Once ACME certs and configuration are acquired at boot, `enclave_init::egress_lockdown()` locks down `nftables`:
   - Sever Alibaba Cloud IMDS: Drop `100.100.100.200:80`.
   - Sever unencrypted HTTP (port 80) and DNS (port 53).
   - Restrict outbound port 443 **strictly** to PayPal's pinned IPs (`104.16.124.74`, `146.75.123.1`) using the embedded DigiCert Global Root G2 certificate.
   - All other outbound traffic is dropped.
2. **Memory Hardening**:
   - Confirm swap is permanently disabled: `libc::swapoff()`.
   - Disable kernel debugging: `kexec_load_disabled = 1` and `suid_dumpable = 0`.
   - Enforce `RLIMIT_CORE = 0` to block core dumps.
   - Zeroize memory: Access tokens, PayPal profile JSON strings, and derived AES-GCM symmetric keys are wiped from RAM using `zeroize_str()` immediately after use.

---

## 4. Operational Workflow for Image Updates & Pin Rotation

Because `RTMR2` changes whenever the kernel, initramfs, or `/init` binary changes, image updates follow a deterministic process:

```bash
# 1. Build bitwise-reproducible disk image
bash build-alibaba-docker.sh

# 2. Deploy to Alibaba Cloud ECS instance via in-place disk rewrite (retaining reserved EIP)
# StopInstance -> ReplaceSystemDisk -> StartInstance

# 3. Capture live TDX quote from test boot and update verify.html pins
curl -sk https://login.airma.de/debug/envelope > /tmp/envelope.json
node scripts/calculate-golden-rtmr.mjs --report /tmp/envelope.json --update

# 4. Verify manifest parity between deployed disk and report
node scripts/check-manifest-parity.mjs https://login.airma.de/debug/envelope output-alibaba/disk-alibaba.raw

# 5. Run test harness (182+ checks must pass)
npm test

# 6. Commit verify.html and updated README.md digest in a single reviewed commit
```

---

## 5. Threat Mitigation Matrix (Pure-Play Alibaba Cloud TDX)

| Attack Vector | Colluding Actor Action | Defense Mechanism | Outcome |
| :--- | :--- | :--- | :--- |
| **Disk/Initramfs Tampering** | Host alters `/init` inside `initrd.img` on virtual disk to log tokens. | GRUB 2.12 measures kernel + initrd into `RTMR2`. `verify.html` enforces `RTMR2 == EXPECTED_RTMR2`. | **Audit Fails Closed**: Hardware quote carries altered `RTMR2`. Client halts before login. |
| **Cross-Cloud Quote Replay** | Host/Owner presents an AMD SEV-SNP quote from an OCI VM. | `verify.html` mandates `claimsTdx && !claimsOci`. PCK chain must terminate at the Intel SGX/TDX Root CA. | **Replay Blocked**: Non-TDX quote rejected immediately. |
| **TLS MITM by Owner** | Owner terminates TLS on load balancer using domain certificate. | Report is encrypted with $\text{AES-256-GCM}_K$ where $K = \text{HKDF}(\text{ECDH}(P_{client}, S_{enclave}))$. | **Data Unreadable**: Adversaries capture only high-entropy ciphertext. $S_{client}$ never left user's browser. |
| **Web Auditor Hijacking** | Host modifies `verify.html` on the ESP partition to suppress errors. | `trustedAuditorContext()` disables key generation on `login.airma.de`. User runs auditor on `file://` or GitHub Pages. | **Script Injection Defeated**: Untrusted host filesystem bypassed completely. |
| **Session Quote Replay** | Host replays an honest hardware quote from another user's session. | Callback quote binds $P_{client} \parallel Nonce_{client}$ into `REPORTDATA[32..64]`. Auditor enforces both slots. | **Substitution Blocked**: Replayed quote carries mismatched client session digest. |
| **Post-Boot Exfiltration** | Malicious dependency attempts to send tokens to external IP or IMDS. | `egress_lockdown()` drops all egress except port 443 to PayPal's pinned IPs. IMDS and DNS blocked post-boot. | **Exfiltration Blocked**: Outbound packets dropped at kernel netfilter boundary. |

---

## 6. Round 2 — Re-audit of the v180/v181 Fixes (2026-10-24)

Independent second pass over every round-1 fix under the same threat model
(cloud provider + `login.airma.de` owner colluding), covering the six plan
steps plus enclave-side surfaces not in the original plan.

### 6.1 Step verification

| Step | Round-2 status | Evidence / action |
| :--- | :--- | :--- |
| 1. Remove multi-cloud remnants & cross-cloud gate | ❌ Docs stale → **fixed this round** | Code was clean (Intel-only auditor, `REJECTED: … no hardware-signed Intel TDX Quote`), but `README.md`/`privacy.html`/`terms.html` still described GCP Confidential VM / AMD SEV-SNP. Full TDX rewrite in this round. |
| 2. Code identity anchored in hardware measurement; self-report never gates | ✅ Verified | `EXPECTED_MRTD` + `EXPECTED_RTMR0..3` are the only code-identity gates; `boot.binary_sha256` is informational (loud amber on mismatch); CI recomputes golden pins independently of the enclave. |
| 3. Live vs CI pin parity | ✅ Verified | CI run 307 (v181) 13/13 green; CI disk digest `8944…9925` == deployed; GitHub attestations API resolves the v181 binary digest `23053c65…` green. |
| 4. No unverified wildcard quote slots | ❌ **Still open at round-2 start** → **fixed this round** | `tdxBindingLoose32` still let a paste audit skip `report_data[32..64]`. Wildcard deleted; see R2-1. |
| 5. Auditor isolation | ✅ Verified | `trustedAuditorContext()` gates every key-generating flow; enclave-origin copy refuses login/claim/decrypt with explicit guidance; harness Test 24/33 (incl. blob-shape, wrong-key, enclave-origin refusals). |
| 6. Egress lockdown + zeroize | ✅ Verified | `egress_lockdown()` severs IMDS/DNS/80 post-ACME and restricts 443 to pinned PayPal IPs; `swapoff`, `kexec_load_disabled=1`, `RLIMIT_CORE=0`; `zeroize_str()` wipes tokens/profile/AES-GCM keys after use. |

### 6.2 R2-1 (fixed): paste-path `[32..64]` wildcard — `tdxBindingLoose32` removed

- **Finding**: a login report audited *without* a local session (paste/offline)
  had its client-session slot skipped — `qBindingOk` compared only
  `report_data[0..32]`. Under the collusion model a provider could serve an
  **authentic-but-stale** v173-era report (or any report whose slot matched
  nothing) and the paste audit passed it with only an informational warning:
  a replay vector through the offline path.
- **Fix**: both 32-byte slots are now enforced in every audit mode. Paste
  audits recompute the slot from the report's own
  `session_context.client_pub_b64` / `session_context.client_nonce_hex`
  (`clientSessionBindingHex(b64ToDer(...), ...)`) and require an exact 64-hex
  match; reports without reconstructible session fields fail closed.
  The success row now states which slot formula was verified.
- **Harness**: Test 30c flipped (paste without session fields → FAIL), new
  30c2 (recomputed slot → GREEN), new 30c3 (substituted session → FAIL).
- **Justification for removing rather than keeping**: no in-field binary emits
  loose-slot reports (v181 enforces the slot at mint time; the enclave echoes
  `session_context` since v179), so the tolerance served only legacy/stale
  reports — exactly the collusion replay case. Fail-closed is the correct
  posture; RR-2 records the cost.

### 6.3 R2-2 (fixed): stale `EXPECTED_ENCLAVE_SHA256` pin

- **Finding**: the code-pin constant still held `ba1a3bfe…` while the deployed
  v180/v181 binary is `23053c65…` (one CI run behind — rendered the amber
  informational note on every honest audit).
- **Fix**: rotated to `23053c650c4bfb88652ebe66cb79a216d66376051666662b5167400bf17a4633`
  in this reviewed commit, together with the `README.md` `verify.html` digest
  (harness Test 28/21d anchor both). Verified before rotation: the GitHub
  attestations API resolves `sha256:23053c65…` green, and the pre-/post-swap
  envelopes (`/tmp/env180.json`, `/tmp/env181.json`) self-report the identical
  digest.
- The pin remains **informational** by design (self-report never gates; the
  MRTD/RTMR silicon pins decide code identity).

### 6.4 R2-3 (fixed): GCP-era user-facing docs (plan Step 1)

`README.md` (v145-era GCP/SEV-SNP content, `deploy-gcp.sh`, `google_ca.pem`),
`privacy.html` ("encrypted RAM (AMD SEV-SNP)") and `terms.html` ("Google Cloud
Confidential VM", "AMD SEV-SNP enclave") rewritten to the v181 TDX reality,
including the correct chain of trust (CI attestations → MRTD/RTMR pins →
PCK chain → dual-slot binding → S_enc → E2EE vault) and the rotated
`verify.html` digest table.

### 6.5 R2-4 (fixed, operational): relay marker scripts used POST

Staged markers (`relay*-sN.txt`) are written to presigned **PUT** URLs; the
generator scripts passed `--data` without `-X PUT`, so curl POSTed and got
`SignatureDoesNotMatch` (the `|| true` swallowed it — markers never landed,
localizing failures to the final marker only). Both active templates
(`/tmp/run-relay180b.mjs`, `/tmp/run-relay181.mjs`) now emit
`-X PUT -H 'Content-Type:' --data …`.

### 6.6 Re-verified enclave surfaces (no change needed)

- `/attest/login-session` (v180): no quote minted, no storage, per-IP egress
  budget charged (4096 B), RSA-2048 echo signature only — the former
  pre-flight quote-exhaustion DoS is gone.
- E2EE vault: `MAX_PENDING_E2EE_BLOBS = 4096` ceiling, one-time remove,
  600 s TTL, claim bound to `SHA-256(blob || nonce)` — bounded and replay-safe.
- Envelope/report fields: no client secret, no sink credentials, no keys —
  `enclave_config` carries only boot measurements.
- Enclave-origin copy of `verify.html`: refuses all key-generating flows and
  explains the post-login claim path (v181 wording verified).

### 6.7 Residual risks — accepted with justification (cannot fix here)

- **RR-1 — repository write access**: an owner able to push can rewrite
  `verify.html` *and* the `README.md` digest in one commit. The digest is an
  out-of-band anchor **only if compared against an independent source** (second
  checkout, mirror, release note) — README says so explicitly. Not fixable
  from inside the repo (self-referential trust); GitHub's Sigstore attestation
  still anchors *code* identity independently of the repo contents.
- **RR-2 — legacy reports rejected**: with the wildcard gone, pre-v179-shape
  reports (no reconstructible `session_context`) now fail closed instead of
  auditing green. Intended: closing the replay vector is worth more than
  auditing stale reports; no in-field binary produces them.
- **RR-3 — enclave-origin `verify.html` copy is stale until the next disk
  cycle**: this round's auditor fixes reach trusted copies (file://, GitHub
  Pages) immediately via the repo; the ESP copy keeps the v181-built script
  until the next image deploy (§4 workflow). By design that copy's verdict is
  meaningless anyway (auditor isolation — it refuses keys and must not be
  believed); rotated with the next deploy.

---

## 7. Round 3 — payment-flow abuse & side-channel lens (2026-10-24)

Third pass, deliberately through a DIFFERENT lens than rounds 1–2: the
**PayPal payment/OAuth flow** (code issuance → exchange → vault → claim) and
**side channels** (console logging, signed timestamps, request budgets), plus
the disposition of the independent `audit2.md` checklist and the remaining
`plan.md` phases. Live probing: `/debug/envelope` and a real
`/attest/login-session` round-trip against the deployed v181 enclave.

### 7.1 Disposition of `audit2.md` (independent audit) + plan status

| audit2.md item | Status | Disposition |
| :--- | :--- | :--- |
| Step 1 — enclave cleanup (remove preflight, login-session, dual-slot REPORTDATA, egress lockdown, zeroize) | ✅ already executed (v180) | Re-verified this round directly in `src/main.rs` (route table, `report_data` dual fill, `egress_lockdown()`, `zeroize_str` at token exchange + now also the PKCE verifier). |
| Step 2 — "streamlined 4-gate verify.html" (delete `tpmCheck`/`tlsCheck`, new gate cards, auto-claim on return) | ⚠️ **deviation, justified** | The sample auditor in audit2.md is a **security regression** vs the current engine and was NOT adopted: its Gate 1 hashes the PCK leaf and declares "ECDSA Valid" **without ever verifying a signature or walking the chain to the pinned Intel root** (current code verifies quote sig → attkey→QE-report binding → QE-report sig → x509 chain walk to the pinned root); its Gate 3 only checks the client slot when a session happens to be in hand — the **exact wildcard class removed in round 2 (R2-1)**; it has no enclave-signature check, no provenance row, no MRTD-vs-RTMR split, no flow/environment gates. The 4-gate UI is presentational consolidation of checks this engine already performs as a strict superset — UX churn with zero security delta would also invalidate ~15 harness row-assertions. `tpmCheck`/`tlsCheck` stay: they are honest informational rows ("no vTPM on this platform", optional channel cross-check) pinned by Tests 5/21/… **v184 update (user directive): the `tpmCheck` ROW was subsequently removed from the UI** (an informational row that never gates is noise on a TPM-less platform; harness assertions now pin its *absence*), and `tlsCheck` now renders an explicit amber "optional cross-check not requested" state instead of a bare placeholder when no certificate is supplied. The engine-level gates above are unchanged. "Auto-claim on return from PayPal" is N/A by architecture: PayPal redirects to the enclave's `/callback` success page (renders the sealed blob for copy — v180 fix), and the claim happens in the key-holding tab (Test 33 covers paste-claim as the documented recovery). |
| Step 3 — harness updates (login-session, synthetic v4/v5 quotes, foreign-quote rejection) | ✅ already executed | Tests 15/18/20/32 + synthetic v4/v5 builders confirmed; extended this round (Test 32 flipped to PKCE-required + downgrade case; new Test 34 with 16 source pins for R3-1..R3-4). |
| Step 4 — golden pins, docs, `npm test` 100% | ✅ executed round 2 (pins `23053c65…`, README/privacy/terms TDX rewrite) + this round's redeploy rotation below. | §6, §7.7. |

Plan.md phases re-checked: Phase 2 (CCEL replay) present in
`src/intel_tdx.rs`; Phase 3 fail-closed quote minting (503) intact; Phase 4
pins enforced; Phase 5 E2EE intact **but its PKCE half was wrongly dropped —
see R3-1**; Phase 6 lockdown/zeroize intact; Phase 1 (UKI) remains the
plan-sanctioned deferral (GRUB 2.12 → RTMR2 measured live, torn-read TOCTOU
documented).

### 7.2 R3-1 (CRITICAL, fixed): OAuth code theft — the owner can exchange codes directly

- **Finding**: the v180 flow dropped PKCE with the justification "the
  client_secret only exists inside the enclave". Under the STATED threat
  model that assumption is false: **the webservice owner writes that secret
  into the enclave config** (threat matrix §1: "Possesses PayPal Client
  Secrets") and **controls domain TLS** — the owner can obtain a valid public
  CA certificate for `login.airma.de` (they control DNS) and terminate the
  victim's `GET /callback?code=…&state=…` at their own proxy; independently,
  the colluding provider saw `code`+`state` on the serial console (R3-4).
  Either adversary then performs `POST /v1/oauth2/token` itself with the
  secret it holds, receives the user's access token, and reads the identity
  from PayPal's userinfo API — **in plaintext, bypassing the enclave, every
  silicon gate and the E2EE layer**. This defeats the core invariant (c) of
  the collusion model. (PayPal's single-use code only prevents the *second*
  exchange; the adversary races or pre-empts the enclave at their own
  endpoint.)
- **Fix (R3-1, v183)**: PKCE (RFC 7636, S256) restored, with the verifier
  held where no adversary can reach it:
  1. `/attest/login-session` mints a 32-byte verifier (43-char base64url),
     parks it in `AppState.pending_pkce` keyed by the state token
     (TTL 600 s, ceiling 4096, prune-on-insert; requests are budget-charged,
     so the table cannot be flooded), and signs only the
     `code_challenge`/`code_challenge_method=S256` into `signed_fields`.
     The verifier is **never echoed** in any response (harness-pinned).
  2. `/callback` resolves the verifier **before any PayPal call** — a forged
     or expired state now fails closed before it can even reach the token
     endpoint — presents it as `code_verifier` in the exchange (PayPal
     enforces it because the authorize URL carried the challenge),
     zeroizes it, and retires the entry **only on success** (keep-on-failure:
     a raced garbage-code request cannot burn a victim's verifier; repeat
     attempts are bounded by the entry budget + TTL). `?error=` (user
     cancel) and empty-code requests return before any consumption, so a
     cancelled consent stays retryable.
  3. The trusted auditor **requires** a well-formed S256 challenge in the
     signed fields (`requirePkceChallenge`) immediately after the app pin —
     before any session state is stored or a PayPal link is built — and
     carries `code_challenge` + `code_challenge_method=S256` into the
     authorize URL (both login paths). A challenge-less login (stale
     enclave or a field-stripping relay) is refused outright.
- **Why this closes it**: every remaining secret needed for the exchange
  (`code_verifier`) lives only in TDX-encrypted enclave RAM; the owner's
  TLS termination and the provider's console/network views expose only
  `code`, `state` and the public challenge. Round 1 already proved these
  apps accept PKCE end-to-end against real PayPal (HANDOVER §2.1 T1:
  "Round-1 CSRF cookie + PKCE exercised against real PayPal").
- **Harness**: Test 32 flipped (`authorize URL carries the required PKCE
  challenge + S256 method`, RFC-shape check) + new downgrade case (signed
  fields without a challenge → `PKCE MISSING OR WEAK`, refused after
  exactly one session call); Test 34 source-pins the enclave side (mint →
  sign → fail-closed lookup → exchange → retire-on-success → bounded
  table) and the auditor side.

### 7.3 R3-2 (fixed): `/callback` egress budget was charged but never enforced

- **Finding**: `callback` charged `html.len()` **after** the PayPal exchange
  with `let _ = record_egress(…)` — the `Err(429)` branch was unreachable by
  construction, so unauthenticated spam (state tokens are freely mintable
  via login-session) could force **unlimited live PayPal token-exchange
  calls**, burning the app/IP quota (availability attack on the payment
  dependency — colluders need no secret for it) while also bypassing the
  per-IP/global bandwidth budget; `/e2ee-blob` was not charged at all.
- **Fix**: budget **checked and enforced at entry** on both routes
  (callback 24 KiB — covers the exchange + response; claim 32 KiB — sealed
  blobs are ~17 KB) before any outbound work; the response-side charge stays.
  Legit cost per login ≈ 60 KB against 25 MiB/h/IP.

### 7.4 R3-3 (fixed): signed timestamps ran +8 h in the future

- **Finding** (live, side-channel/evidence integrity): every signed
  `timestamp_ms` was taken from the platform clock, which reads **exactly
  +8 h** off real UTC (Beijing wall time as UTC) — confirmed across
  `/tmp/env180.json`, `/tmp/env181.json` (both +8 h vs their capture mtimes)
  and the live envelope. The platform clock is **provider-controlled**, i.e.
  untrusted under the collusion model, and no time-sync code exists in the
  tree (the AGENTS.md "HTTPS time fetch" claim is a GCP-era leftover).
  A signature over a false time is forged evidence and would poison any
  future freshness check.
- **Fix**: login reports now take `timestamp_ms` from **PayPal's `Date`
  header on the token-exchange response** — received over pinned-IP,
  pinned-DigiCert-root TLS, a channel neither colluder can forge — and
  declare `timestamp_source: "paypal_date"`; the platform clock survives
  only as the explicitly labelled `"platform_clock"` fallback. The auditor
  displays the field and never gates on it (unchanged).
- **Accepted residual**: `/debug/envelope` mints (no PayPal call in their
  path) keep platform-clock time until the first login syncs nothing —
  i.e. they stay skewed; label + docs cover them. **Justification for NOT
  mutating `CLOCK_REALTIME`**: the ACME cert in use was *issued under the
  skewed clock* (its `notBefore` is +8 h), so jumping the clock back at boot
  would make the enclave's own TLS invalid for up to 8 h after every boot —
  an availability regression far costlier than a labelled-wrong
  informational field; and the provider can already achieve any timing
  outcome by dropping traffic.

### 7.5 R3-4 (fixed): auth codes + state tokens on the provider-visible console

- **Finding**: `TraceLayer::new_for_http()`'s default span logs the **full
  request URI** — `/callback?code=…&state=…`, `/e2ee-blob?state=…` — into
  `/dev/kmsg`, which reaches the provider in plaintext over the serial
  console (guest memory is encrypted; the vUART is not). Pre-R3-1 that
  handed the provider the code it would have needed for a direct exchange;
  post-R3-1 it still exposed `state` (claim-steal/DoS oracle) and any
  `custom_info` travelling in URIs.
- **Fix**: custom `make_span_with` records **method + `uri().path()` only** —
  query strings never reach the console (harness pins both presence of the
  redaction and absence of any raw-URI span field).

### 7.6 Round-3 considerations accepted without code (justified)

- **RR-4 — consent phishing (attacker-initiated session)**: an adversary can
  mint their own login session and lure the victim through PayPal consent;
  the resulting report decrypts in the attacker's browser, bound to the
  attacker's session — every gate green. This is inherent to OAuth
  consent (equivalent to the adversary registering their own app with the
  same scopes), the PayPal consent screen is the designed control, and
  `state` binding was never the counter for it (it counters response
  forgery into a victim's own session). Not fixable from this codebase.
- **RR-5 — vault claim race**: the owner (via TLS-terminating their own
  domain cert) learns `state` and can pre-claim `/e2ee-blob` to deny the
  report. Ciphertext is sealed to a key that never left the victim's
  browser (disclosure impossible), R3-4 removed the provider's console
  oracle for `state`, and an owner who can see the request can already
  drop it — availability-only, equivalent to existing capabilities.
- **Live deployment is sandbox/staging** (live probe: `paypal_environment:
  "sandbox"`, sandbox `authorize_base`; `EXPECTED_APPS` has no production
  entries yet): identity shows the loud v177 SANDBOX warning by design and
  can never render as a production identity. Production cutover needs the
  production PayPal apps added in a reviewed commit — a deployment step,
  not a security hole.
- **UKI deferral / torn-read TOCTOU** — unchanged, plan-sanctioned (§6, AGENTS
  deviations); RTMR2 measured live across rotations.

### 7.7 Verification gate — v183 (all green)

| Check | Result |
| :--- | :--- |
| Rust unit tests | ✅ `cargo test` 20/0 (PKCE table, budget gates, timestamp logic compile + pass). |
| Harness, offline | ✅ **196 passed / 0 failed** — incl. flipped Test 32 (PKCE carried + downgrade refusal) and new Test 34 (16 source pins for R3-1..R3-4). |
| Harness vs live envelope (pre-swap) | ✅ **204/0** with `REAL_REPORT=/tmp/env183a.json` (new RTMR2 pin + new code pin). |
| Harness vs live envelope (final) | ✅ **204/0** with `REAL_REPORT=/tmp/env183b.json`. |
| Build | ✅ Docker pipeline twice: disk `b9292a31…` (first) → **`e0b47124…`** (final, pins on ESP); **binary `01c74f89…` identical across both** (source byte-identity), initramfs **`ce27d413…` unchanged by the verify.html-only rebuild → RTMR2 provably stable**. |
| Deploy | ✅ HK presigned PUT (ETag==md5) → stock-Debian relay re-arm (Stop → ReplaceSystemDisk → UserData → Start; **console-verified**: `RELAY183-SUCCESS`/`RELAY183B-SUCCESS`, md5 round-trip both legs) → `ImportImage` (flat `Format=raw`) → `Features.NvmeSupport=supported` (flat-wire RPC) → prod `Stop → ReplaceSystemDisk --SystemDisk.Size 1 → Start` → **TLS 200/ssl in ~2.5 min** both swaps. |
| Silicon gates on the new deployment | ✅ MRTD `e0199499…` + RTMR0 `06a32a2f…` + RTMR1 `6fa03523…` held; **RTMR2 rotated to `61ce2879…`** (new initramfs) and re-verified identical across the second rebuild; RTMR3 zero; binary self-report `01c74f89…` == pin == local Docker build. |
| Manifest parity + served copy | ✅ `check-manifest-parity` **PARITY OK** (6 same, 0 mismatched); served `verify.html` sha256 == README == live manifest == `51320e28…`. |
| R3-1 live smoke | ✅ `/attest/login-session` returns a 43-char base64url `code_challenge` + `S256`, and **no `verifier` string anywhere in the response**. |
| **R3-1 full e2e vs real PayPal** | ✅ trusted `file://` copy → session → authorize URL **with PKCE** → sandbox consent → `/callback` exchange **with the enclave-held verifier** → vault blob → paste-audit **decrypted + every silicon/identity row green** (`githubCheck` red *only* because the new binary's attestation lands with this commit's CI run — expected pre-CI; identity = designed SANDBOX warning). |
| Docs consistency | ✅ AGENTS/plan "no PKCE / nothing stored" claims corrected to the v183 reality; README digest+size rotated in the same commit (harness Test 28). |

### 7.8 Round 4 — independent audit `audit3.md` (2026-10-24) + UI maximization

Cross-check of `audit3.md` (GRUB 2.12 / RTMR2-anchored plan) against the
shipped code, section by section:

| audit3 section | Verdict | Evidence |
| :--- | :--- | :--- |
| §2/§2.1 measurement table (MRTD/RTMR0–3, GRUB→RTMR2, no-UKI) | ✅ already shipped | plan v179 live-rotation evidence; auditor pins identical (`MRTD e0199499…`, `RTMR0 06a32a2f…`, `RTMR1 6fa03523…`, `RTMR2 61ce2879…`, RTMR3 zero — audit3's constants byte-match the shipped pins) |
| §3 pre-flight elimination + PayPal filter | ✅ shipped (v180) | `/attest/login-session` bookkeeping-only; quote gated behind PayPal-verified exchange (main.rs verified-gate precedes minting) |
| §4 dual-slot (zero wildcards) | ✅ shipped (v161/v179/v182) | slot1 SEC-02 5-component + slot2 `SHA-256(P_client∥Nonce_client)` unconditionally; paste mode reconstructs from `session_context` |
| §6.1 login-session spec | ✅ **superset shipped** | budget-charged at entry (4 KiB), panic-safe DER/nonce validation, TTL+bounded zeroized PKCE table, signed environment, binding echo verified by auditor before redirect (live probe confirms) |
| §6.2 callback dual-slot minting | ✅ matches | fail-closed (`tdx_quote_b64` absent → 503), flow derived server-side |
| §5 sample `verify.html` | ⚠️ **UI shape adopted, engine NOT replaced** | adopted: prefilled enclave input, one action card, one audit card, hidden-until-needed claim. NOT adopted: its single `EXPECTED_PAYPAL_CLIENT_ID` pin (would break the full flow and is weaker than the shipped per-flow `EXPECTED_APPS` with scope+authorize_base), its Gate row set (no enclave-signature/provenance/flow/env rows — the shipped engine remains a strict superset, as justified for audit2 Step 2) |
| §5 "vestigial manual TLS textareas" | ✅ **adopted this round (user: maximum simplification)** | `certFile`/`certInput` UI + `tlsCheck` row + the runAudit cert block removed; `session_context.tls_certificate_pem` stays visible in the report JSON |
| §7 workflow / §8 mitigation matrix | ✅ consistent | current runbook + shipped defenses |

**UI maximization (user directive, v185)**: cards **3 → 2**, visible
buttons **4 → 3** (+contextual claim/link). The "Strongest: own copy"
card was a near-verbatim duplicate of the login flow (`localPreflight` ≈
`executePreflightAndLogin`: same keypair, same checks, same
`pav_local_session` store) — its pedagogy folded into the login card as a
paragraph, its host input moved up (prefilled), its button dropped
(`localPreflight()` kept as a function for the harness's untrusted-origin
assertions; its PayPal-link write now falls back to the visible
`#securePaypalUrl`).

**New independent live probes (`/tmp/audit3-probe.mjs`) — 18/0**: session
signature verifies; PKCE challenge present and **no other exact-43-char
b64url value anywhere in the response (verifier never echoed)**; binding
echo == our computation and session-specific (wrong-nonce mismatch);
per-session state/challenge freshness; flow/scope/environment signed;
warm call 226 ms (no quote minted); bogus `/e2ee-blob` state fail-closed
with no vault/object detail leaked; envelope cached (same timestamp,
fast second GET) and carries a TDX quote.

**New finding — RR-6 (justified residual): session-time enclave
authentication gap.** The `login-session` response is authenticated only
by its own self-referential signature (P_enc is first-touch-pinned from
the response itself). A colluding owner who MITMs `login.airma.de`
(they control DNS and can mint a publicly-trusted cert) can serve a
FAKE session: audited app id + auditor-passing format + THEIR OWN PKCE
verifier, capture `/callback?code&state` at their TLS endpoint, exchange
directly with PayPal (they write the config, so they hold the app
secret), and learn the identity in plaintext — bypassing E2EE — while the
victim's claim simply fails closed (no genuine report → red, nothing
downloaded, user never sees green). **Why not fixable here**: any
session-time authenticator is either (a) a pre-login hardware quote —
explicitly removed by user directive as the DoS surface (and re-adding a
rate-limited quote is exactly the surface the directive forbids), or
(b) a key the collusion pair cannot forge — no such key exists pre-quote
in this stack (config keys are owner-written; the vTPM is
provider-controlled; TDX exposes nothing before `TDG.MR.REPORT`).
**Scope already limited by shipped controls**: `EXPECTED_APPS`+scope
pins (the verified app has no PII scopes at the provider), `state`
forgery is useless downstream (auditor recomputes slot2 against its own
session → red), claim fail-closed, and the trained UX ("if any step
fails, nothing is saved"). Distinct from RR-4 (attacker-minted session
for THEIR browser); this is the owner-as-endpoint variant. Not fixable
with justification — recorded here rather than in code.

  **RR-6 scope-limit live probe (2026-10-24, `/tmp/rr6-scope-probe.mjs`)**:
  the provider-side limit is CONFIRMED — authorize with the audited
  **verified** app + PII scopes (`openid profile email address …`)
  answers a bare `200 "Sorry about that"` error page **before any login**
  (no consent form), while all three controls (verified+minimal,
  full+PII, full+minimal) redirect normally to the login form. So for the
  DEFAULT (verified) button, RR-6's identity exposure is provider-limited
  to the minimal-scope identity (no email/profile/address is obtainable
  with the audited app); PII exposure under RR-6 exists only through the
  explicit "Share full profile" button, whose app carries those scopes by
  design — that is exactly what the user consents to there.
