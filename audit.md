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
