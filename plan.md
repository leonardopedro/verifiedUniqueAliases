Based on the architecture of **Intel TDX on Alibaba Cloud** (as specified in Alibaba Cloud's [Build a TDX confidential computing environment](https://www.alibabacloud.com/help/en/ecs/user-guide/build-a-tdx-confidential-computing-environment) documentation) and the threat model where **the webservice owner and the cloud provider collude**, here is the comprehensive implementation plan to guarantee hardware-enforced verification of the running code.

---

### Threat Model & Threat Matrix

| Actor | Capabilities | Target Asset | Defense Objective |
| :--- | :--- | :--- | :--- |
| **Malicious Webservice Owner** | Possesses PayPal Client Secrets, Cloudflare/DNS credentials, domain TLS certificates, and GitHub push access. | User identity, access tokens, customer PII. | Prevent plaintext observation via TLS termination, malicious PayPal apps, or modified source. |
| **Malicious Cloud Host (Alibaba)** | Controls host hypervisor, storage disks (GPT/ESP), network routing, and virtual console. | In-memory execution state, disk-stored binaries. | Prevent tampering with the running kernel, initramfs, or `/init` binary. |
| **Collusion (Host + Owner)** | Coordinated attack: Host modifies `/init` on disk; Owner signs/approves payloads to fool the client auditor. | Unrestricted user identity exfiltration. | **Hardware-gated execution**: The client refuses to interact unless Intel TDX silicon proves the running code matches the bitwise golden build. |

#### Status — v179 audit cycle (2026-10-23, live-verified on `ecs.c9i.xlarge` cn-beijing-i)

| Defense | Status | Evidence |
| :--- | :--- | :--- |
| **Outbound TLS root pin** (Phase 2 transport half) | ✅ Fixed + rotated. `hardened_client()` disables the platform root store and trusts only `include_bytes!` pins. The embedded `src/paypal.pem` was discovered to be an **expired leaf** (`CN=api-m.paypal.com`, notAfter 2026-09-13), not a root — decorative while system roots were trusted, fail-closed breakage once they were disabled. **Rotated to DigiCert Global Root G2** (`cb3ccbb7…ab1cb5f`, cross-checked against DigiCert's published thumbprint) — the real anchor of both `api-m.paypal.com` and `api-m.sandbox.paypal.com`. | `paypal_api_root_is_digicert_g2_v179` (Rust) · harness Test 31 (PEM ↔ Rust constant ↔ README) · live sandbox token exchange green |
| **Client-session binding** (Phase 5, hardware-bound nonce — login half) | ✅ Implemented beyond the plan formula. Preflight quote binds `P_enc ∥ code_challenge ∥ P_client ∥ Nonce_client ∥ custom_info ∥ App_ID` (v161.2, [32..64] zero); the **callback/login quote now additionally binds `SHA-256(P_client ∥ Nonce_client)` into `REPORTDATA[32..64]`**, so a report minted for another browser's session cannot be replayed at this one — the auditor fails closed on the mismatch (strict when the session is in hand, informational for paste audits). | `client_session_binding_parity_v179` (Rust ↔ JS golden vector) · harness Test 30a–d · live claimed login report shows the non-zero binding slot in the Intel-signed TD Quote v5 |
| **Boot-chain hardware measurement** (Phase 1/4 UKI alternative) | ⚠️ UKI **deferred with live evidence** (AGENTS.md "Deviations"): GRUB 2.12's EFI CC measurement protocol extends kernel/initrd/cmdline into RTMR0–2 and the auditor hard-pins those registers. Confirmed today twice: **RTMR2 (initrd register) moved with each new binary while MRTD/RTMR0/RTMR1 held** across two rotations. | `calculate-golden-rtmr.mjs --report --update` rotations 2026-10-23 · Test 21e2 pin-gate fixture |
| Residual (documented) | The remaining UKI gap is the hypervisor torn-read TOCTOU (clean files served to the runtime measurer while an evil kernel runs). Deferral is the plan-sanctioned option; the manifest-vs-CI provenance row covers the disk side. | AGENTS.md deviations section |
| **Cheapest TDX shape** (v180 user directive) | ✅ Deploy default switched `ecs.c9i.xlarge` ($0.024/h spot) → **`ecs.c9i.large` ($0.012/h spot)** — 50% cheaper. Live-probed 2026-10-23: spot c9i.large with `ConfidentialComputingMode=TDX` (SpotDuration=0, no protection period) booted the ESP image and produced a genuine 5007-byte hardware-signed TD Quote (configfs_tsm, provider=tdx_guest). MRTD/RTMR1/RTMR2/RTMR3 byte-identical to xlarge; **only RTMR0 differs** (ACPI/platform config is per-shape) — shape switch rotates exactly the RTMR0 pin in a reviewed commit. 8th-gen (c8i/g8i) is NOT cheaper in Beijing (c8i.large $0.013/h > c9i.large $0.012/h). | probe instance i-2ze2oi9s4598nrlew7x8 (deleted) · deploy-alibaba.sh default · DescribeSpotPriceHistory capture 2026-10-23 |

#### Status — v180 audit cycle (2026-10-23, per independent audit `audit.md` + user directives)

| Change | Status | Evidence / rationale |
| :--- | :--- | :--- |
| **Pre-login attestation REMOVED** (user directive) | ✅ `/attest/preflight` (one TD quote per unauthenticated click — a trivially reachable enclave resource-exhaustion surface) is deleted. The login now calls `/attest/login-session`: S_enc-signed fields only (app, scope, environment, state), no quote, nothing stored server-side. The completed **PayPal login is the attacker filter**: `/callback` mints the hardware quote only AFTER a PayPal-verified code exchange (verified_account gate included). | harness Test 32 (source pins + functional flow: exactly one network call, no pre-login audit, no PKCE in the authorize URL) |
| **State-carried client session** (no server-side pending session) | ✅ The OAuth `state` token is now a self-describing base64url JSON `{v,p,n,f,c,r}` (client pub, nonce, flow, custom_info, random). It is UNTRUSTED by construction — its only consumer is the callback quote's `report_data[32..64] = SHA-256(P_client ∥ Nonce_client)`, which the auditor compares against ITS OWN session values, so a forged state yields a report that fails the local audit, never a usable blob. PKCE is dropped (confidential-client exchange; the client_secret only exists inside the enclave). | `client_session_binding` golden vector unchanged · harness Test 30a–d |
| **`/debug/envelope` cached** (DoS surface closed) | ✅ Minted once per 15-minute window and served from RAM afterwards — no request path can trigger quote generation at line rate. Kept alive for the golden-pin rotation tooling and manual audits only; the login flow never touches it. | `boot_envelope` cache in `src/main.rs` (pinned by harness Test 32) |
| **Intel-only auditor** (audit.md §5.1) | ✅ The multi-root silicon dispatch (AMD SEV-SNP / Google AK / Intel TDX) and every VCEK→ASK→ARK and Google NVRAM EK path are DELETED. A report with no hardware-signed TDX quote is rejected outright (`REJECTED: Report contains no hardware-signed Intel TDX Quote`), closing cross-cloud quote substitution at the first gate. `tdxBindingLoose32` wildcard already gone (v179): both `report_data` slots are hard-verified. | harness Tests 15/18/20 (Google spoof + fully self-consistent GCP report now rejected) |
| **Post-login dead-end fixed** (user report) | ✅ The enclave-served success page now RENDERS the encrypted blob with a copy button (safe: ciphertext sealed to a key that never left the starting browser), and the auditor copy explains both retrieval paths — the old "go claim it in the other tab" message stranded users who had closed it. | `CALLBACK_CONTENT` in `src/main.rs` · verify.html post-login guidance |
| **Multi-cloud purge** (audit.md §3) | ✅ `alibabacloud` feature toggle removed (TDX compiled unconditionally), `google_ca.pem`/GCP metadata IP/GCP scripts/docs deleted, CI reduced to a single Dockerfile.alibaba job, initramfs module list is pure TDX. | `cargo test` 20/20 · CI single job in `.github/workflows/build-attest.yml` |

#### Status — v180 **cutover** + v181 cycle (2026-10-23/24, live-verified; details in HANDOVER.md §0)

| Item | Status | Evidence |
| :--- | :--- | :--- |
| **v180 cutover** (cheapest-shape deploy) | ✅ Prod is `i-2ze4tvkuf12u933nsw8a` = spot **`ecs.c9i.large`** TDX with the reserved EIP `eip-2zet05jbat6wr6rp7elrc`; old xlarge prod `i-2ze686o40uawcau9vt9v` released (Alibaba preemptible inventory email) + legacy `i-2ze7b9txw6v7c7gtrqwt` and **9 old images deleted** (cost cleanup, user request). Only two images remain: v180 `m-2zed3wq8aubdcddv64az` (rollback) + v181 `m-2zegh5k0gouo3xa81mtk` (deployed). | instance/image listings 2026-10-23/24 · HANDOVER.md §0.1 |
| **Blob-paste audit fix** (user report: pasting the success page's encrypted blob answered `Audit Failed: Invalid report.`) | ✅ `runAudit()` now detects the sealed-blob shape and runs **`decryptPastedBlob()`**: untrusted-origin refusal first (Web Auditor Tampering), session key/P_enc pin/client-session binding restored from `pav_local_session` (fallback `pav_client_jwk`), decryption through the existing fail-closed `localDecryptAndVerify`, plaintext persisted for the 💾 download. No key → actionable guidance; wrong session/tampered → wrapped fail-closed error. | harness **Test 33** (8 checks) · offline **174/0** · `REAL_REPORT=/tmp/env181.json` **182/0** · live blob-paste e2e PASS (real vault blob → decrypt → green) · offline `file://` paste-audit PASS |
| **v181 deploy + gate** (auditor-only change — no pin rotation) | ✅ `verify.html` `b30d6830…` (README digest rotated same commit); initramfs **unchanged** `5b27ec2f…` (verify.html deliberately outside the measured chain) → MRTD/RTMR pins untouched. Disk `69c19ec8…` → HK → Debian relay intranet PUT → `ImportImage` → `ReplaceSystemDisk --SystemDisk.Size 1` (1 GiB verified) → TLS 200/ssl=0 in ~2.5 min. Served digest == README == live manifest; `check-manifest-parity` **PARITY OK**. | HANDOVER.md §0.3–§0.4 |
| **Relay knowledge (new runbook)** | ⚠️ Re-arm order is `Stop` → `ReplaceSystemDisk` → **then** `ModifyInstanceAttribute UserData` → `Start` (a prior push is discarded with the old disk; `DescribeUserData` may also read 0 after a good push — the boot is the test). Only the **stock-Debian** relay (`paypal-tdx-relay179e`) executes user_data; the custom-image `oss-relay-tmp2` never does. Marker writes need `curl -X PUT -H 'Content-Type:'` — `--data` alone sends POST on a PUT-signed URL → 405 → silent 0-byte markers (re-hit this cycle; success was proven from the serial console: `RELAY181-SUCCESS`, `PUT http=200`, readback md5 match). | HANDOVER.md §0.6 |
| **Known-informational** | ⚠️ `EXPECTED_ENCLAVE_SHA256 = 'ba1a3bfe…'` is one CI run behind the live/attested binary `23053c65…` — renders the v168 amber *informational* note only (self-report never gates; silicon pins decide code identity). Both digests attest green on GitHub. Rotate in a reviewed commit **together with** the README digest (harness Test 28). | attestations API lookups 2026-10-23 · verify.html:1738–1750 |

---

### Root Flaw in the Current Implementation

In the current repository (`verify.html` and `src/main.rs`):
1. **Self-Measurement Trap**: `/init` reads `/init` from its own filesystem, hashes it, puts `binary_sha256` into the JSON report, and binds it into `REPORTDATA`.
2. **Missing RTMR Hardware Enforcement**: In `verify.html`, the comment explicitly acknowledges:
   > *"on this platform no hardware measurement covers the running image (RTMR[0] is all zeros, no vTPM) — MRTD covers the launch chain only, so running-code identity is enforced by EXPECTED_ENCLAVE_SHA256 + the CI attestation rows."*
3. **The Collusion Exploit**: The host provider modifies `/init` inside `initrd.img` on disk. The backdoored `/init` steals the PayPal token, but hardcodes `binary_sha256 = EXPECTED_ENCLAVE_SHA256` in the JSON and computes the expected nonce. It requests a TD Quote from `/sys/kernel/config/tsm/report`. Intel hardware signs the quote because `MRTD` (firmware) matches. `verify.html` sees matching `MRTD` and the claimed `binary_sha256` in the JSON, turning all checkmarks green while user data is compromised.

---

### Comprehensive Implementation Plan

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        ALIBABA CLOUD INTEL TDX SILICON TRUST CHAIN                     │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  Intel Hardware Root (PCK CA -> Quoting Enclave)                                       │
│    └─► Signed TD Quote (ECDSA P-256 over SHA-384)                                      │
│          ├─► MRTD (Launch Measurement)        == PINNED_MRTD (TDVF firmware)           │
│          ├─► RTMR0 (Firmware Environment)     == PINNED_RTMR0 (Alibaba TDVF config)    │
│          ├─► RTMR1 (Unified Kernel Image)     == PINNED_RTMR1 (Kernel+Initrd+/init)    │
│          └─► REPORTDATA[0..32]                == SHA-256(P_enc ∥ P_cli ∥ Nonce ∥ App)  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

#### Phase 1: Eliminate Unmeasured Boot via Unified Kernel Image (UKI)

Currently, the disk uses loose files (`shim`, `grub`, `vmlinuz`, `initrd.img`, `grub.cfg`). Standard Debian GRUB does not measure `vmlinuz` and `initrd.img` into TDX RTMRs, leaving the kernel and `/init` unmeasured by hardware.

1. **Replace Grub with Monolithic UKI**:
   - Combine the UEFI stub (`systemd-stub`), Linux Kernel 6.12 (`vmlinuz`), the deterministic Initramfs (`initrd.img`), and a hardcoded, immutable kernel command line (`console=ttyS0,115200n8 panic=1 selinux=0 net.ifnames=0 quiet`) into a single PE binary:
     ```bash
     objcopy \
       --add-section .osrel="/etc/os-release" --change-section-vma .osrel=0x20000 \
       --add-section .cmdline="cmdline.txt" --change-section-vma .cmdline=0x30000 \
       --add-section .linux="output/vmlinuz" --change-section-vma .linux=0x40000 \
       --add-section .initrd="output/initramfs-paypal-auth.img" --change-section-vma .initrd=0x3000000 \
       /usr/lib/systemd/boot/efi/linuxx64.efi.stub \
       output-alibaba/BOOTX64.EFI
     ```
2. **Direct UEFI Boot**:
   - In `build-alibaba-image.sh`, format the ESP FAT32 partition to contain **only** `::/EFI/BOOT/BOOTX64.EFI`.
   - When Alibaba Cloud's TDVF (EDK2) loads `BOOTX64.EFI`, its EFI CC Measurement Protocol measures the **entire binary** (stub + kernel + initramfs + `/init` + cmdline) before transfer of control, extending the SHA-384 hash into **`RTMR1`**.
   - **Result**: Any modification to `/init` or kernel parameters directly mutates `RTMR1`.

---

#### Phase 2: In-Guest Measurement & ACPI CCEL Event Log Validation

Alibaba Cloud's documentation notes:
> *"Measurement register read and extension: Reads MRTD and RTMR[0-3], parses the ACPI CCEL event log and replays it against RTMR[0-3] for comparison, and extends custom measurements into RTMR[2] and RTMR[3]."*

1. **In-Guest Runtime Self-Audit in `src/intel_tdx.rs`**:
   - Read the ACPI CCEL (Confidential Computing Event Log) table from `/sys/firmware/acpi/tables/CCEL` or `/sys/firmware/acpi/tables/data/CCEL`.
   - Replay the SHA-384 event log to verify that the loaded image matches the expected UKI digest before launching the Axum webserver.
2. **Fallback Runtime RTMR Extension**:
   - If a bare kernel is used instead of a UKI, `/init` must read the root partition/ESP image, compute its SHA-384 digest, and execute a direct `TDCALL [TDG.MR.RTMR.EXTEND]` into **`RTMR2`** (via `/sys/kernel/config/tsm/report` or `/dev/tdx_guest`).
   - If the extension fails, the enclave halts (`panic!`) immediately.

---

#### Phase 3: Hardware Quote Generation Hardening (Alibaba Cloud ECS)

Alibaba Cloud TDX instances expose attestation through ConfigFS TSM (`/sys/kernel/config/tsm/report`) on kernels $\ge 6.7$ (our Debian 13 kernel is 6.12).

1. **Fail-Closed Hardware Quote Enforcement**:
   - Modify `src/intel_tdx.rs`: Remove all fallback mocks, dummy reports, or `unavailable_no_guest_device` statuses.
   - If `/sys/kernel/config/tsm/report` or `/dev/tdx_guest` does not produce a quote signed by the Intel Quoting Enclave, the enclave must **refuse to boot or accept traffic**.
2. **Alibaba PCCS Integration**:
   - Ensure the Quoting Enclave can fetch PCK collateral by adding Alibaba Cloud's internal PCCS host to the network whitelist if needed:
     `sgx-dcap-server-vpc.${region_id}.aliyuncs.com` (port 443).

---

#### Phase 4: Enforce Hardware Pins in `verify.html` (Auditor)

Update the browser verification logic in `verify.html` to remove reliance on self-reported fields:

1. **Add Golden RTMR Constants**:
   ```javascript
   // Pinned against CI reproducible build artifacts
   var EXPECTED_MRTD  = "e0199499baacb2e4f4bc73046f25bedf674d42defbe4e854242bd6554a9d155edf7f3bff8e6202e63ed230e59ab2568a";
   var EXPECTED_RTMR0 = "..."; // Alibaba TDVF firmware baseline
   var EXPECTED_RTMR1 = "..."; // SHA-384 measurement of the monolithic UKI (kernel + initrd + /init)
   ```
2. **Update Quote Parsing Logic (TDREPORT Body)**:
   Extract RTMR registers from the Intel TDX Quote body (offsets per Intel DCAP Quote specification):
   - `MRTD`: offset 136..184 (48 bytes SHA-384)
   - `RTMR0`: offset 328..376 (48 bytes SHA-384)
   - `RTMR1`: offset 376..424 (48 bytes SHA-384)
   - `RTMR2`: offset 424..472 (48 bytes SHA-384)
   - `RTMR3`: offset 472..520 (48 bytes SHA-384)
   - `REPORTDATA`: offset 520..584 (64 bytes)
3. **Hard-Pin Verification Gate**:
   ```javascript
   const rtmr1Hex = hx(qBody.subarray(376, 424));
   const rtmr1Ok = (rtmr1Hex === EXPECTED_RTMR1);
   if (!rtmr1Ok) {
       throw new Error(`CRITICAL HARDWARE PIN VIOLATION: RTMR1 (${rtmr1Hex}) does not match the audited UKI image (${EXPECTED_RTMR1}). The host or owner has replaced the running code!`);
   }
   ```
4. **Remove Unmeasured String Checks**:
   - Do not use `report.enclave_config.boot_measurements.binary_sha256` to decide pass/fail. The verification must pass **exclusively** if `RTMR1` matches the golden UKI hash.

---

#### Phase 5: Anti-Collusion Client-Bound E2EE Session Protocol

Even if the owner terminates TLS with a valid certificate for `login.airma.de`, they must not be able to read user data in transit:

1. **Client Pre-Flight Generation**:
   - The user opens `verify.html` locally via `file://` or GitHub Pages (avoiding origin script injection from `login.airma.de`).
   - Browser generates ephemeral ECDH keypair ($P_{client}, S_{client}$) and $Nonce_{client}$.
2. **Hardware-Bound Nonce Commitment**:
   - Client calls `POST /attest/preflight` on the enclave.
   - Enclave generates ephemeral $P_{enclave}$, binds:
     $$\text{REPORTDATA}[0..32] = \text{SHA-256}(P_{enclave} \parallel P_{client} \parallel Nonce_{client} \parallel \text{code\_challenge} \parallel \text{PayPal\_App\_ID})$$
   - Enclave requests an Intel TDX Quote from hardware.
3. **Local Client Verification**:
   - `verify.html` verifies:
     1. Intel DCAP PCK Certificate Chain reaches the pinned Intel SGX Root CA.
     2. `MRTD` and `RTMR1` match the golden pins.
     3. $\text{REPORTDATA}[0..32]$ matches the client's own $P_{client}$ and $Nonce_{client}$.
     4. PayPal App ID in the quote matches the audited minimal-scope application.
4. **End-to-End Encrypted Token Return**:
   - User logs into PayPal. PayPal redirects with auth code to `/callback`.
   - `/init` derives session key $K = \text{HKDF-SHA256}(\text{ECDH}(S_{enclave}, P_{client}), Nonce_{client})$.
   - `/init` queries PayPal API, extracts `verified_account: true`, and zeroizes OAuth tokens immediately.
   - `/init` encrypts the final user report with $\text{AES-256-GCM}_K$ (authenticated with $Nonce_{client}$).
   - The response is returned as an encrypted blob. Only the client browser possessing $S_{client}$ can decrypt it.
   - **Result**: The malicious owner (who can terminate TLS or read network packets) sees only ciphertext that cannot be decrypted without $S_{client}$.

---

#### Phase 6: Egress Lockdown & Post-Boot Tamper Proofing

1. **Post-Init IMDS & HTTP Drop**:
   - Alibaba Cloud metadata service (`100.100.100.200:80`) is required at boot to ingest `user_data`.
   - Once credentials and ACME certs are acquired, `/init` must execute:
     ```rust
     nft add rule inet filter output ip daddr 100.100.100.200 drop
     nft add rule inet filter output tcp dport 80 drop
     ```
   - This prevents any post-boot exfiltration of data via metadata side-channels or unencrypted HTTP.
2. **RAM-Only Operation**:
   - Ensure `SWIOTLB` is sized appropriately (per Alibaba Cloud TDX documentation: `grubby --args=swiotlb=524288`) to avoid I/O buffer exhaustion.
   - All secrets, decrypted tokens, and keys exist exclusively in TDX-encrypted RAM and are explicitly scrubbed (`zeroize`) after execution.

---

### Step-by-Step Execution Sequence

1. **Repo / Build Script Updates**:
   - Update `Dockerfile.alibaba` to package `systemd-boot` / EFI stub tools.
   - Modify `build-alibaba-image.sh` to assemble the monolithic UKI as `BOOTX64.EFI` and eliminate separate GRUB files.
2. **Enclave Rust Updates**:
   - In `src/intel_tdx.rs`, implement CCEL event log parsing and strictly require valid quotes from `/sys/kernel/config/tsm/report`.
   - In `src/main.rs`, drop IMDS and port 80 egress rules after startup.
3. **Auditor Updates (`verify.html`)**:
   - Add `EXPECTED_RTMR1` pin for the reproducible UKI build.
   - Update the TDX parser to extract `RTMR0..3` and enforce equality against pins.
4. **CI/CD Ledger Integration**:
   - In `.github/workflows/build-attest.yml`, add a step to extract the UKI SHA-384 digest and `RTMR1` prediction, attesting them with GitHub Sigstore.
5. **Live Verification**:
   - Deploy to Alibaba Cloud ECS (`ecs.c9i.large` in `cn-beijing-i` — cheapest TDX shape, live-verified 2026-10-23).
   - Run `verify.html` locally via `file://`. Confirm that any modification to `/init` alters `RTMR1` and triggers an immediate hard audit failure.
