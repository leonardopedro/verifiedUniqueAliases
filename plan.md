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
| **Client-session binding** (Phase 5, hardware-bound nonce — login half) | ✅ Implemented beyond the plan formula. Preflight quote binds `P_enc ∥ code_challenge ∥ P_client ∥ Nonce_client ∥ custom_info ∥ App_ID` (v161.2, [32..64] zero); the **callback/login quote now additionally binds `SHA-256(P_client ∥ Nonce_client)` into `REPORTDATA[32..64]`**, so a report minted for another browser's session cannot be replayed at this one — the auditor fails closed on the mismatch (v182: enforced in EVERY mode — paste audits recompute the slot from the report's own `session_context`; no wildcard slots). | `client_session_binding_parity_v179` (Rust ↔ JS golden vector) · harness Test 30a–d+30c2/c3 · live claimed login report shows the non-zero binding slot in the Intel-signed TD Quote v5 |
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
| **Known-informational** | ✅ **Rotated 2026-10-24 (audit round 2, R2-2)**: `EXPECTED_ENCLAVE_SHA256` now pins the live/attested binary `23053c65…` (attestations API green), same reviewed commit as the README `verify.html` digest (harness Test 28/21d gate both). Self-report never gates; silicon pins decide code identity. | audit.md §6.3 · attestations API lookup 2026-10-24 · verify.html `EXPECTED_ENCLAVE_SHA256` block |

---

#### Status — v183 audit round 3 (2026-10-24, payment-flow + side-channel lens per `audit2.md`)

| Finding / item | Status | Evidence / rationale |
| :--- | :--- | :--- |
| **R3-1 — OAuth code theft by the colluding owner (CRITICAL)** | ✅ **Fixed: PKCE restored, verifier enclave-RAM-only.** v180 dropped PKCE with "client_secret only exists inside the enclave" — false under the stated model: the **owner writes that secret** and controls domain TLS (a public-CA cert for `login.airma.de` lets them terminate `/callback?code=…`), and the provider saw `code`+`state` on the serial console (R3-4). Either could exchange the code directly with PayPal and read the identity in plaintext — bypassing enclave, silicon gates and E2EE. Fix: login-session mints a 43-char S256 verifier into a bounded/TTL'd RAM table and signs only the challenge; `/callback` resolves it fail-closed **before any PayPal call**, exchanges with `code_verifier`, retires it on success (keep-on-failure so a raced garbage code can't burn a victim's verifier), zeroizes; auditor hard-requires the challenge (both flows, before storing any session) and carries it into the authorize URL; user-cancel/empty-code return before consumption. | live e2e vs real PayPal: authorize w/ challenge → consent → exchange OK → blob decrypted, rows green · live probe: challenge present, **verifier never echoed** · harness Test 32 flipped + downgrade case, Test 34 pins · round 1 had already proven these apps accept PKCE (HANDOVER T1) |
| **R3-2 — `/callback` egress budget charged but never enforced** | ✅ **Fixed**: budget checked **at entry** (24 KiB) on `/callback` before the PayPal exchange (the old `let _ =` post-charge made 429 unreachable → unbounded forced PayPal token-exchange calls = payment-dependency quota burn) and on `/e2ee-blob` (32 KiB, previously unbudgeted). | Test 34 source pins (entry gate before `oauth2/token`; claim charge) |
| **R3-3 — signed timestamps +8 h off (provider-controlled clock)** | ✅ **Fixed for evidence**: login-report `timestamp_ms` now comes from **PayPal's `Date` header** over pinned-IP/DigiCert-root TLS with `timestamp_source: "paypal_date"` (platform clock only as labelled `platform_clock` fallback). Confirmed skewed across env180/env181/live (`+8h` exactly — Beijing wall time as UTC; no time-sync code exists). **Justified residual**: system clock NOT mutated — the live ACME cert's `notBefore` was minted under the skewed clock, so jumping back would invalidate the enclave's own TLS for up to 8 h per boot (availability > cosmetic); `/debug/envelope` stamps keep the platform clock until the first login (labelled, display-only, never gated). | audit.md §7.4 · Test 34 pins · envelope ts observed +8 h in all three captures |
| **R3-4 — auth codes/state tokens on the provider-visible console** | ✅ **Fixed**: TraceLayer's default span logged the **full URI** (`/callback?code=…&state=…`) into `/dev/kmsg` → plaintext over the serial console to the provider. Custom `make_span_with` records method + `uri().path()` only. | Test 34 pins (redaction present, no raw-URI span field) · pre-fix this was the provider's raw-material path for R3-1 |
| **audit2.md Step 2 (4-gate UI rewrite)** | ⚠️ **Deviation, justified** | The sample auditor would REGRESS security: its Gate 1 hashes the PCK leaf without verifying any signature or walking to the pinned Intel root; its Gate 3 skips the client slot without a session (the exact wildcard removed in R2-1); no enclave-signature/provenance/flow/env gates. Current engine = strict superset; tpmCheck/tlsCheck are honest informational rows. UX churn with zero security delta → not adopted. "Auto-claim on return" is N/A by architecture (redirect → enclave success page; claim in the key-holding tab — Test 33). audit2 Steps 1/3/4 were already executed (re-verified). | audit.md §7.1 |
| **Justified residuals** | RR-4 consent phishing (inherent to OAuth consent — PayPal consent screen is the control, `state` counters response-forgery, not phishing) · RR-5 vault claim-steal = availability-only post-R3-4 (ciphertext sealed to a browser-only key; an owner who sees the request can already drop it) · live deployment still sandbox/staging (loud v177 warning by design; production cutover needs production apps in a reviewed commit) · UKI deferral unchanged. | audit.md §7.6 |
| **v183 deploy + gate** | ✅ Two-cycle deploy so the ESP copy carries fully rotated pins: disk `b9292a31…` → then **`e0b47124…`** (verify.html with new RTMR2/code pins; **binary `01c74f89…` + initramfs `ce27d413…` byte-identical across both** → RTMR2 `61ce2879…` provably stable). Relay legs console-verified (`RELAY183-SUCCESS`, `RELAY183B-SUCCESS`, md5 round-trips), import + NVMe flag, prod `ReplaceSystemDisk --SystemDisk.Size 1` both swaps, TLS ~2.5 min. Gates: `PARITY OK`, served == README == manifest `51320e28…`, offline **196/0**, live-envelope **204/0**, live PKCE e2e green. | audit.md §7.7 |

---

#### Status — v184 UI simplification (2026-10-24, user directives: no pre-flight surface, minimal UI)

| Item | Status | Evidence / rationale |
| :--- | :--- | :--- |
| **Pre-flight surface REMOVED** | ✅ The user's directive: *the completed PayPal (verified-scope) login IS the pre-flight check* — it uses PayPal itself as the attacker filter, so a separate pre-login hardware-check surface only adds a free resource-exhaustion vector. The audit2.md "Step 3 — Verify WITHOUT login" card (fetch silicon cert / audit chain buttons) and the green "Most visitors" explainer card are deleted; the login card's label now states this explicitly ("the login IS the pre-flight check"). The engine functions (`preflightBindingHex`, P_enc pin, dual-slot enforcement, PKCE) are untouched — only the surface is gone; a pre-v184 saved report with a pinned P_enc still audits fail-closed against a swapped enclave. | harness 196/0 (incl. Test 30a–30d session-binding suite, Test 32 PKCE, P_enc-pin violation path) |
| **UI collapsed to the minimum** | ✅ 4 input cards + help card → **2 input cards** (login / audit) + results table; buttons 8 → 5 (3 of them hidden by default); `tpmCheck` row deleted (no TPM evidence exists on this platform — an informational row that never gates is noise); the "Need help?" card and the "Seeing No valid Silicon Root of Trust?" card are folded into one fail-closed sentence in the audit card. Prose kept: throwaway-key model, owner+provider collusion threat, enclave-never-redirects, file:// strongest setup, fail-closed reading of rows. | verify.html v184; harness pins row removal (tpmCheck absent) |
| **Webservice URL prefilled** | ✅ `localEnclaveHost` is pre-filled synchronously at script start: an enclave-served copy gets `location.origin`; a file:// or GitHub Pages copy defaults to the production `https://login.airma.de`. Field stays fully editable; e2e `page.fill` overrides cleanly. | harness (stub DOM prefill path), e2e-login-download.mjs L63 fill |
| **Login-link contrast fixed** | ✅ Anchors had NO explicit style → browser default link blue/purple was near-invisible on the dark background (user report: the enclave-signed "Continue to PayPal →" link was indistinguishable from the page). Global `a { color:#58a6ff; underline; 600 }` + hover. | verify.html CSS v184 |
| **Claim-button lifecycle** | ✅ `claimBtn` hidden by default (minimal UI), surfaced when a client session/key exists (login success + reload with stored `pav_local_session`), hidden again while claiming. | harness 196/0 |
| **audit2.md Gate 1/Gate 3 corrections** | ✅ Confirmed already-implemented in the shipped engine — audit2.md's *plan draft* had those defects (Gate 1: bare PCK hash, no signature walk; Gate 3: `activeSession`-gated slot skip = the R2-1 wildcard). Shipped verify.html verifies the ECDSA quote signature over `header||body`, the QE `report_data` commitment, the QE-report signature under the PCK leaf, and the chain link-by-link to the pinned Intel root (`44a0196b…`); both report_data slots are enforced unconditionally, paste mode reconstructs slot 2 from `session_context`, missing fields fail closed. | verify.html L2205–2254; harness Test 2/3/30a–30d; audit.md §6.2 R2-1 |
| **Offline gates** | ✅ `node scripts/test-verify-security.mjs` → **196/0** (README digest+size rotated same commit: `verify.html` 163,371 bytes, `c40d22e2…`). | this cycle |
| **Visual-review pass + v184b deploy** | ✅ Real-Chromium screenshots (default + full audit of the live claimed report): restored the help card's operational walkthrough + fail-safe line as a **Flow:** paragraph; `tlsCheck` amber "cross-check not requested" state replaces the bare state-less placeholder; "Silicon Root row below"→"above"; header lost the removed AMD path. Two deploy passes (final disk **`de52934e…`**, image `m-2ze4c305t483i9b5275c`, no pin rotation). Gates: 196/0 offline, **204/0 live**, PARITY OK, served==README `c40d22e2…`, **sandbox e2e PASS ×2**. | HANDOVER §0.8 |

---

#### Status — v185 audit round 4 (2026-10-24, independent audit `audit3.md` + user directives: maximum UI simplification)

| Item | Status | Evidence / rationale |
| :--- | :--- | :--- |
| **audit3.md cross-check (all sections)** | ✅ §2/§2.1 measurement+no-UKI, §3 pre-flight elimination, §4 dual-slot, §6.1/§6.2 enclave spec, §7 workflow, §8 matrix = **already shipped** (audit3's pin constants byte-match the shipped MRTD/RTMR pins). §5's sample `verify.html` **UI shape adopted, engine not replaced**: its single `EXPECTED_PAYPAL_CLIENT_ID` pin would break the full flow and is weaker than the shipped per-flow `EXPECTED_APPS` (client_id+scope+authorize_base); its gate rows lack the enclave-signature/provenance/flow/env gates the shipped engine keeps. §5's "vestigial manual TLS textareas" **adopted**. | audit.md §7.8 disposition table |
| **Maximum UI simplification (user directive)** | ✅ Cards **3 → 2** (login / audit), visible buttons **4 → 3** (+contextual claim & PayPal link). The "Strongest: own copy" card duplicated the login flow verbatim (`localPreflight` ≈ `executePreflightAndLogin` — same keypair, same checks, same session store): pedagogy folded into the login card (own-copy paragraph), host input moved up (prefilled), button dropped. `localPreflight()` kept for the harness's untrusted-origin assertions; its link write falls back to `#securePaypalUrl`. TLS cert inputs + `tlsCheck` row + runAudit cert block removed (informational-only, never gated; report JSON keeps `tls_certificate_pem`). | screenshots (2-card + 4-row results) · harness **196/0** · cargo 20/0 |
| **New live probes (independent)** | ✅ **18/0** (`/tmp/audit3-probe.mjs`): session signature, PKCE challenge present with verifier-never-echoed (exact-value scan), binding echo == our computation + session-specific, per-session freshness, signed flow/scope/environment, warm 226 ms (no quote), bogus-state vault fail-closed with no leak, envelope cached + quote present. | probe run 2026-10-24 |
| **NEW: RR-6 — session-time enclave authentication gap** | ⚠️ **Justified residual (cannot be fixed without violating the no-pre-login-quote directive)**: the login-session response authenticates only via its own first-touch P_enc signature; an owner who MITMs the domain (DNS + publicly-trusted cert) can serve a fake session with the audited app + THEIR PKCE verifier, capture `/callback`, exchange directly (they hold the app secret) and learn identity in plaintext — E2EE bypassed — while the victim's claim fails closed (red, nothing saved, never green). No collusion-proof pre-quote authenticator exists (config keys owner-written, vTPM provider-controlled, TDX silent before `TDG.MR.REPORT`; a pre-login quote is the exact DoS surface the user directive removed). Scope limited by shipped controls: `EXPECTED_APPS`+scope pins, session-bound slot2 (forged state → red), claim fail-closed, trained UX. Distinct from RR-4 (owner-as-endpoint variant). **Scope-limit live-probed ✅**: verified app + PII scopes → PayPal error page at authorize *before login*; controls pass — provider-side PII denial confirmed, so default-button exposure is minimal-scope identity only. | audit.md §7.8 RR-6 |
| **v185 gates** | ✅ offline **196/0**, cargo **20/0**, README digest rotated (`verify.html` 161,473 B, `d9a91a16…`); live gates + e2e recorded in HANDOVER §0.9 after deploy. | this cycle |

---

#### Status — v185.1 deploy + gates (2026-10-24/25, user directive: TLS binding restored)

| Item | Status | Evidence / rationale |
| :--- | :--- | :--- |
| **TLS Certificate Binding RESTORED** (user directive, overriding audit3 §5's "vestigial" adoption in v185) | ✅ The audit card regains the optional PEM textarea + file input; `runAudit()` leaf-compares the pasted cert against `report.session_context.tls_certificate_pem` (equal → green "TLS channel bound.", unequal → red); with no certificate the row renders the explicit amber "cross-check not requested" state — informational, never gates. README sample output + digest rotated the **same commit**: 163,150 B, `14a54222d693988a638e252ce18d6abaf4950d31add2d2ae415334e2fae845c2`. | verify.html v185.1 · harness offline **196/0** |
| **index.html mirrors verify.html** | ✅ Byte-identical copy (`cmp` clean, 163,150 B) so the GitHub Pages root serves the auditor directly. | this cycle |
| **v185d build + prod swap** | ✅ disk sha256 `75ef77dc…` / md5 `a87f73f58b78f805ec2bc0fa47480dc6` → HK `disk185d.raw` → relay185e green (s1→s4 markers + `relay-ok185e.txt`, readback md5 match) → Beijing intranet `paypal-auth-vm/disk185d.raw` → `ImportImage` (flat `.Format=raw`) → image **`m-2ze5hs6tgv7pwfzcuryu`** + `Features.NvmeSupport=supported` → prod `Stop ForceStop` → `ReplaceSystemDisk --SystemDisk.Size 1` (`d-2zef7xhigzn43mn4l15n`, 1 GiB `cloud_auto`) → Start. binary `01c74f89…` + initramfs `ce27d413…` unchanged → **no pin rotation** (live RTMR0/1/2 identical to pinned values). | HANDOVER §0.10 |
| **ZeroSSL route incident (ACME dark ≈18:45–19:49 UTC)** | ⚠️ Route-dependent `acme.zerossl.com` trouble — black-holed from the operator host, undecodable poll bodies from Beijing, HTTP 200 from a third network — NOT the enclave or its config. The retry ladder (15 s → 300 s) recovered it without intervention: cert reissued by `ZeroSSL RSA DV SSL CA 2` (valid → 2027-01-22), HTTPS 200 at 19:49:58 UTC. The designed no-EAB Let's Encrypt fallback was deliberately not triggered (no config change). | serial-console capture (`GetInstanceConsoleOutput`) + openssl s_client issuer/dates |
| **Tooling** | ✅ `check-manifest-parity.mjs` SKIP gains **`boot-probe.log`** (enclave-written to `/boot/efi` at runtime, post-measurement — a cold-built image can never contain it while every post-boot manifest does; same class as `NvVars`) → first parity run against a live post-boot envelope now reports **PARITY OK** (6 SAME, 2 excluded, 0 mismatched). Local cargo gate documented: `PKG_CONFIG_PATH=/nix/store/7l09089ahshxjx4js3zswqk6azhx6ccq-openssl-3.6.5-dev/lib/pkgconfig cargo test`. | scripts/check-manifest-parity.mjs · /tmp/cargo-debug2.log |
| **v185.1 gates** | ✅ offline **196/0** · live-envelope **204/0** · cargo **20/0** · PARITY OK · served == README == `14a54222…` (https + http/IP) · **live sandbox e2e PASS ×2** (verified 19:56:43 + full 19:57:31 UTC: login → consent → callback → claim → green → downloaded). | this cycle · HANDOVER §0.10 |

---

#### Status — v186 audit round 5 (2026-10-25, independent audit `audit5.md` + user directives: heartbeat survives lockdown, maximum UI simplification)

| Item | Status | Evidence / rationale |
|---|---|---|
| **Self-report success heartbeat survives egress lockdown** (queued directive) | ✅ `egress_lockdown()` calls `selfreport::pin_sink_network()` BEFORE flushing the output chain (DNS still open; 3 attempts, IPv4 only) and adds `ip daddr {…} tcp dport 443 accept` for exactly those addresses; `put()` pins the reqwest resolver (`resolve_to_addrs`) so post-lockdown publishes need **no DNS** — deliberately NO `udp 53` reopen (no query-channel exfil; the payload stays secret-free, signed per request by the write-only RAM key). Root cause: the flush ran before `selfreport::serving()`, so the heartbeat and every post-lockdown halt were silently dropped while pre-lockdown stage docs landed. | cargo `selfreport_survives_egress_lockdown_v186` (pin-before-flush ordering, sink rule present, no-DNS pin, IPv4-only) · **LIVE-PROVEN twice**: `boot/latest.json` = `kind:ok, stage:serving` on the v186a AND v186b boots (uptime_s 112 / 157 — published after lockdown) |
| **NEW — session-time FLOW substitution refused** | ✅ The enclave signs whatever flow label the (adversary-owned) request path delivered; substituting `verified → full` passed EVERY signature, app-pin and PKCE check (the full app is legitimately in `EXPECTED_APPS`) — the audit-time FLOW ESCALATION only caught it AFTER the PayPal consent. `executePreflightAndLogin` now compares `sf.flow` against the flow THIS tab requested, before the authorize link exists. | harness Test 32 (`substituteFlow` stub → FLOW SUBSTITUTION, no link built, no extra session) |
| **NEW — 512-byte `custom_info` cap on BOTH ends** | ✅ The auditor always capped it client-side; `/attest/login-session` accepted unbounded `custom_info` — the field is copied TWICE into the signed response (state + signed_fields) while charged 4 KiB egress (≈256× budget bypass), and a forged `/callback` state could park an unbounded blob in the 32 KiB-charged vault. Shared `canonical_custom_info()` → 400 / `invalid_session`; auditor check switched to `TextEncoder` BYTES (257 two-byte chars = 514 B refused pre-fetch). | cargo `custom_info_512_byte_cap_v186` (bounds, multibyte, both call-site source pins) + harness byte-cap case |
| **NEW — no green Identity row on unauthenticated reports** | ✅ `identityCheck` was painted green BEFORE the enclave-signature check — a forged report rendered a green Identity row beside the red signature row. Moved after `sigOk`; explicitly failed + explained on invalid sig. | harness Test 16 (row ≠ verified + /unauthenticated/ explanation) |
| **Max UI simplification** (user directive: BOTH login buttons + 5 result rows explicitly KEPT) | ✅ Two `.grid` wrappers → one; login card 3 → 2 paragraphs (content preserved); second status paragraph removed (single status line for login+claim). Dead code deleted: `localPreflight()` (5.8 KB duplicate of `executePreflightAndLogin`, zero UI callers — harness's untrusted-origin assertion moved to the claim path), `preflightUrl`/`localPaypalUrl` fallbacks. verify.html **163,150 → 158,202 B** (`242b033e…`) == README == served == index.html (byte-identical mirror). | harness 201/0 · e2e claim-status selector updated to `#secureLoginStatus` |
| **audit5.md disposition** | ✅ **Key invariants 1–4 already shipped**: Gate-1 cryptographic completeness (quote ECDSA over header+body, `SHA-256(attkey‖qe_auth)` binding, QE report signed by PCK leaf, chain walk to the pinned Intel root `44a0196b…`), Gate-3 zero-wildcard dual-slot (v182 — paste mode reconstructs slot2 from `session_context` fail-closed), no pre-flight quote (v180 `/attest/login-session`, RAM-only PKCE), GRUB 2.12 → RTMR2 hard pins. §3 protocol ≡ shipped; §5.1/§5.2 code ≡ shipped handlers; §6 threat-matrix rows all map to shipped controls. **§4 sample `verify.html`: engine NOT replaced** — its single `EXPECTED_PAYPAL_CLIENT_ID` pin would break the full flow and is weaker than per-flow `EXPECTED_APPS` (client_id+scope+authorize_base+flow), and the sample lacks the enclave-signature / PKCE / flow-binding / provenance / P_enc-continuity / TLS gates the shipped engine keeps. §4's single-button + 4-gate UI: **user explicitly chose** both-buttons + 5-rows this cycle. §4 tail (replace the /callback copy-encrypted-report button with a plain download): not adopted — the copy button is the pinned fallback of the trusted-copy recovery flow (harness Test 33 + untrusted-origin guidance), and a downloaded blob cannot decrypt in another origin without the key (that is the design). | this cycle |
| **Two-cycle deploy (sanctioned pin-rotation procedure)** | ✅ Cycle A: disk `643f013e…`/md5 `5f7925aa…` → HK `disk186a.raw` → relay186a green (2.2 min, s1→s4 + `relay-ok186a.txt`) → Beijing intranet → `ImportImage` `m-2zefiag79exwggjl8z0m` + NVMe (flat-wire RPC) → prod swap (config re-pushed after ReplaceSystemDisk — user_data is disk-bound, §0.6 quirk) → TLS 200 in 2.3 min → envelope → **RTMR2 rotated `61ce2879… → 99c5322d…`** (MRTD/RTMR0/1/3 held; live binary_sha256 == pin `68281d24…`). Cycle B: rebuild **byte-identical** binary `68281d24…` + initrd `1af2c963…` (reproducible synthesis → RTMR2 stable) carrying the rotated verify.html on the ESP → disk `66befe70…`/md5 `58815d45…` → relay186b (2 min) → `m-2ze5hs6tgv7q4lyymybm` + NVMe → prod swap (disk `d-2ze5juogkfapt7f97584`) → TLS 200 05:20 UTC. | HANDOVER §0.11 |
| **v186 gates** | ✅ offline **201/0** (196 → 201: +identity-row ×2, flow-substitution ×2, byte-cap ×1) · live-envelope **209/0** (captures from BOTH cycle boots) · cargo **22/0** · `check-manifest-parity` **PARITY OK** (6 same incl. verify.html, 0 mismatched) · served == README == `242b033e…` over https **and** http/IP · **live PayPal sandbox e2e PASS ×2** (verified + full buttons). | this cycle · HANDOVER §0.11 |
| **v187 — single workflow button** (user directive: ONE button that changes text+action through the flow; sequence = **verified-only round THEN full-profile round**; the PayPal link REPLACES the button and its click swaps in the next button; supersedes the “BOTH login buttons kept” choice of v186) | ✅ `#workflowBtn` state machine (`start-verified → to-paypal → claim → start-full → to-paypal → claim → done`), driven by `setWorkflow`/`renderWorkflow`, resume-on-reload via `pav_local_session` + `pav_wf_stage`; `claimBtn` and the two inline login handlers removed; link moved into the same slot with inline `setWorkflow('claim')` swap; card copy rewritten to “Flow (one button)”. **Callback landing page gains 💾 Download encrypted report (.json)** next to 📋 Copy (ciphertext download → trusted auditor's file picker → v181 decrypt+audit path; copy kept — it is Test 33's pinned fallback). index.html kept byte-identical; README digest rotated (final `3030363a…`, 163,208 B). **Deployed (two-cycle, 2026-10-25):** cycle A disk `a6f87f39…` → image `m-2ze37tjptqghwkcqt7i7` → live envelope → **RTMR2 `99c5322d… → 153b4f71…`** + binary pin `cebf46eb…` (commit `42920ed`; MRTD/RTMR0/1/3 byte-held) → cycle B rebuild byte-identical binary `cebf46eb…` + initrd `7e26d4e8…` → disk `aad98b9f…` → image `m-2zeidtvqcw46h2ypl6f0` → prod swap (disk `d-2ze8qrvt5fqcuxl40kuu`, config re-pushed 5,836 b64) → TLS 200/ssl=0 → envelope B pins byte-match A; callback 📁 button live (`6b. callback download button count: 1`), heartbeat `ok/serving` 11:21:41Z. | harness **221/0** (+Test 36 ×9, +Test 37 ×6) · live-envelope **229/0** ×2 · cargo **22/0** · parity **OK** · served==README==local `3030363a…` https+http/IP · **live e2e PASS ×2** |
| **v188/v188.1 — ZK escrow credential + audit round 2 (F1–F6), collusion model** | ✅ New: full Circom/Groth16 selective-disclosure layer (circuit 200,818 constraints, local ceremony, lazy SRI-pinned snarkjs, embedded vkey, artifact sha256 pins, escrow decrypt tool, Tests 38/39) + v188 flow (callback auto-download + window.close, two explicit login links, no claim step). Audit findings **F1** zero-slot login fall-through → hard reject; **F2** index↔verify auditor byte-parity gate (Test 40); **F3** HSTS on every response (source-pinned); **F4** credential statement bound to the PROVEN Groth16 signals (6 forgery tests); **F5** zkey published split under GitHub's 100 MB limit (browser reassembles + one pin); **F6** live-e2e double-prepare race (repeat click re-minted state #2 and overwrote the seal nonce — broke EVERY login) → prepared link returns early. **Deployed in three cycles**: A `m-2zegh5k0goup4x432oai` (RTMR2 `153b4f71… → 09e22230…`, binary pin `3f684786…` rotated offline from the built binary) → B `m-2ze8vh5ynx2z7pn4e55c` (rotated auditor, RTMR2 byte-held live-proven) → C `m-2ze7zy0u7fv3shpcrxw0` (F6 auditor `0eb6324f…`, ESP-only, no rotation needed). | harness **286/0** offline · **294/0** live · cargo **22/0** · witness R1CS PASS · real groth16 prove/verify PASS · parity **OK** · served==README==local `0eb6324f…` · **live PayPal e2e PASS ×3** · CI f2b0ddf/65b99ca/2ab7560/bacb725 all success · HANDOVER §0.13 |

---

#### Production cutover readiness (2026-10-25 — live production-mode audit cycle)

Probe: live `POST /attest/login-session` (HTTP 200) + config/auditor/enclave
static cross-check. **Verdict: NOT READY — 3 blockers, all config/allow-list
level; the enclave and auditor code paths are production-complete.**

| Area | State | Evidence |
|---|---|---|
| Enclave production code path | ✅ ready | `PAYPAL_PRODUCTION_AUTH` (main.rs:1025); `staging:false` flips authorize_base + signed `paypal_environment: "production"`; both flows configured (`get_flow_config`) |
| Auditor production gates | ✅ ready | harness `production login passes` (production envelope → identity green); environment + app + scope all live inside the S_enc-signed report (unspoofable); sandbox keeps its loud amber verdict by design (v177 two-verdict) |
| Hardware + transport | ✅ ready | MRTD/RTMR pins live `99c5322d…`, live-envelope 206–209/0, ZeroSSL cert valid → 2027-01-22, DigiCert-G2 transport pin covers BOTH api-m.paypal.com and api-m.sandbox (v179) |
| Live probe (today) | ℹ️ sandbox mode | signed `paypal_environment: sandbox`, `authorize_base: sandbox.paypal.com`, verified app `AZXkzMWM…`, PKCE S256/43, `binding v180` — session contract healthy |
| **Blocker 1 — production PayPal apps** | ❌ missing | the configured ids are SANDBOX apps (they only authorize at sandbox.paypal.com). Cutover needs live REST apps (verified + full) with `https://login.airma.de/callback` whitelisted |
| **Blocker 2 — EXPECTED_APPS allow-list is sandbox-only** | ❌ | both entries pin `authorize_base: https://www.sandbox.paypal.com/signin/authorize` — `checkExpectedApp` would fail-closed REFUSE a production session (pin discipline working as intended). A reviewed commit must add the production entries (client_id + authorize_base + scope × both flows) BEFORE the config flip |
| **Blocker 3 — config flip** | ❌ `staging: true` | prod user_data carries `staging:true` + sandbox secrets. Cutover = push `staging:false` + live pairs (deploy-alibaba.sh env path — sink emission pinned by harness Test 35) + restart |
| Post-cutover validation | ⚠️ manual step | production consent cannot be e2e-automated without a real PayPal account; the offline harness already audits production reports green (206/0) |


---

### Root Flaw in the Current Implementation

> **STATUS (v186, 2026-10-25): RESOLVED.** The self-measurement trap described
> below is closed in the shipped code: `binary_sha256` gates NOTHING
> (informational row only; `EXPECTED_ENCLAVE_SHA256` is a display pin), and
> code identity is decided EXCLUSIVELY by the MRTD/RTMR silicon pins enforced
> in the auditor over the Intel-signed quote. RTMR2 rotates with every
> `/init` build (last rotation this cycle: `61ce2879… → 99c5322d…`), so a
> backdoored initrd on the virtual disk yields a quote whose RTMR2 fails the
> hard pin — exactly the collusion exploit this section warned about. The
> UKI-based fix (Phase 1 below) remains deferred WITH justification; see the
> phase-status table.

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

#### Phase status (v186, 2026-10-25) — plan is LARGELY EXECUTED; deviations documented

| Phase | Status | Where |
|---|---|---|
| 1 — UKI / eliminate unmeasured boot | ⚠️ **Deferred with justification** — GRUB 2.12's `EFI_CC_MEASUREMENT_PROTOCOL` live-proven to measure vmlinuz+initrd+cmdline into RTMR2 (RTMR2 rotated with every initrd build, incl. this cycle); residual = hypervisor torn-read TOCTOU, the plan-sanctioned deferral | AGENTS.md "Deviations" · v179 status row |
| 2 — In-guest CCEL replay (+ optional RTMR extension) | ✅ **Shipped** — `intel_tdx::replay_ccel` replays the ACPI CCEL against the quoted RTMRs at boot, fail-closed on mismatch; golden-vector self-test shared with the JS tool and the Rust test | `src/intel_tdx.rs` · `ccel_replay_selftest_v168` |
| 3 — Fail-closed hardware quote generation | ✅ **Shipped** — `tdx_quote_b64` is published only from a hardware-signed quote (configfs_tsm / tdx-guest probe); no mocks or dummy fallbacks; the auditor rejects every other evidence class outright (Intel-only gate) | `src/intel_tdx.rs` · verify.html Gate 1 |
| 4 — Hard pins in verify.html | ✅ **Shipped** — EXPECTED_MRTD + EXPECTED_RTMR0–3 hard pins over the quote body (fail-closed on missing/malformed pins), offsets per Intel DCAP spec | verify.html silicon gate |
| 5 — Anti-collusion client-bound E2EE session | ✅ **Shipped** — client ECDH keys browser-only, dual-slot REPORTDATA (SEC-02 slot1 + client-session slot2), P_enc key-continuity, RAM-only PKCE, app/flow/environment binding | verify.html + `src/main.rs` |
| 6 — Egress lockdown + RAM-only operation | ✅ **Shipped** — nftables post-boot lockdown (v186 adds the pinned self-report sink on 443), kernel hardening (swapoff/kexec/suid_dumpable/core-dump), zeroize of secrets | `egress_lockdown` · `harden_kernel` |

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
