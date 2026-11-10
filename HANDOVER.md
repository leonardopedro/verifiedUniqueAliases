# HANDOVER — paypal-auth-vm security audit cycle (2026-10-20)

Audience: the next LLM/agent continuing the work. Read **AGENTS.md** first for
architecture, threat model, and live-tested API traps; this file is the *state
of play* + *what to do next*. Everything here was verified on 2026-10-20
(UTC times given). **No secrets are stored in this file** — see §6 for where
the real credentials live.

---

## 0. LATEST — v180 cutover + v181 blob-paste cycle (2026-10-24 05:45 UTC)

> §2 below is the **2026-10-20** state (its instance/image ids are STALE —
> AGENTS.md trap "re-list first"). This §0 is current truth. Everything here
> was verified live this session.

### 0.1 Production (cn-beijing) — current inventory

| Resource | ID / value | Notes |
|---|---|---|
| **Prod instance** | `i-2ze4tvkuf12u933nsw8a` (paypal-auth-vm-v180) | `ecs.c9i.large` spot TDX (cheapest shape, $0.012/h), holds the reserved EIP `eip-2zet05jbat6wr6rp7elrc` = 101.200.178.251; system disk **`d-2ze07r378z8o5mjiuxkc`** = 1 GiB `cloud_auto` (size verified after the v181 swap) |
| **Deployed image** | `m-2zegh5k0gouo3xa81mtk` (paypal-tdx-esp-**v181**) | imported from `disk181.raw`; `Features.NvmeSupport=supported` set via flat-wire RPC |
| **Rollback image** | `m-2zed3wq8aubdcddv64az` (paypal-tdx-esp-202610232004) | the v180 image — only these two images remain (9 old ones deleted this session) |
| **Relay — THE working one** | `i-2zed9gkche63zxrzyf9s` (paypal-tdx-relay179e) | **stock Debian 12.15**, 20 GiB `cloud_auto`; stopped in economy mode; re-arm recipe §0.6 |
| **Relay — custom image, cloud-init BROKEN** | `i-2ze19752fjlhw6rf4mpl` (oss-relay-tmp2) | OthersLinux_64 custom image (40 GiB): `user_data` does **NOT** fire even after `ReplaceSystemDisk` with its own image — do not use for transfers (see §0.6) |
| **Deleted this session (cost cleanup, user request)** | `i-2ze686o40uawcau9vt9v` (old prod xlarge "paypal-auth-vm-1g" — Alibaba released it via the preemptible inventory email), `i-2ze7b9txw6v7c7gtrqwt` (legacy "paypal-auth-vm-2" xlarge), + **9 old images** | prod TLS was unaffected throughout |

### 0.2 v181 change — the blob-paste audit fix (user-reported bug)

- **Bug**: pasting the success page's "Copy encrypted report" ciphertext into
  the auditor's report box answered `Audit Failed: Invalid report.` —
  `runAudit()` only understood decrypted envelopes, although the documented
  recovery flow tells users to paste the blob into a trusted auditor.
- **Fix (verify.html v181)**: `runAudit()` detects the sealed-blob shape
  (`ct_b64` + `iv_b64` + `enclave_ecdh_public_key_b64`, no
  `attestation_report`) and calls new **`decryptPastedBlob()`**: refuses
  untrusted origins first (Web Auditor Tampering), restores the session key /
  P_enc pin / client-session binding from `pav_local_session` (fallback
  `pav_client_jwk`), decrypts via the existing fail-closed
  `localDecryptAndVerify` (key-continuity + S_enc signature + GCM auth), and
  persists the plaintext so the 💾 download works. No key in this copy →
  actionable guidance ("claim from the tab where the login started, or audit
  the downloaded attestation-report-*.json"); wrong session / tampered →
  wrapped fail-closed error. Never the cryptic parse error again.
- **Tests**: harness **Test 33** (8 checks: keyed trusted copy → green audit
  + decrypted textarea + persisted download; no key → ENCRYPTED BLOB
  guidance AND absence of the old `Invalid report.`; enclave-origin →
  UNTRUSTED refusal; wrong-session key → `Could not decrypt the pasted blob…`).
  Offline: **174 passed / 0 failed**; with `REAL_REPORT=/tmp/env181.json`:
  **182 / 0**.
- **README digest rotated in the same change**: `verify.html` =
  `b30d6830bafc738c8f0170195a0f8f7d1c330efd58f49ab6e4242310bc34c356`
  (157,602 bytes).

### 0.3 Build + deploy lineage (v181)

| Artifact | SHA-256 | Note |
|---|---|---|
| `output-alibaba/disk-alibaba.raw` | `69c19ec81668b6672e41310c46b9537a22302c7e5037478e2272893552c5b60f` | rebuilt from the same commit — only the ESP's `verify.html` differs from v180 |
| `initramfs-alibaba.img` | `5b27ec2f5596a0be00038ea89f1733db9026dd717fc854ec342d5056cb517d0b` | **UNCHANGED** — verify.html is deliberately not in the measured chain, so the fix rotated no pins |
| binary `paypal-auth-vm` | `23053c650c4bfb88652ebe66cb79a216d66376051666662b5167400bf17a4633` | unchanged; pre-swap `/tmp/env180.json` and post-swap `/tmp/env181.json` carry the identical value |
| `verify.html` | `b30d6830…c34c356` | == README == served file == live ESP manifest entry |

**Cutover timeline (2026-10-23/24 UTC)**: build (podman, exit 0) → presigned
PUT → HK bucket `disk181.raw` (ETag `ED9114BDD85A48984430549B036EA599` ==
local MD5) → Debian relay cloud-init pulled + **Beijing intranet PUT 200** +
readback md5 match (`RELAY181-SUCCESS` in the serial console) →
`ImportImage` (flat `DiskDeviceMapping.1.Format=raw`) → NVMe flag →
prod `StopInstance ForceStop` → `ReplaceSystemDisk --SystemDisk.Size 1`
(verified 1 GiB `cloud_auto`) → `StartInstance` → **TLS 200/ssl=0 in ~2.5 min**.

### 0.4 Verification gate — all green

1. Served `https://login.airma.de/verify.html` sha256 == README digest
   (`b30d6830…`) and the live envelope's manifest entry carries the same hash.
2. `node scripts/check-manifest-parity.mjs https://login.airma.de/debug/envelope
   output-alibaba/disk-alibaba.raw` → **PARITY OK** (6 same, 0 mismatched,
   NvVars excluded by design).
3. `REAL_REPORT=/tmp/env181.json node scripts/test-verify-security.mjs` →
   **182/0** (fresh quote from the NEW deployment through the default Intel
   anchor — MRTD/RTMR/pins all green).
4. **Offline paste-audit** (user request): real Chromium, `file://` copy of
   verify.html, saved `/tmp/claimed-report.json` pasted, button clicked →
   PASS — enclave/tpm/firmware/github rows green, identity = the designed
   SANDBOX warning (the report is a sandbox mint; v177 two-verdict).
5. **Live blob-paste e2e** (the reported bug, end to end): fresh PayPal
   sandbox login → real vault blob fetched (8 keys incl. `ct_b64`/`state`) →
   pasted into the report box → audit button → **decrypted + full green, no
   `Invalid report.`** (`/tmp/e2e-blob-paste.mjs`).

### 0.5 Known-informational (do NOT treat as regressions)

- ✅ **RESOLVED 2026-10-24 (audit round 2, R2-2)**: `EXPECTED_ENCLAVE_SHA256`
  rotated to the live binary `23053c650c4bfb88652ebe66cb79a216d66376051666662b5167400bf17a4633`
  in the same reviewed commit as the README `verify.html` digest (harness
  Test 28/21d). Self-report remains informational by design — code identity
  is decided exclusively by the MRTD/RTMR silicon pins.
- Sandbox-minted reports show `identityCheck = warning` by design (v177).

### 0.6 Relay transfer runbook — what actually works (all hit live)

1. **Re-arm order matters**: `StopInstance ForceStop` → `ReplaceSystemDisk`
   → **then** `ModifyInstanceAttribute UserData` → `StartInstance`.
   A user_data push made BEFORE the swap is discarded with the old disk
   (observed: `DescribeUserData` afterwards = 0 bytes).
2. **`DescribeUserData` can read 0 right after a successful push** — a
   negative read is NOT proof the push failed; the boot is the test.
3. **Only the stock-Debian relay runs user_data.** The custom-image relay
   (`oss-relay-tmp2`, OthersLinux_64) swallowed every attempt even with the
   correct order + its own image. Use `paypal-tdx-relay179e` (stock Debian
   12.15): its cloud-init ran the transfer script on the first try.
4. **Marker trap (re-hit, fix is documented in AGENTS.md)**: a marker written
   with `curl --data` sends **POST** on a PUT-signed presigned URL → 405 →
   the marker silently lands 0-byte/absent. Markers MUST be
   `curl -X PUT -H 'Content-Type:' --data …`. This is why every
   `relay181-s*.txt` was empty while the transfer actually succeeded.
5. **Ground truth when markers lie**: poll `GetInstanceConsoleOutput` WHILE
   the instance is Running — the v181 capture shows `PUT http=200`,
   `ETag: "ED9114BD…"`, `back md5=ed9114bd…` (== local),
   `RELAY181-SUCCESS`. Also `aliyun oss ls oss://paypal-tdx-relay-…/` works
   from the operator host (control-plane-ish) and shows object sizes/ETags.
6. Generate the transfer script fresh near the run (`node /tmp/run-relay181.mjs`)
   — the baked presigned URLs carry a 3 h expiry and the current STS token.

### 0.7 v183 cycle — audit round 3 (payment-flow + side-channel lens, 2026-10-24)

Full write-up: `audit.md` §7 (+ `audit2.md` disposition §7.1, gate evidence
§7.7); status table in `plan.md` ("Status — v183 audit round 3").

| Item | Value |
|---|---|
| **Prod** | same instance `i-2ze4tvkuf12u933nsw8a`, system disk **`d-2zec5a2xx1220rsyeskt`**… replaced again in cycle 2 — current disk id from `DescribeInstances` (1 GiB `cloud_auto` both swaps) |
| **Deployed image** | **`m-2ze1bkloc2r9h98n10z6`** (`paypal-tdx-esp-v183b-*`, NVMe flag set). Rollback: `m-2zegh5k0gouo3xa81mtk` (v181) + `m-2zehcg17z0nhqmmdo8co` (v183 first pass) + `m-2zed3wq8aubdcddv64az` (v180) |
| **disk-alibaba.raw** | **`e0b47124dffb26749478509c3427bb8a5782caedd690bd4a92263ee7b707776a`** (md5 `6362a614…`, object `paypal-auth-vm/disk183b.raw`); first pass `b9292a31…` (`disk183.raw`) |
| **binary** | **`01c74f89d64abca22a2f6ef8c1aaeeb1884c417a8eb3bac447b41e4a8809511d`** — byte-identical in both builds; equals `EXPECTED_ENCLAVE_SHA256` (attestation lands with this commit's CI run) |
| **initramfs** | `ce27d4134c5ead1d23a4d949db41634618cea4ce8daa50bc0ade035a8c1e7934` — CHANGED vs v181 (`5b27ec2f…`, new binary) → **RTMR2 rotated `b7fa8c04… → 61ce2879ea9f31cadf09ba6498104c7501dc0ac7969d4bf1c401ad92585386332fc5cbdb45182a2193f11f71a4a30324`**; MRTD/RTMR0/RTMR1/RTMR3 all held |
| **verify.html** | **`51320e28ce134600ea7a10c6dd15472a4f7656ddacbc48fbc36dd04a6f01517b`** (162,081 B) == README == served == live manifest |

What changed (fixes): **R3-1 PKCE restored** (enclave-held verifier — the
owner holds the PayPal client secret and can observe the redirect code, so
v180's no-PKCE exchange let them read identities in plaintext; auditor now
REFUSES a challenge-less login), **R3-2** egress budget enforced at entry on
`/callback` + `/e2ee-blob`, **R3-3** signed `timestamp_ms` from PayPal's
`Date` (platform clock is +8 h off and provider-controlled; system clock
left alone — justified), **R3-4** console spans log path only (no more
`?code=`/`?state=` on the serial console). audit2.md Step-2 UI rewrite
deviated-with-justification (sample would regress the silicon gates).

Gate results: cargo 20/0 · offline harness **196/0** · live-envelope harness
**204/0** (×2 captures) · `check-manifest-parity` PARITY OK · served==README
· **live PKCE e2e vs real PayPal green** (authorize w/ challenge → consent →
exchange with enclave verifier → blob decrypt → audit rows green; only
`githubCheck` red pre-CI by design). Console-verified transfers
(`RELAY183-SUCCESS`, `RELAY183B-SUCCESS` both with md5 round-trips).

Relay notes re-hit this cycle: **ReplaceSystemDisk requires a Stopped
relay** — a Running relay silently fails the swap while UserData+Start
"succeed" and cloud-init never re-runs (stale console). Order must be Stop →
Replace → UserData → Start. Marker files must be renamed per run
(`relay-ok183b.txt`) or stale ones false-positive. `aliyun oss stat/ls` from
the operator host now 403s (endpoint/CNAME rule) — **serial console is the
ground truth**, as §0.6 says.

### 0.8 v184 cycle — UI simplification (user directives, 2026-10-24)

Status table: `plan.md` ("Status — v184 UI simplification").

User directives: (1) **no pre-flight surface** — the verified-scope PayPal
login itself is the attacker filter; a pre-login hardware-check button only
adds a free VM-resource-exhaustion vector; (2) **verify.html minimal** —
fewest buttons/sections without losing functionality or pedagogy; (3) the
webservice URL field **prefilled** (still editable); (4) the enclave-signed
"Continue to PayPal" link was **invisible** (unstyled anchors → browser
default blue on the dark theme) — fixed with a global anchor style.

What changed in `verify.html` (UI only — engine untouched):

- Deleted: green "Most visitors" explainer card, the "Verify WITHOUT login"
card (fetch-silicon-cert / audit-chain buttons — pre-flight surface), the
"Need help?" card, the "Seeing No valid Silicon Root of Trust?" card (folded
into one fail-closed sentence), and the `tpmCheck` row (no TPM evidence
exists on this TDX platform; informational-only rows are noise).
- Cards 4 → 2 (login / audit); buttons 8 → 5 (claim hidden until a session
  key exists). Labels de-jargonized; "the login IS the pre-flight check".
- `localEnclaveHost` prefilled synchronously at script start (enclave-served
copy → `location.origin`; file:// → production `https://login.airma.de`).
- `claimBtn` lifecycle: hidden → shown on login success / stored session →
  hidden while claiming.
- Harness: tpmCheck assertions flipped to pin the row's *absence*; all other
  security assertions untouched → **196/0**.

Visual-review pass (real Chromium, file:// + full audit with the live claimed
report): the operational walkthrough + fail-safe line lost with the "Need
help?" card was restored as its own scannable **Flow:** paragraph in the
login card; the `tlsCheck` row now renders an explicit amber "optional
cross-check not requested" state instead of a bare state-less placeholder
after paste audits; GitHub row's "Silicon Root row below" → "above" (the
silicon row sits above it); silicon row header lost the removed AMD path →
"Silicon Root of Trust (Intel TDX)". audit.md §7.1 got a v184 footnote (its
round-3 note still said `tpmCheck` stays).

Deployed in TWO passes: `4ec52485…` then **`de52934e…`** (final; md5
`257598d4…`, object `paypal-auth-vm/disk184b.raw`, image
`m-2ze4c305t483i9b5275c`, NVMe flag set) — binary+initramfs unchanged both
times → no pin rotation. Relay legs console-verified (`RELAY184-SUCCESS`,
`RELAY184B-SUCCESS`, md5 round-trips both).

Gates: offline harness **196/0**, live-envelope **204/0**, cargo 20/0,
served == README (`c40d22e204f5ba91c94a461387d804e3347a50044fdd8260fa3b4264f5bca082`),
`check-manifest-parity` PARITY OK, **live PayPal sandbox e2e PASS ×2**
(login → consent → callback → claim → audit green → report downloaded).

---

### 0.9 v185 cycle — independent audit `audit3.md` + maximum UI simplification (2026-10-24)

Full write-up: `audit.md` §7.8 (disposition table + probes + RR-6);
status table in `plan.md` ("Status — v185 audit round 4").

| Item | Value |
|---|---|
| **audit3.md** | Cross-checked section by section: §2/§2.1 (GRUB 2.12 → RTMR2, no-UKI), §3 (pre-flight elimination), §4 (dual-slot zero-wildcard), §6.1/§6.2 (login-session + callback specs), §7 workflow, §8 matrix = **already shipped**; audit3's pin constants byte-match the shipped MRTD/RTMR pins. §5's sample `verify.html` **UI shape adopted, engine NOT replaced** (its single-ID `EXPECTED_PAYPAL_CLIENT_ID` pin would break the full flow and is weaker than the shipped per-flow `EXPECTED_APPS` client_id+scope+authorize_base; its gate rows lack the enclave-signature/provenance/flow/env gates). Its "vestigial manual TLS textareas" **adopted**. |
| **UI (v185)** | Cards **3 → 2** (login / audit), visible buttons **4 → 3** (+contextual claim + PayPal link). The "Strongest: own copy" card duplicated the login flow verbatim (`localPreflight` ≈ `executePreflightAndLogin`): pedagogy folded into the login card, host input moved up (prefilled), button dropped (`localPreflight()` kept — the harness asserts its untrusted-origin refusal; its link write falls back to `#securePaypalUrl`). TLS cert inputs + `tlsCheck` row + runAudit cert block removed; report JSON keeps `tls_certificate_pem`. Results table now **4 rows**. |
| **New live probes** | ✅ **18/0** (`/tmp/audit3-probe.mjs`): S_enc signature, PKCE challenge present, verifier-never-echoed (exact-43-char value scan outside the key/signature blobs), binding echo == our computation + session-specific, per-session state/challenge freshness, signed flow/scope/environment, warm 226 ms (no quote), bogus-state `/e2ee-blob` fail-closed with no leak, envelope cached + TDX quote present. |
| **NEW RR-6 (justified residual)** | Session-time enclave authentication gap: the login-session response authenticates only via its own first-touch P_enc signature; an owner who MITMs the domain can serve a fake session (audited app + THEIR PKCE verifier), capture `/callback`, exchange directly with PayPal and learn identity in plaintext — while the victim's claim fails closed (red, never green). Not fixable without a pre-login hardware quote (the exact DoS surface the user directive removed) and no collusion-proof pre-quote key exists (config keys owner-written, vTPM provider-controlled, TDX silent before `TDG.MR.REPORT`). Scope limited by `EXPECTED_APPS`+scope pins, session-bound slot2, fail-closed claim. | audit.md §7.8 RR-6 |
| **v185 deploy** | disk **`ff5c2dc8…`** (md5 `08e1c084…`, object `paypal-auth-vm/disk185b.raw`, image **`m-2ze9uedflocs2rks2ini`**, NVMe flag set); binary+initramfs unchanged (`ce27d413…`) → **no pin rotation**. Relay: **STS lesson re-hit** — presigned URLs embed the STS token from `~/.aliyun/config.json`, which rotates/expires (~1 h): a script generated ~15 min earlier failed with `SecurityTokenExpired` (relay hangs by design; md5 "mismatch" bodies were 403 XML — their md5 differs per RequestId). **Fix: regenerate the relay script (fresh presigns) immediately before the re-arm**, and check marker files with fresh `oss-url.mjs … GET` URLs (the `GET` verb arg is required — the tool defaults to PUT and yields `SignatureDoesNotMatch`); serial console can lag minutes behind — markers/HK are ground truth. `RELAY185C-SUCCESS` equivalent: markers s1→s2(hk-get-md5-ok)→s3(bj-put-200)→s4(readback-ok)→`relay-ok185c.txt`, fail marker 404. |
| **v185 gates** | ✅ offline **196/0** · live-envelope **204/0** · cargo 20/0 · `check-manifest-parity` **PARITY OK** · served == README == `d9a91a16985e1df30a5849df22d289aa1fbab39b4e96dc451c79b6b270522091` · **live PayPal sandbox e2e PASS ×2 on the merged 2-card UI** (verified AND full-profile buttons: login → consent → callback → claim → green → downloaded). RR-6 scope-limit probe: verified app + PII scopes rejected by PayPal at authorize pre-login (`/tmp/rr6-scope-probe.mjs`, 4 cases). |

### 0.10 v185.1 — TLS-binding restore + v185d prod swap (2026-10-25)

| Item | Value |
|---|---|
| **v185.1 change (user directive)** | TLS Certificate Binding **restored** — v185 had adopted audit3 §5's "vestigial manual TLS textareas" removal, the user overrode it: the audit card regains the optional PEM textarea + file input, `runAudit()` leaf-compares `getLeafCert(pasted)` against `getLeafCert(report.session_context.tls_certificate_pem)`, and with no certificate the row renders the explicit amber "cross-check not requested" state (informational, never gates). README sample output + digest rotated the **same commit**: `verify.html` = **163,150 bytes**, `14a54222d693988a638e252ce18d6abaf4950d31add2d2ae415334e2fae845c2`. |
| **index.html** | Now a **byte-identical mirror of `verify.html`** (GitHub Pages root serves the auditor directly; `cmp` clean). |
| **Build/deploy lineage (v185d)** | disk `output-alibaba/disk-alibaba.raw` sha256 **`75ef77dc7f2a82ead1772afafc0963721c51c2a45f8d1dd79a85901902578597`**, md5 `a87f73f58b78f805ec2bc0fa47480dc6` → HK object `paypal-tdx-relay-1792227992/disk185d.raw` → relay185e legs s1(script-start)→s2(hk-get-md5-ok)→s3(bj-put-200)→s4(readback-ok) + `relay-ok185e.txt`, fail marker 404 → Beijing intranet `paypal-auth-vm/disk185d.raw` → `ImportImage` (flat `DiskDeviceMapping.1.Format=raw`) → image **`m-2ze5hs6tgv7pwfzcuryu`** Available → `Features.NvmeSupport=supported` (hand-signed flat-wire RPC) → prod `StopInstance --ForceStop true` → `ReplaceSystemDisk --SystemDisk.Size 1` → `StartInstance`. binary `01c74f89…` + initramfs `ce27d413…` unchanged → **no pin rotation**; live RTMR0/1/2 identical to the pinned v183+ values. System disk now **`d-2zef7xhigzn43mn4l15n` = 1 GiB `cloud_auto`** (`DescribeDisks` is the API that reports it — `DescribeInstances`/`DescribeInstanceAttribute` return `SystemDisk: null` here). |
| **ACME incident (ZeroSSL route flakiness, not the enclave)** | After the swap :443 stayed dark ≈ **18:45 → 19:49 UTC**: `acme.zerossl.com` was black-holed from the operator host (8–10 s, 0 bytes) and degraded from Beijing — `newNonce` errors first, then `wait_ready`/`order` polls receiving bodies the client could not decode — while a third network fetched the same directory with HTTP 200. The enclave's retry ladder (15 s → 30 s → … → 300 s) rode it out: `ACME certificate obtained in RAM successfully` **19:49:57 UTC**, `HTTPS server listening on 443` at :58, cert `CN=login.airma.de` issued by `ZeroSSL RSA DV SSL CA 2`, valid 2026-10-24 → 2027-01-22. The designed Let's Encrypt fallback (no EAB ⇒ LE directory) was **deliberately not triggered** — no config change was needed, and prod stayed on ZeroSSL+EAB. |
| **Diagnostics runbook additions** | • **Serial console** = `GetInstanceConsoleOutput` (64 KiB head-capped, lags minutes behind): `node /tmp/ecs-call.mjs '{"Action":"GetInstanceConsoleOutput","RegionId":"cn-beijing","InstanceId":"i-2ze4tvkuf12u933nsw8a"}'` → base64-decode. • **Config** = `DescribeUserData` (the `UserData` field of `DescribeInstanceAttribute`/`DescribeInstances` is `null` even when user_data is set — pure red herring). • Prod config has **no `self_report` sink** → the HK `boot/latest.json` boot-status channel is dark; push `self_report` in the next config update for console-free boot visibility. • Plain-HTTP requests with `Host: login.airma.de` from outside mainland get Alibaba's **Beaver ICP-filing 403** page — that interception is NOT the enclave; probe `http://101.200.178.251/` (no Host rewrite) to reach it. |
| **Tooling fixes** | • `scripts/check-manifest-parity.mjs`: **`boot-probe.log` added to the SKIP set** — the enclave appends it to `/boot/efi` at runtime after measurement (`src/main.rs` open-append), so a cold-built image never contains it while every post-boot live manifest does (same uncomparable-by-design class as `NvVars`). First parity run against a *live post-boot* envelope had hit this; after the fix: **PARITY OK** (6 SAME, 2 excluded, 0 mismatched). • Local `cargo test` gate needs `PKG_CONFIG_PATH=/nix/store/7l09089ahshxjx4js3zswqk6azhx6ccq-openssl-3.6.5-dev/lib/pkgconfig` (host has no system openssl dev; that nix store matches the cached link target `/nix/store/kysvfcf8…-openssl-3.6.5/lib/libssl.so.3`). |
| **self_report sink ENABLED (2026-10-24 21:25 UTC)** | ✅ Prod config (user_data) now carries `self_report` → HK bucket `paypal-tdx-relay-1792227992`, prefix `boot`, signed by a dedicated **write-only RAM key**: user `pav-selfreport`, policy `pav-selfreport-put` = `oss:PutObject` on `acs:oss:*:*:paypal-tdx-relay-1792227992/boot/*` ONLY (live-probed: in-scope PUT 200, out-of-scope 403). Pushed via `Stop → ModifyInstanceAttribute --UserData → Start` (readback matched, 5,836 B b64); first boot published `boot/(none)-1792905904-stage.json` + `boot/latest.json` (`schema pav-selfreport/1`, `stage: config`, `ok: true`). **Known gap**: `egress_lockdown()` (main.rs:206) flushes the nftables output chain BEFORE `selfreport::serving()`, so the success heartbeat — and any halt after lockdown — is silently dropped; pre-lockdown stage/ACME-failure/halt docs land (proven by the `boot/prod/*-halt.json` history from 2026-10-23). Fix = sink-IP allow rule in the lockdown set or publishing the heartbeat before lockdown — needs a rebuild + deploy cycle. ✅ **RESOLVED v186 (§0.11)**: `pin_sink_network()` runs before the flush; `boot/latest.json` `serving/ok:true` live-proven twice. Listing needs `aliyun oss ls oss://…/boot/ --endpoint oss-cn-hongkong.aliyuncs.com` (bare `ls` 403s). Config generator `deploy-alibaba.sh` does NOT yet emit `self_report` — next deploy would drop the sink unless wired in. ✅ **RESOLVED 2026-10-26**: the generator now emits `self_report` on every path — key precedence env `SELF_REPORT_*` → §6 mirror `/tmp/pav-ak.{id,secret}` → keep the file's own block; bucket/endpoint/prefix env → file → prod defaults; placeholder credentials and a fully-missing sink both warn loudly. 5-scenario harness green (env inject / mirror inject == prod key `LTAI5t…` / file kept verbatim / placeholder warn / drop warn). |
| **v185.1 gates (2026-10-24 19:5x UTC)** | ✅ offline **196/0** · live-envelope **204/0** (`REAL_REPORT=/tmp/live-report.json`) · cargo **20/0** · `check-manifest-parity` **PARITY OK** · served == README == local == `14a54222…` (163,150 B) over https **and** http/IP · **live PayPal sandbox e2e PASS ×2** — verified (19:56:43) AND full (19:57:31) buttons: login → consent → callback → claim → green → downloaded. |

---

### 0.11 v186 cycle — audit round 5 (`audit5.md`) + heartbeat fix + max UI simplification (2026-10-25)

Status table: `plan.md` ("Status — v186 audit round 5").

| Item | Value |
|---|---|
| **Self-report heartbeat survives lockdown (queued directive)** | ✅ `egress_lockdown()` now calls `selfreport::pin_sink_network()` BEFORE flushing the output chain (DNS still open; 3 attempts, IPv4 only) and adds `ip daddr {…} tcp dport 443 accept` for exactly those addresses; `put()` pins the reqwest resolver (`resolve_to_addrs`) so post-lockdown publishes need **no DNS** — deliberately NO `udp 53` reopen (no query-channel exfil; payload stays secret-free, signed per request by the write-only RAM key). **LIVE-PROVEN twice**: `boot/latest.json` = `{"kind":"ok","stage":"serving","ok":true}` on the v186a AND v186b boots (uptime_s 112 / 157 — published after lockdown; pre-fix this doc never landed). Source-pinned by cargo `selfreport_survives_egress_lockdown_v186`. |
| **Two more audit fixes (fresh pass, collusion lens)** | ✅ **session-time FLOW substitution**: the enclave signs whatever flow label the (adversary-owned) request path delivered — substituting `verified → full` passed signature + app-pin + PKCE (the full app IS in EXPECTED_APPS) and was only caught by the audit-time FLOW ESCALATION *after* the PayPal consent; the auditor now refuses before the authorize link exists. **512-byte `custom_info` cap on BOTH ends**: `canonical_custom_info()` (login-session → 400, forged callback state → invalid_session; auditor check now counts `TextEncoder` BYTES — 514 B refused pre-fetch); the field was unbounded while charged 4 KiB (≈256× budget bypass) and parkable in the 32 KiB-charged vault. **Identity row**: painted green only after `sigOk` (a forged report used to show a green Identity row beside the red signature row; now failed + explained). |
| **UI (user directive: BOTH login buttons + 5 result rows kept)** | ✅ One `.grid` (was two), login card 3 → 2 paragraphs (content preserved), single status line; dead `localPreflight()` deleted (5.8 KB duplicate of `executePreflightAndLogin`, zero UI callers — harness's untrusted-origin assertion moved to the claim path) + `preflightUrl`/`localPaypalUrl` fallbacks. verify.html **163,150 → 158,202 B**, `242b033e…` == README == served == `index.html` (byte-identical). |
| **Build/deploy lineage (two cycles — sanctioned rotation procedure)** | Cycle A: disk **`643f013e…`** (md5 `5f7925aa…`, HK `disk186a.raw`) → relay186a green in 2.2 min (s1→s4 + `relay-ok186a.txt`, md5 round-trip) → Beijing intranet → `ImportImage` (flat `.Format=raw`) **`m-2zefiag79exwggjl8z0m`** + NVMe flat-wire RPC → prod Stop → ReplaceSystemDisk → **config re-pushed** (user_data is disk-bound — §0.6 quirk) → Start → TLS 200 in 2.3 min → `/debug/envelope` → **RTMR2 rotated `61ce2879… → 99c5322df676198c0b9aa86dd0e9ea63062f36b16c2609a4c5160033650236bcf161581d6047513411d9f1aa0ae25d13`** (MRTD/RTMR0/1/3 byte-held; live binary_sha256 == pin `68281d24…`). Cycle B: rebuild **byte-identical** binary `68281d24…` + initrd `1af2c963…` (RTMR2 stable — reproducible Docker synthesis, both shas re-checked) carrying the rotated verify.html on the ESP → disk **`66befe70…`** (md5 `58815d45…`, `disk186b.raw`) → relay186b green in 2 min → **`m-2ze5hs6tgv7q4lyymybm`** + NVMe → prod swap (disk `d-2ze5juogkfapt7f97584`, 1 GiB cloud_auto) → TLS 200 05:20:01 UTC. |
| **v186 gates** | ✅ offline **201/0** (196 → 201: +identity-row ×2, flow-substitution ×2, byte-cap ×1) · live-envelope **209/0** (captures from BOTH cycle boots) · cargo **22/0** · `check-manifest-parity` **PARITY OK** (6 same incl. verify.html, 0 mismatched, NvVars excluded) · served == README == `242b033e…` over https **and** http/IP · **live PayPal sandbox e2e PASS ×2** (verified AND full — the full run exercises the flow check symmetrically; e2e claim-status selector updated `#localLoginStatus` → `#secureLoginStatus`). |
| **Ops notes (this cycle)** | OAuth STS in `~/.aliyun/config.json` expires (~1 h) and the presign helpers read it directly → dead token = `InvalidAccessKeyId`; **ONE `aliyun …` call re-mints it** (config rewritten with a new expiration). `DescribeImageAttribute` is NOT a valid CLI action — use `aliyun ecs DescribeImages --ImageId …`. Relay re-arm order re-confirmed (Stop → Replace → UserData → Start) + fresh presigns generated immediately before each arm. Rollback images kept: `m-2zefiag79exwggjl8z0m` (A), `m-2ze5hs6tgv7pwfzcuryu` (v185d). Relay stopped in economy mode after each leg. |
| **Residuals (unchanged, justified)** | RR-6 session-time enclave authentication gap (audit.md §7.8 — no collusion-proof pre-quote authenticator exists without the removed pre-login DoS surface) · UKI deferral (GRUB 2.12 → RTMR2 live-proven) · sandbox/staging deployment (loud two-verdict model) · GitHub-outage provenance row advisory · self-report informational-only (code identity = silicon pins exclusively). audit5.md disposition in plan.md. |

---

### 0.12 v187 cycle — single workflow button + callback download (2026-10-25)

Status table: `plan.md` ("v187 — single workflow button").

| Item | Value |
|---|---|
| **User directives** | (1) ONE button in verify.html that changes text+action through the flow — sequence **verified round THEN full-profile round**; the PayPal link REPLACES the button and its click swaps in the next button; (2) the /callback landing page must offer **download**, not only copy; (3) rebuild + two-cycle deploy to ship it; (4) live e2e both flows; (5) harness pin for the callback button. Supersedes v186's "BOTH login buttons kept" choice. |
| **verify.html v187** | `#workflowBtn` state machine (`start-verified → to-paypal → claim → start-full → to-paypal → claim → done`), `setWorkflow`/`renderWorkflow`, resume via `pav_local_session` + new `pav_wf_stage`; `claimBtn` + inline login handlers removed; link moved into the button's slot (`onclick=setWorkflow('claim')`); card copy “Flow (one button)”. index.html byte-identical mirror. e2e `full` flow now starts via `#login-full` (the full button only exists after round 1). |
| **main.rs v187** | CALLBACK_CONTENT gains **💾 Download encrypted report (.json)** (Blob+anchor over the rendered ciphertext textarea) beside 📋 Copy (kept — Test 33's pinned fallback); heading “Copy or download your encrypted report”. Feeds the trusted auditor's file picker → v181 decrypt path. |
| **Build/deploy lineage (two cycles)** | Cycle A: disk **`a6f87f39…`** (md5 `be942e28…`, HK `disk187a.raw`, ETag==md5 from operator host) → relay legs green (Cloud Assistant RunCommand, exit 0, `RELAY187A-SUCCESS`) → Beijing intranet → `ImportImage` **`m-2ze37tjptqghwkcqt7i7`** + NVMe flat-wire RPC → prod Stop → ReplaceSystemDisk (`d-2ze15nhjh4dusfeif2l2`) → **config re-pushed (5,836 b64, disk-bound §0.6)** → Start → TLS 200/ssl=0 in ~3 min → envelope → **RTMR2 rotated `99c5322d… → 153b4f71a24635e7c383b201604fa364ab87771c43e3f024cef537c412c301a81b3d9e90b4532595810daa7f282b01a0`** + EXPECTED_ENCLAVE_SHA256 `68281d24… → cebf46eb…` (commit `42920ed`), MRTD/RTMR0/1/3 byte-held. Cycle B: rebuild **byte-identical** binary `cebf46eb…` + initrd `7e26d4e8…` (RTMR2 stable live-proven) carrying the rotated auditor → disk **`aad98b9f…`** (md5 `2995abb8…`, `disk187b.raw`) → relay green → **`m-2zeidtvqcw46h2ypl6f0`** + NVMe → prod swap (disk `d-2ze8qrvt5fqcuxl40kuu`, 1 GiB) → TLS 200/ssl=0 ~1.8 min → envelope B **pins byte-match A**. |
| **v187 gates (final, on the B deployment)** | ✅ offline **221/0** (+Test 36 ×9 workflow states, +Test 37 ×6 callback download) · live-envelope **229/0** ×2 (fresh quotes from BOTH boots) · cargo **22/0** · `check-manifest-parity` **PARITY OK** (6 same incl. verify.html, 0 mismatched, NvVars excluded) · served == README == local == **`3030363a…`** over https **and** http/IP · **live PayPal sandbox e2e PASS ×2** (verified AND full — step `6b. callback download button count: 1` proves the main.rs change is on prod) · heartbeat `boot/latest.json` `ok/serving` (11:21:41Z, uptime 129 s). |
| **Ops notes (new traps hit + fixes)** | The stock relay was GONE (deleted in this morning's storage cleanup) → recreated fresh from public `debian_12_15_x64_20G_alibase_20260916.vhd`: `RunInstances` needs BOTH `--SecurityGroupId` (else `InvalidSecurityGroupId`) and `--VSwitchId`+`--ZoneId` (else `OperationDenied.InvalidNetworkType`); vsw `vsw-2zemsk0m5ky2j6uttlk82`, sg `sg-2zehehuvi1f0v67q11bo`. Transfer used **Cloud Assistant RunCommand** instead of user_data (no re-arm dance): `RunCommand --ContentEncoding Base64` (there is NO `--CommandEncoding` flag), poll with `aliyun ecs describe-invocation-results --biz-region-id cn-beijing --invoke-id <id>` (PascalCase `DescribeInvocationTasks` is NOT in this CLI's API list; kebab flags for kebab commands; `Output`/`CommandContent` come back base64). `--InstanceIds` on DescribeInstances silently returns empty here — list + filter client-side (AGENTS trap re-hit). Relay `i-2ze7j6czd1qmzaeeaca7` **deleted after the legs** (cost discipline). ossutil 2.2.1 reinstalled project-local `build-scripts/bin/ossutil` (gitignored) — stat **and** cat both work on the HK bucket from the operator host; needs the STS token passed (`--sts-token`, mode OAuth). |

Run an independent end-to-end security audit of the project, of the **live
report + `verify.html` flow**, and **fix findings in a cycle until no security
flaws remain (or cannot be fixed with justification)**.

Threat model (the user's exact framing):

> The cloud provider (Alibaba) **and** the owner of the webservice
> `login.airma.de` **cannot be trusted and can collude with each other**.

Corollaries used when judging findings: everything *self-reported* by the
enclave or *hosted* by the webservice is attacker-controlled; only hardware
roots (TDX/TPM quotes), CI Sigstore provenance, and auditor-local computation
may be trusted. Round 1 classified every report field along exactly those lines
before fixing (Phase A of the audit).

---

### 0.13 v188 / v188.1 cycle — ZK escrow layer + audit round 2 (F1–F6), three-cycle deploy (2026-10-25 22:1x UTC)

**Findings fixed this round (collusion model: provider + login.airma.de owner):**

| # | Finding | Fix |
|---|---|---|
| F1 | A LOGIN report with no client-session fields fell through to the zero-slot (non-login) branch in paste mode — an owner-crafted/legacy zero-slot report audited green | verify.html: login-shaped + no binding anywhere ⇒ hard reject ("no unverified quote slots"); harness negative test |
| F2 | `index.html` (GitHub Pages root) carries a byte-identical auditor that had already diverged from `verify.html` | Harness **Test 40**: byte-parity gate + node --check; re-synced |
| F3 | **No HSTS** on any response — a colluding network keeps victims on plaintext http:// forever | `with_secure_headers()` now sends `strict-transport-security: max-age=31536000` (deliberately no includeSubDomains/preload — can't vouch for other airma.de subdomains); source-pinned in Test 28 |
| F4 | `zkVerifyCredential` built its statement from **untrusted summary fields** — a valid Groth16 proof over a DIFFERENT identity/bit-0/other escrow key could be displayed as the audited identity | All summary fields (identity hash, verified bit, ephemeral pubkey, ciphertext, escrow key) now bound to the PROVEN `raw[271]` signals; 6 negative tests |
| F5 | The 105 MB zkey cannot be pushed to GitHub (>100 MB object limit; release assets send no CORS) | Published SPLIT (`zk/*.zkey.part{0,1}` 60+45 MB, Pages serves ACAO:*); browser reassembles + pins ONE sha256; `build-zk.sh` regenerates parts; assembled file gitignored |
| F6 | **Live-e2e blocker**: the v188 handoff link re-ran `executePreflightAndLogin` on EVERY click — the PayPal-opening click navigated with state #1 while state #2's fresh nonce overwrote `pav_client_nonce`/`pav_local_session`, so the callback ciphertext (sealed to #1) failed GCM auth (every real login) | Prepared link (href contains `authorize`) returns immediately — click just navigates; +4 harness regression checks |

**Also shipped**: the whole ZK selective-disclosure subsystem (circom.md, circuit 200,818
constraints, local ceremony, lazy SRI-pinned snarkjs, embedded vkey, artifact sha256
pins, `zk-decrypt-escrow.mjs`, Tests 38/39) and the v188 flow (callback auto-download
+ window.close, two explicit login links, no claim step; e2e tooling updated).

**Deploy: THREE cycles (RTMR2 rotated once, then byte-held):**

| Cycle | Image / disk | Notes |
|---|---|---|
| A | `m-2zegh5k0goup4x432oai`, disk `7d8781b7…` (md5 `1f12e2f4…`) | binary `3f684786…` + initrd `26c891b2…`; live envelope ⇒ **RTMR2 `153b4f71… → 09e22230…`**, MRTD/RTMR0/1/3 byte-held; EXPECTED_ENCLAVE_SHA256 rotated pre-build (offline — sha of the built binary, no boot needed) |
| B | `m-2ze8vh5ynx2z7pn4e55c`, disk `3caf960d…` (md5 `8d71df42…`) | rotated auditor (`98d3196a…`) on ESP; RTMR2 held live-proven; prod swap disk `d-2zed9gkche659r9nva2u` |
| C | `m-2ze7zy0u7fv3shpcrxw0`, disk `366c1f6e…` (md5 `92c2fc89…`) | **F6 auditor (`0eb6324f…`, 238,881 B)** on ESP; swap disk `d-2zeitwv66qbu50hvb3u9`; no pin rotation needed (binary/initrd byte-identical ⇒ ESP-only change) |

**Final gates (on the cycle-C deployment):** served == README == local == **`0eb6324f…`** ·
`check-manifest-parity` **PARITY OK** (6 same incl. verify.html, 0 mismatched) ·
live-envelope harness **294/0** · offline harness **286/0** · cargo **22/0** · zk witness
R1CS PASS · real groth16 prove/verify PASS (2.7 s) · **live PayPal e2e PASS ×3**
(verified + full after F6, + final verified smoke on cycle C) · HSTS + full header set
live · CI runs (f2b0ddf, 65b99ca, 2ab7560, bacb725) all **success**.

**Runbook deltas (all hit live):** `RunCommand` needs `--InstanceId.1` (indexed
RepeatList; bare `--InstanceId`/`--InstanceIds` both fail); BOTH OSS buckets now refuse
the **public endpoint** entirely (`PublicEndpointForbidden`) — uploads = presigned PUT
(vhost style; path-style → `SecondLevelDomainForbidden`) to HK, relay pull, Beijing
**intranet** PUT, ETag==MD5 on both hops; `import-alibaba-image.sh` gained
`SKIP_OSS_UPLOAD=1` for that staging; relay used: `i-2zefiag79exwsshidi3z`
(debian_12_15, zone cn-beijing-i, sg `sg-2zehehuvi1f0v67q11bo`, vsw
`vsw-2zemsk0m5ky2j6uttlk82`) — **stopped in economy mode after the legs** (restart:
`aliyun ecs StartInstance`). Staging objects `disk188{,b,c}.raw` remain in the HK
bucket (≤147 MB, cents/month; data-plane delete is geo-blocked from the operator).

**Traps:** `scripts/e2e-sandbox.mjs` is STALE (navigates to `/login`, which does not
exist since v180 — 404); the working tool is `scripts/e2e-login-download.mjs`
(`VERIFY_HTML=… CHROMIUM_PATH=… node scripts/e2e-login-download.mjs verified|full`).
A second local clone exists outside this worktree (parallel `m` commits; its push was
rejected once as non-FF — reconcile it with `git fetch && git rebase origin/alibabacloud`
before pushing from there).

**Branch restructure 2026-10-26 (Pages trust-path fix):** GitHub Pages deploys from
`main`, which had been frozen at the **v164 era** (`67f5952`, verify.html sha
`2f397676…`) since work moved to `alibabacloud` — the README-documented trusted
remote copy was serving a stale auditor that REDs on current reports. Per user
direction: old tip preserved as **`oldmain`** (`67f5952`, recoverable), then
`alibabacloud` force-pushed onto `main` (lease-guarded). Verified live:
`leonardopedro.github.io/verifiedUniqueAliases/` now serves `verify.html`
`0eb6324f…` (238,881 B, byte-identical to worktree), `index.html` `b35ff106…`,
`zk/identity_escrow_vkey.json` `18063c00…` — all matching repo `e548856`.
CI on `e548856` = **success**. Note: `refs/heads/zk/…` release-style refs are
absent locally (`git log --remotes` misses them); fetch explicitly if needed.

**Post-cycle ops round (2026-10-26 06:17–07:11 UTC — three user requests):**
- **Pages-served e2e PASS ×4/4**: `e2e-login-download.mjs` now accepts a full
  `https://` `VERIFY_HTML`; drove the pinned Pages auditor through the live
  PayPal flow before the reboot and after each fresh boot — auto-download →
  paste-decrypt green → plain-report download every time.
- **F6 proven gone in production at the network layer**: the e2e now counts
  POSTs to `/attest/login-session` and FAILS unless exactly 1 — **1 ✓ on
  every instrumented run** (the old race minted a second, racing round whose
  nonce overwrote the one PayPal carried). Combined with the 294/0 harness
  (offline F6 regression) the fix is covered on both ends.
- **`self_report` always wired into `deploy-alibaba.sh`** (§0.10 gaps marked
  resolved): key precedence env `SELF_REPORT_*` → `/tmp/pav-ak.*` mirror →
  the config file's own block; placeholder and fully-missing sink both warn
  loudly. 5-scenario harness green (env inject / mirror inject == prod key
  `LTAI5t…` / file kept verbatim / placeholder warn / drop warn).
- **Fresh boots green ×2** (relay188 started; prod `RebootInstance`, then a
  `Stop → Start`): strict TLS `200 verify=0` (ZeroSSL chain) ~90–150 s after
  start on both, heartbeat `boot/latest.json` `stage=serving ok=true`
  (uptime 435 s / 110 s) published post-lockdown on both — the sink fires on
  every boot. e2e #4 (final boot) PASS with single-prepare ✓.
- **Serial-console trap EXTENDED (AGENTS updated)**: `GetInstanceConsoleOutput`
  on prod returns the SAME stale 64 KB buffer across Reboot AND Stop→Start —
  0 bytes while Stopped, then the OLD pre-stop capture back byte-identical
  within 10 s of Start. Fresh-boot console for this instance is unobtainable;
  use the heartbeat. `RunCommand` on prod → `Aborted` (no agent, by design);
  relay `RunCommand` works — flags `--CommandContent` / `--Timeout` /
  `--InstanceId.1`.

---

### 0.14 v190 cycle — ZK FastFile fix + TLS-cert download + callback warnings + authority escrow key (2026-10-26)

Status table: `plan.md` (v190 row). Four user requests, all shipped and live-verified.

| Item | Value |
|---|---|
| **User requests** | (1) bug report: the ZK button showed `❌ Invalid FastFile type: undefined`; (2) the webservice must let the user **download the TLS PEM certificate** with instructions, preferably BEFORE "Login with PayPal" (question: does the page go to PayPal directly or via my IP?); (3) the auto-closing callback page must **warn** that the download is in progress, that the page closes itself, and that the file must then be uploaded in the previous (local) tab; (4) verify.html must have a **text field + file picker for an authority's public key** (e.g. law enforcement) that can read the escrowed attestation, used when generating the proof. |
| **Fix 1 — ZK crash (root cause found + fixed)** | snarkjs's fastfile accepts ONLY `Uint8Array`/string/`{type}`: the raw `ArrayBuffer` from `fetch()` falls through to `o.type` and throws `Invalid FastFile type: undefined`. `zkFetchArtifact`/`zkFetchZkey` now cache **and** return `new Uint8Array(buf)` (caching the bare buffer broke cache *hits*). Reproduced offline against REAL snarkjs: ArrayBuffer → the exact live error; Uint8Array → proof in 2.8 s, 271 signals, `groth16.verify` vs the committed vkey **true**. The mocked harness prover could never see this — new Test 39 pin asserts the FastFile type. |
| **Fix 2 — TLS cert download** | New `GET /tls-cert.pem` (`serve_tls_cert`): serves `state.tls_cert_pem` (the same RAM copy the report records as `session_context.tls_certificate_pem`) as `application/x-pem-file` + `Content-Disposition: attachment`, `ACAO:*` (public handshake bytes, no credentials), charged 4 KiB to the caller's egress budget, **503 before ACME**. verify.html gains a collapsed block **above both login links**: download button + 3-step instructions (save → load into the audit's "Browser TLS certificate" picker → inspect with `openssl x509`/`openssl s_client`, doc link), and it answers the routing question in-page: the cert download connects only to the enclave address, while the PayPal login is a **direct** browser→PayPal connection (the authorize URL is built client-side from the S_enc-signed `authorize_base`; PayPal then redirects to the enclave's `/callback`). |
| **Fix 3 — callback page** | `CALLBACK_CONTENT` now warns in order: **1/3 download in progress**, **2/3 this page auto-closes itself** (live countdown `<span id="autoclose-secs">`), **3/3 once closed, upload the file in the PREVIOUS (local) `verify.html` tab** — plus, if the browser blocks `window.close()`, an amber fallback telling the user to close by hand and upload in the previous tab (was a silent dead page). |
| **Fix 4 — authority escrow key** | New paste `<textarea id="zkAuthorityKey">` + `<input type="file" id="zkAuthorityKeyFile">` in the ZK card. `zkParseAuthorityKey` accepts `x y`, labelled `x: … y: …`, JSON `[x,y]` / `{"x","y"}` / `{"pubkey":[x,y]}` and **fails closed** on PEM/RSA input, non-decimals, out-of-field coordinates and off-curve points (`zkPointOnBabyJub`, a=168700 d=168696 over BN254 — params verified against circomlibjs); the key is written into the escrow x/y fields and **re-validated inside `zkGenerateCredential`** (a raw paste with no blur still binds; a bad key dies before any constraint is proven). It reaches the proof as `escrow_pubkey` — a public signal the verifier cross-checks, so the recipient cannot be swapped after the fact. |
| **Pins rotated (sanctioned procedure)** | `scripts/calculate-golden-rtmr.mjs --report <live /debug/envelope> --update`: **EXPECTED_RTMR2 `09e22230… → 0fda7c8a5318d6c8fb9b3246695bb6774b973c11d3089c3654c006f6837e4f6f7895116f15af44e9141aebb662ab4079`**, **EXPECTED_ENCLAVE_SHA256 `3f684786… → d1e288c688ccf81a7519994f6698282d2678a58eb8eed0835011f832236e56ab`** (live self-report == `sha256sum paypal-auth-vm`); MRTD / RTMR0 / RTMR1 / RTMR3 byte-held. README auditor pin → **`204391e4…` (251,884 B)**; index.html re-synced. |
| **Build/deploy lineage (two cycles)** | Cycle A: disk **`eccb2ec6…`** (md5 `6ea8a819…`, HK `paypal-auth-vm/disk190.raw`, ETag==md5 from the operator host via presigned PUT — `aliyun oss cp` hits the endpoint-addressing 403) → relay190 green in **12 s** (`relay-ok-v190.txt`: `PUT200 verified-by-readback ok`) → Beijing intranet → `ImportImage` (flat `.Format=raw`) **`m-2ze0ma3y1b26qrv9zfag`** + NVMe flat-wire RPC → **new spot instance `i-2zed3wq8aubeph9na28i`** (ecs.c9i.large TDX, prod's exact user_data 5,837 b64 incl. self_report) → EIP dance → TLS 200/ssl=0 at t+120 s. Cycle B: rebuild **byte-identical** binary `d1e288c6…` + initrd `eb90872a…` (RTMR2 stable — reproducible Docker synthesis, both re-checked) carrying the rotated auditor → disk **`717d064c…`** (md5 `c05e27ec…`, `disk190b.raw`) → relay190b green in 40 s → **`m-2ze07ji23vhpxmu8xdch`** + NVMe → prod Stop → `ReplaceSystemDisk` (flat RPC) → disk `d-2zefhqk47a20eil89yzt` → **user_data re-pushed** (disk-bound §0.6) → Start → TLS 200/ssl=0 at t+180 s → **live RTMR2 byte-matches the new pin**. |
| **v190 gates (final, on the cycle-B deployment)** | ✅ harness **317/0** (new Test 41 ×8 cert route/UI, Test 42 ×18 authority key incl. an end-to-end prove bound to the pasted key; Test 35 re-pinned to the committed `deploy-alibaba.sh` — its stale patterns already failed at HEAD) · cargo **22/0** · real-snarkjs prove+verify **PASS** · served == README == local == Pages == **`204391e4…`** · `/tls-cert.pem` 200 (3-cert ZeroSSL chain, `CN=login.airma.de`) and its **leaf SHA-256 fingerprint equals the one inside a live login report** · heartbeat `boot/latest.json` `{"ok":true,"stage":"serving"}` (uptime 169 s, published post-lockdown) · **live PayPal sandbox e2e PASS** — callback auto-download fired on the new page, audit green with the rotated pins, report downloaded, **F6 single-prepare = 1**. |
| **Ops notes (new traps hit + fixes)** | (a) **`import-alibaba-image.sh` imports `paypal-auth-vm/$(basename "$DISK_FILE")`** — staging bytes under a different object name (e.g. `disk190.raw` while the script's disk is `disk-alibaba.raw`) silently imports the **STALE** object (bit me: image `m-2zec5ky7ny552uckp02l`, never deployed). Fix without re-staging: `cp disk /tmp/<the-staged-name>.raw` and run with `DISK_FILE=/tmp/<that-name>.raw SKIP_OSS_UPLOAD=1`. (b) `ecs-call.mjs` VPC actions need `_version=2016-04-28` (default 2014-05-26 → `InvalidVersion`). (c) `AssociateEipAddress` rejects an instance in `Stopping` (`InvalidStatus.NotAllow`) but accepts `Stopped`; the enclave has no ACPI handler, so a `RebootInstance` issued while the instance had just lost its auto public IP hung in `Stopping` for 5+ min → force-stop → bind EIP → start. (d) Marker polling must use `curl -sf`: OSS returns an XML `NoSuchKey` BODY with the GET, which reads as a marker otherwise. (e) `ReplaceSystemDisk` flags `--SystemDisk.Category/Size` are rejected by CLI 3.3.15 → flat RPC. |
| **State left behind** | prod = `i-2zed3wq8aubeph9na28i` (Running, EIP 101.200.178.251, 1 GiB `cloud_auto` disk `d-2zefhqk47a20eil89yzt`, image `m-2ze07ji23vhpxmu8xdch`); previous prod `i-2ze4tvkuf12u933nsw8a` **Stopped** (rollback — EIP removed; start + re-associate to restore); `relay188` **Stopped** (self-stopped after the legs). The stale-object image `m-2zec5ky7ny552uckp02l` was **deleted** (2026-10-26, user-approved). ⚠️ **Policy deviation (user reviewed + accepted)**: cycle A went through `deploy-alibaba.sh`, which **launches a new Confidential VM** (then EIP role-swap) — the Instance & Disk Policy mandates in-place `ReplaceSystemDisk` on the existing instance. Functionally equivalent (same c9i.large/zone/VPC/SG, byte-identical user_data, 1 GiB disk, EIP attached, e2e green) and the original instance is preserved as the rollback; cycle B then did an in-place rewrite on the new box. Decision: **keep the new instance as prod**; consolidate back only via the documented EIP role-swap + in-place rewrite if the original ID matters again. |

---

## 0.15 v191 follow-ups — ESP auditor refresh, `luks.key` dropped, captured-report gate (2026-10-26)

Three user requests issued while the v191 deploy cycle was in flight (rows
1-3), plus the follow-on verification they triggered (row 4). All verified
this session.

| Item | Value |
|---|---|
| **1 — ESP `verify.html` carries the rotated ZK pins** | `build-alibaba-image.sh` `mcopy`s `./verify.html` onto the ESP, so the refreshed tree is what ships. Verified end-to-end: **served `https://login.airma.de/verify.html` == GitHub Pages == `index.html` (byte-identical) == README == local** = **`84d9ec41f233d7ba96b411865ed53ca8ca09d984246c7b99c19de6ab94bbee4c`** (261,710 B); that file's `ZK_WASM_SHA256 = b8ce562f…585e8d` and `ZK_ZKEY_SHA256 = e320086d…27365` **byte-equal** `sha256sum zk/identity_escrow.wasm` and `sha256(cat zk/*_final.zkey.part{0,1})`. `check-manifest-parity.mjs` against the live `/debug/envelope` + `output-alibaba/disk-alibaba.raw` → **PARITY OK, 6 same incl. `verify.html`, 0 mismatched, NvVars excluded** — the deployed ESP is exactly this tree. Deployed `binary_sha256 = d1e288c6…` == `EXPECTED_ENCLAVE_SHA256` in verify.html. |
| **2 — `luks.key` dropped (user directive) + volume audit** | **Audit: nothing uses it.** The 512 B blob (sha256 `f6a551da9375ff8b66a83c792241fc5fbf201a631bf8d201f2bfc476c79fa5f9`) was added in `818e953` (2025-11-26) and deleted the next day in `b9e5cf6` with the whole dracut-era stack. It is on **no branch tip**, and `git grep luks.key` across **every** ref (sh/mjs/rs/yml/md/json/toml) returns **zero** references. Byte-scan of all four images (`output-alibaba/disk-alibaba.raw`, `output-relay/disk-relay.raw`, both `initramfs-*.img`): the `LUKS\xba\xbe` hits are **not 512-B-aligned** and sit inside GRUB/cryptsetup **string tables** (`Invalid LUKS2 JSON header`, `crypto_LUKS.DM_integrity`) — there is **no LUKS1/LUKS2 header** anywhere (no JSON `"keyslots":`/`"segments":`/`"pbkdf":` marker in any image), and `cryptsetup`/`luks` appears in no package list. Cloud side: all **144** objects in `paypal-tdx-relay-1792227992` → **0** matching `luks`/`.key`; the image bucket listing is blocked by the known `PublicEndpointForbidden` endpoint quirk, but its objects are md5-verified copies of the local `disk*.raw` already scanned. **Disposition:** a replacement was generated (512 B, mode `600`) and then **discarded — no rotation, no committed digest**. With zero consumers it would have been dead material. `.gitignore` keeps a `*.key` guard (the historical blob is what burned it, not the missing file) so the original mistake cannot recur; a future LUKS consumer must mint its own key and pin it where the volume actually reads it. The historical blob is still in git history and therefore burned; treat it as public. |
| **3 — harness gate on a CAPTURED odd-length report** | New **Test 45** (9 checks) in `scripts/test-verify-security.mjs`, fixture `scripts/fixtures/captured-odd-report.json` (sandbox `verified` flow, saved live capture). Test 44 proves a *synthesized* 251-byte identity; Test 45 proves the identity **extracted from the capture** through the **REAL** `snarkjs.groth16.fullProve` + `verify` against the committed vkey: canonical order (`user_id, sub, verified_account, payer_id`) → **len 251 (odd)**, in band, `sha256 == ` the report's own signed `paypal_user_info_raw_hash` (`53dd6264…48c81`), 271 signals, `verified_account_bit = 1`, and the credential **decrypts back to the exact captured bytes**. This closes the report→identity extraction path (key order / null handling / UTF-8), not just the circuit. `zkProverPaths()` hoisted so Tests 44/45 share the wasm/vkey/zkey-part resolution. **Harness 348/0 → 357/0, exit 0.** |
| **4 — live e2e re-run + a Test 22 assertion bug found by it** | ✅ **Both flows PASS** against the deployed enclave via the maintained driver `scripts/e2e-login-download.mjs` (`CHROMIUM_PATH=$(command -v chromium)` — Playwright's own headless shell can't launch here: 22 shared libs missing, Nix profile chromium 155 used instead). `verified` **and** `full`: login session ready → PayPal sandbox consent → `/callback` auto-download fired → **audit green** → report downloaded → **F6 single-prepare = 1**. Fresh capture: `flow=verified`, identity **len 251 (odd)**, in band, `sha256 == ` the signed `paypal_user_info_raw_hash`. ⚠️ `scripts/e2e-sandbox.mjs` is **STALE — do not use**: it navigates to `GET /login?flow=…` and clicks a `form[action="/generate"]`, neither of which exists in the current router (`/`, `/verify.html`, `/attest/login-session`, `/debug/envelope`, `/tls-cert.pem`, `/callback`, `/e2ee-blob`). It last predates v187. **Test 22 fix**: with `REAL_REPORT=<live capture>` the harness reported `364/1` — `live audit returns true — alert=null`. Root cause: **not a security failure**. verify.html v177 deliberately returns the string **`'sandbox'`** (not `true`) for a sandbox deployment and downgrades `identityCheck` to the SANDBOX IDENTITY warning, so `ok === true` fails on *every* genuine sandbox report. Rows were `enclave✓ github✓ firmware✓ identity⚠(by design) tls⚠(informational)`. Assert now: verdict **matches the declared `paypal_environment`** (`'sandbox'` ⇔ sandbox report, `true` ⇔ production) + the downgrade text is present. **357/0 plain (CI path, unchanged) · 367/0 with `REAL_REPORT`.** Not a regression from the v191 work — that commit's hunks start at lines 2793/2818/2886 and `verify.html` is untouched (`84d9ec41…` == README). |

---

## 0.16 v192 cycle — callback no auto-close (TLS-cert export window) + RTMR2/enclave-pin rotation, two-cycle deploy (2026-10-26)

User request: the `/callback` page must **stop closing itself** — it is the
only place where its own TLS certificate can still be exported from the
browser's certificate panel. Rotated pins + cycle-B swap follow the §0.14
sanctioned procedure. All gates below ran on the deployed cycle-B build.

| Item | Value |
|---|---|
| **Callback change (`src/main.rs` `CALLBACK_CONTENT`)** | Auto-close machinery **deleted** (the 3 s `__secs`/`__timer` countdown, `window.close()`, the blocked-close fallback notice — all gone; `autoclose-secs`/`autoclose-notice` ids removed). Step **2/3** is now the cert-export walkthrough (Chrome/Edge padlock → *Certificate is valid* → Details → Export PEM; Firefox → View Certificate → Save PEM; Safari → drag out) plus the explicit warning that `/tls-cert.pem` **can never disagree with the report** (same party serves it — not an independent source). Step **3/3** loads **both** files in the previous local tab ("Attestation JSON report" + "Browser TLS certificate" pickers). An amber `cert-reminder` sits **above** the ✖ button; the manual `window.close()` button (v187 fallback) stays. Rationale in-code: no page can read its own connection certificate from script, so closing the tab destroyed the one channel a hostile host cannot fake. **Test 37 rewritten** (8 checks): no-countdown/no-timer pins, manual close retained, per-browser export text, `/tls-cert.pem` non-independence, both-file step 3, reminder-above-button ordering. |
| **Pins rotated (sanctioned procedure)** | From the cycle-A live `/debug/envelope`: **EXPECTED_RTMR2 `0fda7c8a… → ae57a30457fe3305c080c0f43fe785762ec39e74b78aa2e57c47cb6742b52e86917e8ca44ff51f3fbe6cf4713a85c640`**, **EXPECTED_ENCLAVE_SHA256 `d1e288c6… → b0dd61804936a6068e3a69961f7d83b5a4acec49817bc5a1138e7316c81f8d4e`** (== live envelope `binary_sha256` == `sha256sum paypal-auth-vm`); MRTD / RTMR0 / RTMR1 / RTMR3 byte-held. `verify.html` **and** `index.html` (byte-identical) carry both; README `verify.html` digest rotated **in the same commit** → **`c450eedb6ff2a071d108102244dd3665c5f7638b44b6f5a9799a125f7e44551c`** (261,710 B). |
| **Build/deploy lineage (two cycles)** | Cycle A: `build-alibaba-docker.sh` → relay → Beijing → `ImportImage` → prod swap → live envelope captured (the rotation source). Cycle B: rebuild **byte-identical** — binary **`b0dd6180…`** and initrd **`529358c9…`** re-verified identical (reproducible Docker synthesis ⇒ RTMR2 holds; only the ESP disk differs, which is the point: rotated auditor on it) → disk `output-alibaba/disk-alibaba.raw` (49,283,072 B) → relay green → imported as **`m-2ze27p6937asuzw3afy8`** → prod `i-2zed3wq8aubeph9na28i`: `StopInstance ForceStop` → flat-RPC `ReplaceSystemDisk` (new disk **`d-2zef7xhigzn56li445oa`**) → **user_data re-pushed after the swap** (HTTP 200; §0.6 order — a push before the swap is discarded) → `StartInstance` → Running in 25 s → **HTTPS 200 at t+210 s**. Envelope reports `binary_sha256 = b0dd6180…`, `platform_type = Intel TDX`, `tdx_quote_source = configfs_tsm`, `tdx_quote_status = ok`. |
| **v192 gates (all on the deployed cycle-B build)** | ✅ harness **360/0 plain (CI path) · 370/0 with `REAL_REPORT=/tmp/claimed-report.json`** (a fresh login capture — Test 22 needs a report that *declares* `paypal_environment`; the bare `/debug/envelope` legitimately has no such field, which is what made an envelope-fed run show 368/2) · **cargo `--release` 22/0, exit 0** · `check-manifest-parity.mjs` vs live envelope + deployed disk → **PARITY OK, 6 same** (incl. `verify.html`), 0 mismatched, NvVars excluded · **served == repo == README == `c450eedb…`** for `verify.html`, and `/` == `index.html` · heartbeat `boot/latest.json` = `{"ok":true,"kind":"ok","stage":"serving","uptime_s":230}` from the current boot · **live PayPal sandbox e2e PASS ×2** (`e2e-login-download.mjs`, Nix chromium): `verified` (21:25:01Z) **and** `full` (21:25:35Z) — callback auto-download fired on the new page, audit green, report downloaded, **F6 single-prepare = 1**. |
| **CI workflow check** | `.github/workflows/build-attest.yml` parses clean (js-yaml; 1 job, 9 build steps) and its **step 1 is the same harness that just ran 360/0**. Latest 5 GitHub Actions runs on `alibabacloud` = **success** (newest `40362360196`, 2026-10-26 16:46Z) — but those are pre-commit SHAs: **this rotation has not been pushed**, so CI has not yet seen it. Push (user-gated) is what puts the rotated build through the real workflow. |
| **New trap — `cargo test` fails 101 on this host without an OpenSSL pkg-config path** | `openssl-sys` build script: *Could not find directory of OpenSSL installation*. NixOS has no system `libssl-dev`; pkg-config finds no `openssl.pc`. Fix: `export PKG_CONFIG_PATH=/nix/store/7l09089ahshxjx4js3zswqk6azhx6ccq-openssl-3.6.5-dev/lib/pkgconfig` (resolve the store path at run time: `ls -d /nix/store/*openssl*-dev/lib/pkgconfig`) before `cargo test --release`. The stale `/tmp/cargo-test.log` from 2026-10-24 shows the **same** 101 — earlier "cargo 20/0" runs must have had this set. |
| **State left behind** | prod = `i-2zed3wq8aubeph9na28i` Running (image `m-2ze27p6937asuzw3afy8`, disk `d-2zef7xhigzn56li445oa`, EIP unchanged), old prod `i-2ze4tvkuf12u933nsw8a` still Stopped as rollback. Uncommitted at record time: `README.md`, `index.html`, `verify.html`, `src/main.rs`, `scripts/test-verify-security.mjs`, `output-alibaba/disk-alibaba.raw` (cycle-B disk) — committed together as the v192 rotation commit. |
| **🆕 Test 46 — GitHub Pages drift gate (`9a39d29`)** | Found while pushing v192: **GitHub Pages publishes from `main` while the active line is `alibabacloud`**, and Pages hosts both the "GitHub Pages auditor" copy **and** `ZK_BASE` (wasm + both zkey parts). After the rotation Pages kept serving the previous `verify.html` (old RTMR2/enclave pins) while enclave, repo and README all agreed — the Pages link would have failed every audit. Test 46 fetches the Pages copy over raw `node:https` (NOT the stubbed `globalThis.fetch`), compares it byte-for-byte with the working tree, and on mismatch **classifies the cause** from the `pages build and deployment` run + local git: wrong Pages source branch (exact actionable message), rebuild finished-but-stale, or <20-min rebuild-pending grace (logged, counted as pass). Knobs: `PAGES_PARITY=1` = every mode fatal incl. network failure (use in CI/post-deploy), `PAGES_PARITY=0` = skip (offline dev), `PAGES_VERIFY_URL` = override. Harness **362/0** default + strict; negatives verified (stale copy `84d9ec41…` vs `c450eedb…` → exit 1 in both modes; tampered repo digest → the branch-mismatch message fires). |
| **🆕 Push-both-branches rule (permanent)** | Pages tracks **`main`**, CI tracks `main` + `alibabacloud`. So ANY commit that changes `verify.html` (or the `zk/` artifacts) must be pushed to **both**: `git push origin alibabacloud` **and** `git push origin alibabacloud:main` (fast-forward — `main` is not a divergent line, it is the Pages publisher). Pushing `alibabacloud` alone updates CI but leaves Pages serving the old auditor next to correct ZK downloads — exactly the v192 failure. Test 46 fails the suite with that message when it happens; the fix is the one-line fast-forward push. |
| **⚠️ ZK wasm `INTEGRITY FAILURE` in the wild = BROWSER CACHE, not Pages** | A live error `identity_escrow.wasm sha256 6300a547… does NOT match the pinned b8ce562f…` was traced: `6300a547…` is the **v188-era wasm** (`f2b0ddf`, same 2,863,855 B) that Pages legitimately served before the v191 circuit fix rotated it. Cause: `zkFetchArtifact` uses `fetch(ZK_BASE + name, { cache: 'force-cache' })` on an **unversioned URL**, so a copy cached during the old era is re-served after rotation. Pages itself is correct (fresh fetch = `b8ce562f…`), and the gate **failed closed as designed**. Remedy today: hard-reload / clear cached images for `github.io`. Durable fix (needs a verify.html change ⇒ digest rotation + README + ESP rebuild + RTMR2 rotation cycle, **not done yet**): cache-bust the ZK URLs with the pinned digest (`?v=<ZK_WASM_SHA256>`) and say "stale cached copy — hard-reload" in the integrity error. |

---

## 0.17 v193 debug cycle — webservice + verify.html e2e, fix-until-green (2026-10-27)

User request: debug the new webservice + `verify.html` end to end and fix in a
loop until no more fixes are possible. Result: **every gate green; the only
defect found (a favicon 404) was dispositioned by the user as a justified
non-fix — no deploy.**

| Item | Value |
|---|---|
| **v193 change under test** | ZK artifact URLs **versioned by their pin** (`?v=<sha256>`) + the stale-cache “Hard-reload” hint — the durable fix for the v192-era `INTEGRITY FAILURE` incident (a `force-cache` copy of the OLD unversioned URL). Commits `240040a` + `6e01d63` (Test 46 hardening). |
| **Four-copy parity** | local == enclave-served == GitHub Pages == README digest == `index.html` mirror = **`a7e6fdb6a181c27ecce39d7e0b6c50ee1f3472554c55d1b2655af9d080265d54`**; served page carries `?v=` links. |
| **Debug round 1 — HTTP surface** (`/tmp/dbg1.mjs`) | **31/0**: `/`, `/verify.html` (byte-identical to repo, HSTS, HTML), `/debug/envelope` (Intel TDX, binary pin `b0dd6180…`), `/tls-cert.pem` (attachment), legacy `GET /report` + `POST /generate` stay **404**, `GET /attest/login-session` → **405**, empty contract POST + bare `/callback` → controlled **4xx** (never 5xx), HEAD 200, unknown route 404, port-80 Alibaba ICP gate (`403 Server: Beaver`) with HTTPS+HSTS unaffected, all three ZK artifacts fetch **200 from `?v=` URLs with bytes == repo**. |
| **Debug round 2 — real browser** (`/tmp/dbg2.mjs`, Nix chromium) | **16/0**: live report pasted into the enclave-served auditor → `runAudit()` = `sandbox` (declared env), identity/enclave/firmware rows verified, ZK identity stashed; ⚡ Generate ZK credential → wasm + both zkey parts fetched from **VERSIONED** `?v=<64-hex>` URLs on the pinned Pages origin, **no INTEGRITY FAILURE**, proof produced. The v193 fix demonstrably executes in a browser. |
| **Debug round 3 — subresource sweep** (`/tmp/dbg3.mjs`) | Plain `networkidle` load of BOTH origins: no bad responses, no failed requests — the **sole** console error is the favicon 404 (see disposition). |
| **Full gates re-run on the fresh capture** | harness **367/0** plain (CI path) · **377/0** with `REAL_REPORT=/tmp/claimed-report.json` **+ `PAGES_PARITY=1` strict** · `check-manifest-parity` **PARITY OK** (6 same incl. `verify.html`, 0 mismatched) · heartbeat `boot/latest.json` `{"ok":true,"stage":"serving"}` · **live PayPal sandbox e2e PASS ×2** — `verified` (04:46:13Z) and `full` (04:46:49Z): callback auto-download, audit green, report downloaded, **F6 single-prepare = 1**. |
| **Favicon finding + disposition** | `/favicon.ico` → **404 on both origins** (enclave AND Pages): no page declares `<link rel="icon">` — not `verify.html`/`index.html`, not `CALLBACK_CONTENT` (src/main.rs:1067). It is the only console error during load. **User decision (2026-10-27): document, do NOT deploy for it.** Justification: browsers fall back to a default tab icon, zero security impact, and every route outside the v180 router table is *deliberately* 404. Fix path if ever wanted: inline `data:` icon in `verify.html` + `index.html` → ESP-only rebuild+swap (**no pin rotation**, binary/initrd unchanged); silencing it on the transient `/callback` tab additionally needs a `CALLBACK_CONTENT` edit → binary change → sanctioned **two-cycle** RTMR2/`EXPECTED_ENCLAVE_SHA256` rotation. |

---

## 0.18 v194 cycle — verify.html/zk.html SPLIT + the live witness failure fixed (2026-10-27)

Two user requests, shipped together because the second one IS the reason for
the first: the ZK layer needs debugging (a live circom witness failure), and
after the split it iterates on **GitHub Pages alone — no enclave rebuild, no
pin rotation, no ceremony**.

### The split (commit `a499555`, pushed to `alibabacloud` + `main`)

| Item | Value |
|---|---|
| **New `zk.html`** (Pages origin, README-digested) | The WHOLE ZK engine moved verbatim: `#zkCard` (escrow x/y, authority key + keygen, ⚡ prove, credential verify), versioned artifact pins (`?v=`), embedded Groth16 vkey, `zkFetchArtifact`/`zkFetchZkey`, curve math, prove/verify. **Two fail-closed identity loaders** land in the same stash the engine proves from: (1) **postMessage handoff** — accepts ONLY from `https://leonardopedro.github.io`, re-verifies band [248,300] + hash re-derivation + the report's SIGNED `paypal_user_info_raw_hash`, acks `pavZkAck` back; (2) **paste fallback** — the same preimage gate recomputed locally (for file:// auditors and cold opens; a `file://` opener cannot authenticate itself in a message → paste by design). `reportFileText` renamed `zkReportFileText` (each page keeps its own copy — harness co-evals both). |
| **`verify.html` (slim, 261,710 → 177,053 B, `5fd32b9e…`)** | Keeps the GATE: preimage-gate staging + green-audit stash. The card is now `#zkHandoffCard` (revealed ONLY by a green audit) with `#zkOpenBtn` → `openZkProver()`: opens the pinned zk.html, posts `{pavZkHandoff, identityJson, identityHashHex, reportText}` every 250 ms until the ack (pinned origin OUT, pinned origin IN, both fail closed). vkey + engine + ZK constants deleted. `index.html` re-synced byte-identical; README digest table carries BOTH files (byte counts — the first attempt published JS string lengths, caught by the harness size check). |
| **Enclave copy = deliberately STALE (user decision: Pages-first)** | `login.airma.de/verify.html` still serves the pre-split auditor (self-contained, its inline ZK card still works — artifacts unchanged). `served == repo` therefore holds only after the NEXT ESP deploy (one ESP-only cycle, no pin rotation — binary/initrd unchanged). The old inline engine still contains the unreduced-r bug below ⇒ the next ESP deploy is also what fixes the enclave copy's prove path. |
| **Harness** | Co-evals both scripts (verify first, zk second — zk's bindings win, as on the real page). Test 39: handoff card reveal + pinned-link pins + `zkStashIdentity` accept/tamper/wrong-report/refuse-keeps-stash cases. Tests 40/42/43: the auditor copies must NOT carry `zkCard`/`zkCredVkey`/ZK controls (split assertions). Test 46: byte-compares **Pages' `zk.html`** against the repo (the stale-branch trap applies to it too) + reads the artifact pins from `zk.html`. |

### The witness failure — root cause + fix (commit `723e3a0`, pushed both branches)

User's live error, reproduced VERBATIM against the committed build (same
template/instance IDs):

```
❌ Error: Assert Failed. Error in template Num2Bits_103 line: 38
   Error in template BabyPbk_114 line: 97
   Error in template IdentityEscrow_191 line: 267
```

| | |
|---|---|
| **Root cause** | The prove path built the ECDH ephemeral scalar from 32 RAW Web-Crypto bytes (`r ∈ [0, 2^256)`), but the circuit decomposes it with `Num2Bits(253)` — in `BabyPbk` (line 267 `rG.in`) AND `rBits` (line 271). Whenever `r mod p ≥ 2^253` the witness calculator dies at `lc1 === in` (bitify.circom:38). Empirically ~1/3 of browser draws fail (mod-p folding makes some ≥2^253 draws pass — hence intermittent: it hit the user, then passed in 3 of 5 local trials before failing). The mocked harness prover can NEVER see this (HANDOVER lesson re-confirmed). |
| **Fix (input side)** | `var r = zkRandomScalar();` — the page's existing draw (32 bytes → `% ZK_BB_SUBORDER`, refuse 0, retry). SubOrder < 2^253 always, and `R = r·G` is mathematically unchanged by the reduction (`L·G = 0`) so escrow decryption still agrees. **No circuit change ⇒ no rebuild, no new zkey/vkey, no pin rotation** — zk.html + README digest + push to Pages only. |
| **Regression gates (REAL witness calc)** | `zk/test-witness.mjs`: unreduced `2^253+12345` scalar → REJECTED with the documented chain (match on stdout+stderr — snarkjs splits them), reduced scalar → PASS (both new checks green). Harness Test 44: the same two `wtns calculate` checks + source pin `var r = zkRandomScalar();` with no raw 32-byte draw left in `zk.html`. |

### Gates (all on the pushed build)

✅ harness **380/0** (`PAGES_PARITY=1` strict) · **390/0** with
`REAL_REPORT=/tmp/claimed-report.json` · `zk/test-witness.mjs` **PASS** (now
includes the input-contract pair) · **browser split e2e 15/0** (`/tmp/dbg4.mjs`:
Pages auditor green audit → handoff card → popup zk.html accepts+acks → REAL
Groth16 proof from versioned URLs, no INTEGRITY FAILURE; cold zk.html paste
path green + tampered signed-hash refused) · **live PayPal sandbox e2e PASS ×2**
(verified + full, F6 single-prepare = 1) · Pages serves `verify.html`
`5fd32b9e…` + `zk.html` `3f70a1ea…` byte-identical to repo · README digests
match both files · CI runs on `a499555` and `723e3a0` success.

**Builds are byte-reproducible**: `zk.html` is assembled from verify.html's
exact slices by `/tmp/mk-zk.mjs` + `/tmp/zk-glue.js` (ephemeral `/tmp` tools —
if gone, the markers are documented in the commit; every replacement has a
fail-loud guard).

---

## 0.19 v195 deploy cycle — the ESP-only split deploy + the handoff-origin fix the gate caught (2026-10-27)

**The deploy** (user directive: run the ESP-only cycle so the enclave serves
the split auditor). No pin rotation by design: rebuilt binary
`b0dd6180…` + initramfs `529358c9…` **byte-identical to live**, disk
`11ce5b59…` differs from the deployed ESP **only in `verify.html`** (parity
5 same → after deploy `check-manifest-parity` **PARITY OK, 6 same, 0
mismatched**). Chain: HK staging `paypal-auth-vm/disk194.raw` (ETag==md5) →
relay188 RunCommand hop (HK GET → Beijing **intranet** PUT → read-back md5
verified, `relay-ok-v194.txt`) → `ImportImage` (flat `--DiskDeviceMapping.1.Format`,
task `t-2ze27p6937at3pm0vvrs`) → image **`m-2ze27p6937at3pm0763t`** Available
→ flat-wire RPC `Features.NvmeSupport=supported` (verified in DescribeImages)
→ prod in-place swap: `StopInstance` → `ReplaceSystemDisk` → system disk
**`d-2ze15nhjh4dvrs1ghwi4`** (20 G cloud_auto) → **user_data byte-identical to
the pre-swap backup (5,836 B b64 — no re-push needed this cycle)** → `StartInstance`
→ TLS 200 at ~t+180 s. **§0.18's prediction is now discharged: `served ==
repo == README` for `verify.html` = `5fd32b9e…`** — the enclave copy is the
slim split auditor.

**The gate caught a real defect** (first run of `/tmp/dbg5.mjs`, 9/1): zk.html's
handoff origin gate (`ev.origin !== 'https://leonardopedro.github.io'`) dropped
every postMessage from the enclave, so the deployed auditor's "⚡ Open the ZK
escrow prover" button ALWAYS spun out its 10 s timeout and forced the manual
paste path. **Fix (commit `c076e01`, pushed `alibabacloud` + `main` → Pages
`1beb6b78…`)**: `ZK_HANDOFF_ORIGINS = [Pages, https://login.airma.de]` — the
measured enclave is a pinned opener; `zkStashIdentity` still re-verifies every
handed-over identity fail-closed (band, hash re-derivation, SIGNED raw-hash)
regardless of origin. Pages-only change: **no enclave rebuild, no pin rotation**
— exactly what the split was built for. README `zk.html` row rotated same-commit
(**111,684 B, `1beb6b78…`**). Regression measurement (dbg4 stress, same day):
the OLD raw 32-byte scalar draw failed **6/20 (30%)**, the fixed `zkRandomScalar`
draw **10/10** + **5/5** consecutive browser proves (~3.3 s each).

**v195 final gates (all on the deployed cycle build)** · harness **380/0** plain
· **390/0** strict (`REAL_REPORT` + `PAGES_PARITY=1`) · `check-manifest-parity`
**PARITY OK** (6 same incl. verify.html) · served == repo == README
`5fd32b9e…`, Pages `zk.html` == repo `1beb6b78…` · heartbeat `boot/latest.json`
`{kind:ok, stage:serving, uptime_s:181}` from the current boot · dbg1 HTTP
surface **34/0** (section D re-pointed at the split's zk.html) · dbg4 Pages split
**18/0** (handoff-seeded proof + 5× prove + tampered-hash refused) · **dbg5
enclave-copy split 14/0** (handoff ACKED from `login.airma.de`, real proof,
versioned `?v=` fetches, paste fallback green) · **live PayPal sandbox e2e PASS
×2** (verified 09:06:41Z + full 09:07:18Z, F6 single-prepare = 1) · CI on
`c076e01` pushed both branches.

---

## 0.20 v195b — `zk-rsa.html`: an RSA ZK escrow prover for PGP/S-MIME keys (2026-10-27)

User request: an ALTERNATIVE zero-knowledge proof generator (separate file)
that works with the RSA keys used on encrypted police/whistleblower mail.
Scope confirmed via choice cards: **escrow credential like zk.html** ·
**pure-JS Fiat–Shamir, no trusted setup** · **PGP/GPG + X.509/S-MIME + raw
n/e** input formats.

| Item | Value |
|---|---|
| **New `zk-rsa.html`** (repo root + Pages, 51,405 B, `ce763e20…`) | Parses OpenPGP v4 transferable keys (old+new packet formats, CRC24 armor check, fingerprint = `SHA1(0x99‖len16‖material)`), X.509 certs (DER→SPKI), PKCS#1/PKCS#8 PEM, raw `n=/e=` — all hand-rolled, no library. **Proof = Guillou–Quisquater Σ-protocol, Fiat–Shamir over SHA-256**: `t = w^e`, `c = H(domain‖nonce‖purpose‖fp‖idh‖ciphertext‖g‖t)`, `z = w·(g^d)^c`; verify `z^e ≡ t·g^c (mod n)`. Private exponentiation runs OUTSIDE any circuit (CRT, ~ms). Escrow = hybrid RSA-OAEP-SHA256 + AES-256-GCM to the recipient; `identity_hash` public and challenge-bound. **Honest no-circuit caveat in-UI + as a warning row**: plaintext↔hash tie completed by the RECIPIENT after decrypt (the in-page binding checker does it). Passphrase-protected secret keys refused by design (export guidance in the UI). **Zero network by construction** — no external scripts/fonts/artifacts (system font stack, unlike zk.html's Google Fonts), asserted by the e2e. |
| **`zk/rsa-test/` fixtures** | TEST-ONLY RSA-2048 pair: PKCS#8 + self-signed X.509 + raw lines + hand-packed PGP pub/sec armors (no gpg on the build host — `mk-pgp.mjs` packs v4 packets, s2k usage 0, CRC24; fingerprint round-trip verified against the fixture generator's own value) + `gen-fixtures.sh`. Fixture README states the keys are throwaway. |
| **Harness Test 47** (21 checks) | Co-evals the page script (everything `zkRsa`-prefixed → no collision with verify/zk): five-encoding agreement on one fingerprint, PGP fingerprint shape, 2048-bit floor, public-key-can't-prove, **s2k-usage-flip ⇒ PASSPHRASE-PROTECTED refusal**, prove→verify green with expected nonce/domain, no-circuit caveat row present, tamper refusal ×4 (nonce/ciphertext/z/modulus), expected-mismatch flagged, escrow round-trip + attrs + wrong-key rejection, README digest current, no external subresources. |
| **Browser e2e `/tmp/dbg6.mjs`** | file:// run **19/0**, Pages-origin run **18/0**: real UI parse→prove→verify (zero failed rows)→binding decrypt (attrs recovered)→tamper red row→4 formats via the page parser→**no request outside the page origin**. |
| **Gates** | harness plain **401/0**, strict (`REAL_REPORT`+`PAGES_PARITY=1`) **411/0** · Pages serves `zk-rsa.html` byte-identical (`200:51405`, `ce763e20…`) · dbg1 **34/0** (regression canary; its section D was re-pointed at the v194 split earlier today) · commit `de973e2` pushed `alibabacloud`+`main`. |

Threat-model note carried in the page itself: a key typed into any web page
is only as safe as the machine rendering it (Tails/Tor Browser guidance,
unencrypted-session-key export command, delete-after-use) — the tool never
sees a passphrase and never makes a request.

---

## 0.21 v197 cycle — Police-escrow SECOND download (PGP-sealed copy) + two-cycle deploy (2026-10-28/29)

User request: at `/callback`, alongside the E2EE ciphertext, emit a **second,
PGP-sealed copy of the attestation addressed to the police (BKA) key** so the
recipient can open it with plain `gpg --decrypt` — no browser, no ECDH.

### What shipped (commits `e94f305`, `4662475`, `f69f86f`, pushed `alibabacloud` + `main`)

| Layer | Detail |
|---|---|
| **Enclave** `src/main.rs` `mod pgp_escrow` | Armor dearmor + CRC-24, OpenPGP packet/MPI parsing, encrypt-capable **subkey** selection (`0x04\|0x08` → last subkey → primary), then a real OpenPGP message: **PKESK v3** (PKCS#1 v1.5 of `0x09‖sk‖checksum`) + **SEIPD v1** (zero-IV AES-256-CFB-128, **no** §13.9 resync, SHA-1 MDC). **No new dependencies.** Wiring: `pgp_recipient` on `POST /attest/login-session` (validated fail-closed, egress-charged, ≤16 KiB), armored key parked in a bounded TTL `pending_pgp` table retired only on a successful exchange (PKCE semantics), **recipient fingerprint signed into `signed_fields`** (substitution defense), `/callback` mints `pgp-sealed-attestation.json` next to the ciphertext. A failed seal only warns — it never blocks the primary attestation. |
| **Clear fields by design** | `paypal_user_info_raw_hash` (signed identity hash) + `paypal_id_sha256` (SHA-256 of the raw PayPal id, captured before `minimized` moves) sit in **clear** so anyone can match the sealed file to the plain attestation without reading it. |
| **Auditor** `verify.html` (⇒ `index.html`) | Prefilled `#policePgpInput`, `pgpPublicFingerprints()` (same SHA-1 rule as the enclave), key sent as `pgp_recipient`, and the **signed fingerprint re-checked against the pasted armor BEFORE PayPal** (`ESCROW KEY SUBSTITUTION` aborts; a missing fingerprint from a pre-v197 enclave warns instead) + the callback page's second auto-download box with copy/manual fallback. |
| **Deliberate deviation** | The sealed JSON does **NOT** claim `"recipient": "Bundeskriminalamt (BKA)"` — the box accepts any key, so that label could be false. It ships `recipient_fingerprint` + `recipient_target_fingerprint` (both verified by the e2e) instead. |

### Verification

- `cargo test` **25/25**, including `gpg_interop_roundtrip_or_skipped` — gpg 2.4.9 decrypts our message **and** our parser handles a gpg-produced one (the test caught two real bugs: session key zeroized before SEIPD used it, and a `key_flags` port that read the length octet as the subpacket type).
- `npm test` harness **420/0** (baseline 412 + 8 escrow checks). README digest/size rotated **in the same commit** (Test 28 rule): `verify.html` = `8c1b5c42b241d9acc4a6b6ac86618e2e479f5dd021efd0c6a6275575187516d1`, 186,117 B.
- **Live e2e both flows PASS** (`scripts/e2e-login-download.mjs`, extended to assert the 2nd download): type `pav-pgp-sealed-attestation/v1`, `recipient_fingerprint` == fingerprint computed from `police-bka-pub.asc`, clear `paypal_user_info_raw_hash` == the signed report's (addressing proof, needs no private key), `idHash` = `17a1022f…`, ct 34,195 B. Captures: `/tmp/pgp-sealed-attestation.json`, `/tmp/claimed-report.json`.

### Build + deploy lineage (two cycles, in-place disk rewrites ONLY — no instance was ever created)

| Artifact / pin | Value |
|---|---|
| `output-alibaba/disk-alibaba.raw` (49,283,072 B) | `5c1c1ba867de06e5cf141987065f8bf0923cb2dc759b631131757a816c7b6529` |
| `initramfs-alibaba.img` | `92b1476ad990c0e90812bb1df4b9677938587a6ae2f8e3445dee67b2d1ec7e6c` |
| binary (`EXPECTED_ENCLAVE_SHA256`) | `b0dd61804936…` → **`11932297902a4cdc05607c3d5444222c6af918786af17d9bc90512fa21c064c2`** (rotated `4662475`) |
| `EXPECTED_RTMR2` | `ae57a30457fe…` → **`86784f375604fceecadaf02ebf4556c7ef397103cbbc852ba7f1cb832fe8461ef1f4f49a1dd72228bf61a528680d0e8f`** (rotated `4662475` from the cycle-A live envelope) |
| `EXPECTED_MRTD` / `RTMR0` / `RTMR1` / `RTMR3` | **byte-held** (no rotation — cycle B rebuilt the binary + initramfs bit-identical) |
| Deployed image | `m-2zef5rtftylwooqx1a9b` (cycle B; cycle A's image superseded) |
| Prod instance | `i-2zed3wq8aubeph9na28i` (paypal-auth-vm, created 2026-10-26 — **untouched by this cycle**) |
| Prod system disk | `d-2ze5juogkfarmx5c16hr`, 20 GiB `cloud_auto`, created 2026-10-28T18:32:07Z by the cycle-A `ReplaceSystemDisk` |
| Relay | `i-2zefiag79exwsshidi3z` (relay188), Stopped + `StopCharging` after both legs |
| Parity | `node scripts/check-manifest-parity.mjs https://login.airma.de <disk>.raw` → **PARITY OK** (deployed ESP == report, incl. `verify.html`) |

**Transfer legs** both green: presigned PUT → HK bucket, relay `RunCommand`
(HK GET → Beijing intranet PUT, ETag/md5 verified), `ImportImage`
(`DiskDeviceMapping.1.Format=raw`), flat `Features.NvmeSupport=supported`,
then `Stop` → `ReplaceSystemDisk` → `Start` on the SAME instance with the
user_data preserved. Second relay marker: `relay-ok197b`.

### Incidents & gotchas hit this cycle

1. **Cycle B booted dark for ~13 min**: self-report `stage=acme,
   reason="acme: error decoding response body"` (ZeroSSL hiccup). The ACME
   retry loop recovered on its own — first live sighting of that exact reason;
   no action taken, none needed.
2. **`ReplaceSystemDisk --SystemDisk.Size=1` fails** with
   `InvalidSystemDiskSize.ValueNotSupported` — the documented irreversible
   overshoot from an earlier cycle. Kept at 20 GiB `cloud_auto` rather than
   role-swapping instances (role swap = new instance, which the operator has
   forbidden). NOTE: the disk image itself is only 47 MiB, so 1 GiB would fit
   — the refusal is a platform-side floor on shrinking, not an image-size issue.
3. **`DescribeUserData` returns `UserData` as a bare string** in CLI 3.3.15,
   not `UserData.Value` (and it needs `--RegionId`), and `DescribeDisks` wants
   the SINGULAR `--InstanceId` while `DescribeInstances` wants the plural.
   ECS tagging is exposed as `add-tags` (kebab-case), not `CreateTags`.
4. **Two disk ids exist in the account and only two** — `ReplaceSystemDisk`
   always mints a new system-disk id (that IS the in-place rewrite) and the
   old one is released; no stray disks and no new instances were created.

### New this cycle: `watchdog/` — self-healing replacement (code done, deploy BLOCKED)

`watchdog/` implements the operator's request: an idle serverless function
that notices the enclave is **released** (spot eviction) and keeps trying
until an equivalent confidential VM exists. FC 5-minute timer **+**
EventBridge rule on `ecs:Instance:StateChange` /
`PreemptibleInstanceInterruption` / `SystemFailure.Delete`, both feeding one
idempotent `ensure()`. It **never touches a Stopped instance** (operator
safety), never steals a bound EIP, and uses an hour-bucketed `ClientToken` so
retries cannot fan out into several boxes. 13 unit tests green
(`node watchdog/test-watchdog.mjs`).

**Blocked on two account-level gates (hit 2026-10-29):**
- `CreateFunction` → `AccessDenied: Current user is in debt overdue.` — FC
  will not provision until the account's overdue balance is settled.
- EventBridge → `ServiceNotEnable` — the event bus product is not activated.

Already done and persisting across re-runs: RAM user `pav-watchdog` + policy
`pav-watchdog-ecs` + access key (`/tmp/pav-watchdog-ak.json`, 600), the
`pav-watchdog=prod` tag on the enclave, `dist/config.json` (captured spec +
`user_data` + delivery token, gitignored), the built package
(`dist/pav-watchdog.zip`). **Resume with `bash watchdog/deploy-watchdog.sh
deploy`** once the balance is settled and EventBridge is activated.

### Full private-key proof of the sealed copy (2026-10-29)

The BKA key has no private half in this repo (correctly — it is the recipient's),
so the proof was run against a **fixture key whose secret we hold**, through the
LIVE enclave:

1. `gpg --quick-generate-key` fixture (`5BD70750F05476878CDC71B1F7181F4BF4F6E4B2`,
homedir `/tmp/pav-fixture-gpg`, pub exported to `/tmp/pav-fixture-pub.asc`).
2. New e2e override: `PAV_E2E_PGP_KEY_PATH` (paste that key into
   `#policePgpInput` instead of the page's prefilled BKA key) +
   `PAV_E2E_SEALED_OUT`. Live run **PASS** — status line showed
   `🚔 Police escrow ON → 5BD70750…`, sealed copy captured to
   `/tmp/pgp-sealed-fixture.json` (ct 33,837 B).
3. `gpg --decrypt` → **`encrypted with rsa2048 key, ID F7181F4BF4F6E4B2`**,
   24,612 B plaintext, exit 0. Then **10/10 consistency checks**:
   plaintext `attestation_report` == the auditor-decrypted report; clear
   `paypal_user_info_raw_hash` == the value inside == SHA-256 of the canonical
   identity preimage (`{user_id, sub, verified_account, payer_id}` — the
   struct order, not the report's alphabetical json! order); clear
   `paypal_id_sha256` == SHA-256(`user_id`); `binary_sha256` inside == pinned
   `11932297…`; `verified_account: "true"`; recipient == target == fixture
   key; and **MRTD/RTMR0/1/2 all present byte-for-byte inside the signed TDX
   quote** in that plaintext, matching verify.html's pins.

Note: `zk/rsa-test/signer-sec.asc` (hand-packed by `mk-pgp.mjs`) is **rejected
by gpg** (import exits 2, nothing stored) — it is fine for the Rust parser
tests but useless as a gpg decrypt fixture. Generate fixture secrets with gpg.

---

## 0.22 v199 cycle — escrow TARGET now signed + Alibaba-priced egress budget, two-cycle deploy (2026-10-29)

Two requests, one deploy cycle each of them needing the same pin rotation:

1. **Auditor must verify the sealed copy's PKESK key-id against the SIGNED
   escrow target.** The e2e caught the real bug behind the request: the
   enclave signed `r.fingerprint` (the **primary**, `081910AD…`) while
   `build_sealed_report` encrypts to `r.target.fingerprint` (the **encryption
   subkey**, `183BA8C8…`, key-id `7DE765EF79EFF86C`) — so there was no signed
   value the ciphertext could be matched against. `main.rs` now signs the
   target (`ParsedRecipient::target_fingerprint()`); the auditor reads the
   PKESK (OpenPGP tag 1) recipient key-id straight out of the armor and
   requires **ciphertext key-id == file-declared target == S_enc-signed
   target**, fail-closed on every disagreement (rewritten clear field,
   hostile reseal, missing signature, anonymous zero key-id, non-PKESK first
   packet). The signed target is remembered in `pav_local_session.pgpTargetFp`
   at prepare time.
2. **Egress protections re-priced for Alibaba.** The caps were GCP-era
   leftovers. Live EIP facts (`DescribeEipAddresses`):
   `PayByTraffic` · BGP · cn-beijing · **5 Mbps peak** · bound to the ECS
   instance (no config fee); price **¥0.80/GB, egress only, billed hourly**;
   saturated line = 2.20 GB/h ≈ ¥1,270/month (the bill the caps exist to
   prevent). Caps are now *derived*: `¥30/month ÷ ¥0.80/GB ÷ 730 h` →
   `GLOBAL_EGRESS_BYTES_PER_HOUR = 55,157,970` (52.6 MiB/h) and per-IP
   `÷13` = 4,242,920 B/h (4.05 MiB/h ≈ ¥2.34/month per client). The window stays
   exactly 1 h to match Alibaba's billing period, and the FIRST rejection of
   each window logs one `warn!` (bounded so a flood can't bury the 64 KiB
   serial console).

### Verification

- `cargo test` **26/26** — new `egress_budget_matches_alibaba_price_v199`
  pins the price/budget/line-rate arithmetic (a tweak that silently unbounds
  the ¥30 ceiling fails the test).
- `npm test` harness **422 passed / 1 failed** — the 1 is Test 46 (GitHub
  Pages byte-parity), red only until this commit is pushed and Pages rebuilds.
  New **Test 48**: 10 checks over `zk/rsa-test/sealed-sample.json` (a real
  gpg-produced ciphertext to the BKA key, committed as a fixture).
- **Live e2e PASS** (`scripts/e2e-login-download.mjs`, extended with the
  sealed-paste step): status now shows `Police escrow ON → 183BA8C8…` (the
  TARGET), the audit is green, the report downloads, single-prepare holds,
  and step 10 reports
  `✅ Police-escrow copy ADDRESSED CORRECTLY — the ciphertext's PKESK key-id is
  7DE765EF79EFF86C, exactly the last 16 hex of the S_enc-signed escrow target
  183BA8C8492359736B9E015E7DE765EF79EFF86C`.

### Build + deploy lineage (two cycles, in-place disk rewrites ONLY)

| Artifact / pin | Value |
|---|---|
| Cycle A `disk-alibaba.raw` (49,283,072 B) | `e1bce1d847e871cc17f0e4a6b6496a8a4bc0c6effc2b59b3cba968a790fcb40c` (md5 `afb998080833d9ae59adf529098d558e`, HK `paypal-auth-vm/disk199a.raw`) |
| Cycle B `disk-alibaba.raw` | `3382e9ef65d4dba1ea84f55f79d98a998f475642b8c8c6c3293bb0e9d4678485` (md5 `81d9eebfbeefbe6a2c407e09b800f49a`, HK `disk199b.raw`) — differs from A **only** by the rotated `verify.html` on the ESP |
| binary (`EXPECTED_ENCLAVE_SHA256`) | `11932297902a4cdc…` → **`4933005adfbebbfcf586dda87640f6d9c83f720c4794869fbe701165ed11900f`** — built twice, byte-identical both cycles |
| `initramfs-alibaba.img` | `73f30b13cfb8702b3072296d174584a732fe85d1ea70cb2d7ebad3ded373b2e3` (both cycles) |
| `EXPECTED_RTMR2` | `86784f375604fce…` → **`e79cce72a685c9459c0a31e740e3ca0fcfd9321087d6dbd90a148903272895d9575b7bd2433c84d253080df5f23293fc`** (cycle-A live envelope; cycle-B live envelope **byte-matches** it) |
| `EXPECTED_MRTD` / `RTMR0` / `RTMR1` / `RTMR3` | **byte-held** (MRTD `e0199499…`, RTMR0 `06a32a2f…`, RTMR1 `6fa03523…`, RTMR3 zeros) |
| `verify.html` | `dd18e9b50b97eeda7f7661bcfab63bc8d68599bd53d556105e5b7ee828c36323`, **195,027 B** (README table + `sha256sum` block rotated in the same commit; `index.html` re-synced) |
| Images | A `m-2ze34rkx4y8pl6ve0wag` → B **`m-2ze2z92s2ewrax782f2i`** (both `Features.NvmeSupport=supported` via the flat RPC) |
| Prod system disks | A `d-2zecfx57tvws37hbb8eh` → B **`d-2ze58xtopd0s2o4g5fjr`** (20 GiB `cloud_auto`, `SystemDisk.Size=20` sent explicitly) |
| Parity | `node scripts/check-manifest-parity.mjs https://login.airma.de output-alibaba/disk-alibaba.raw` → **PARITY OK** (6 same, 1 excluded `NvVars`; live `disk_manifest.verify.html == dd18e9b5…`) |

### Gotchas hit this cycle

1. **The self-report prefix is `boot/`, not `boot/prod/`** — the old
   `boot/prod/latest.json` object still exists (a 2026-10-23 heartbeat) and
   reads as a stale `stage=config`, which looks exactly like "the new boot is
   stuck at config". Poll `boot/latest.json`.
2. The serial console stayed the frozen 64 KiB pre-stop buffer again —
   `LastUpdateTime` advanced while the content was days old. Self-report +
   `curl https://…/` were the only live signals (as documented).
3. A `set -e` script where a node one-liner dies mid-way silently skips the
   steps after it — cycle B's first attempt never re-pushed `user_data` or
   started the instance. Re-run the tail steps explicitly and verify the
   readback (`DescribeUserData` → 5836 b64 chars).
4. Generating the relay script with `python3 … || node -e` mangled the file
   (no python3 here; env vars were not exported). Generate with node only and
   check `bash -n` + `grep -c undefined` **before** base64-ing it into
   `RunCommand`.
5. `aliyun oss ls oss://bucket/boot/` (object listing) is 403 even on the HK
   bucket — only presigned GETs work; bucket-level `aliyun oss ls` is fine.

---

## 2. Where things stand right now (2026-10-20 14:30 UTC)

### 2.1 Code & CI — round 1 complete, all green

| Item | State |
|---|---|
| Audit Phases A–C (threat-model map, verify.html, enclave OAuth/session) | ✅ done |
| Round-1 fixes | ✅ committed as **`6a99f0e`** and pushed |
| CI run for `6a99f0e` (API id 39355523083, UI "run 283") | ✅ every job/step green, incl. the **83-test harness gate** and the new *Attest ESP Boot Chain* step |
| CI run for `0e15b7a` (API id 39384204004 — the user's disk commit "m", pushed 07:04 UTC) | ✅ **success** — same digests re-attested |
| Attestations resolve unauthenticated | ✅ via `https://api.github.com/repos/<owner>/<repo>/attestations/sha256:<hex>` (path form — this is exactly what `verify.html` calls) |
| Local artifacts == CI-attested digests | ✅ `sha256sum` verified: disk `00963ad57d0e6a99f9f784652835dc7e2baf36e9996bcdc80e81a37786c6daf9`, binary `ebe9fa31465c314f8ed25f86171ab45f4fb343cd821e5da2296ef0d235822226`, initrd `ab97b8edb69e9e21065cf80828829e1ecfccc8b7bbb147a8ae4fb4398527361e`; also shim `10b44fae…` (30 attestations) and grub `6db42071…` (30) |
| **T1 · E2E live, both flows** | ✅ 2026-10-20 ~09:2x UTC — `verified`: consent auto-completed, callback+state accepted, report captured, page shows `verified_account: true` / `No name, email`; `full`: report captured, page shows the identity markers. Round-1 CSRF cookie + PKCE exercised against real PayPal. Reports: `/tmp/report-verified.json`, `/tmp/report-full.json` |
| **T2 · Live harness** | ✅ **90 passed / 0 failed** with `REAL_REPORT=/tmp/report-verified.json` (83 offline + 7 live: TDX silicon root vs pinned Intel root, nonce binding, MRTD, provenance, TPM-less tpmCheck) |
| **T3 · Console PII = 0** | ✅ no identity string reaches kmsg (code audit: every log macro PII-free, explicit "no payer_id in the log" design comment at the verified-flow handler); live `verified` report contains **0** identity strings (the `full` report contains them by design). Serial-console spot-check remains a manual ECS-VNC step (no headless API) |

What round 1 changed (files):

- `src/main.rs` — OAuth hardening: **CSRF cookie + PKCE** (`code_verifier`,
  `state = <flow>.<nonce>`, pending-flow map with TTL). Config→callback wiring
  verified: `pending.flow` holds a short token that round-trips through
  `get_flow_config(&flow)` (`"verified"`/`else → "full"`).
- `verify.html` — MRTD/RTMR pinning, code & session pins, **app pins** (v180: no pre-login attestation — the login-session call is bookkeeping only)
  (`full = ARDDrFepkPcuh-…`, `verified = AZXkzMWMioIQ-…`), boot-chain
  provenance (shim/grub digests), injection re-sweep.
- `.github/workflows/build-attest.yml` — attests **shim + grub** as subjects;
  gates the build on `node scripts/test-verify-security.mjs`.
- `scripts/test-verify-security.mjs` — grown to **83 tests / 0 failures**
  (includes a REAL live-report test driven by `REAL_REPORT=…`).

Test commands:

```bash
node scripts/test-verify-security.mjs                       # 83 offline tests
REAL_REPORT=/tmp/report-verified.json node scripts/test-verify-security.mjs   # + live report
node scripts/e2e-sandbox.mjs                                # drives both OAuth flows headlessly
```

### 2.2 Production (Alibaba, cn-beijing) — ⚠️ STALE (2026-10-20), ids superseded by §0

| Resource | ID / value | Notes |
|---|---|---|
| **Production instance** | `i-2ze0sd65q6qhot55aerq` | `ecs.c9i.xlarge` spot TDX, image `m-2zecs3h1bypk39nheql2` (NVMe feature set via flat-wire RPC), user_data = prod's proven config, **holds the EIP**, TLS up since 14:29:35 UTC, `:80 → 308` |
| **Reserved EIP** | `eip-2zet05jbat6wr6rp7elrc` = **101.200.178.251** | = DNS A for `login.airma.de`; **also the IP the Cloudflare DNS-01 token is pinned to** (see AGENTS.md §Cloudflare) |
| **Rollback instance** | `i-2zefwa6bdimeg1rbcfsg` | old prod — **Stopped** (T5, 2026-10-20 ~09:4x UTC, after E2E went green). Do not delete. Restarting it + re-attaching the EIP restores service instantly |
| **OSS relay instance** | `i-2ze19752fjlhw6rf4mpl` @ 123.57.45.105 | Debian, has Cloud Assistant agent; the intranet hop for OSS uploads (mainland-only API) + a CF probe box. Keep |
| Import task (this round) | image `m-2zecs3h1bypk39nheql2` | NVMe `supported` confirmed by round-trip `ModifyImageAttribute` read-back |

Git: **HEAD = `6494e92` ("m" — user's concurrent commit containing this
session's `AGENTS.md` updates, pushed; sits on top of `0e15b7a` ("m") which
contains the rebuilt disk `output-alibaba/disk-alibaba.raw`, sha `00963ad5…`
= CI's attested digest, rebuilt 03:27). Branch in sync with
`origin/alibabacloud`; `6e1f71e` (this file + the AGENTS.md status refresh)
pushed too — working tree clean. (Heads-up: the repo sees concurrent human commits — re-check `git log`
before acting on git state from this file.)

### 2.3 How the redeploy happened (compressed timeline, for reproduction)

1. Disk `output-alibaba/disk-alibaba.raw` → HK OSS bucket (public endpoint,
   presigned PUT, ETag==md5) → relay instance pulled it and PUT to the
   **Beijing intranet** bucket (Cloud Assistant RunCommand; keep `&` out of
   shell `sed` replacements — it corrupted presigned URLs once).
2. `ImportImage` (flat `DiskDeviceMapping.1.Format=raw`) → `Available`;
   `Features.NvmeSupport=supported` via hand-signed RPC (`/tmp/ali-rpc.mjs`).
3. Launched instance; ACME failed — **CF token rejected from the instance's
   auto public IP**. Root-cause trail: token works only from the reserved EIP
   (old instance used it successfully at 08:27 UTC; rejected from operator
   host, from relay, and from the new instance's own IP). User confirmed:
   *"The machine needs the same reserved IP to access Cloudflare DNS-01"*.
4. EIP move (exact working sequence — the wrong turns are in AGENTS.md traps):

```bash
# 1. release the new instance's auto public IP (required before EIP bind)
node /tmp/ali-rpc.mjs ecs ReleasePublicIpAddress RegionId=cn-beijing \
  InstanceId=<new> PublicIpAddress=<its public ip>
# 2. unbind EIP from old (NO InstanceType!)
node /tmp/ali-rpc.mjs vpc UnassociateEipAddress RegionId=cn-beijing \
  AllocationId=eip-2zet05jbat6wr6rp7elrc InstanceId=<old>
# 3. bind to new (NO InstanceType, and the new instance must have NO public ip)
node /tmp/ali-rpc.mjs vpc AssociateEipAddress RegionId=cn-beijing \
  AllocationId=eip-2zet05jbat6wr6rp7elrc InstanceId=<new>
# 4. reboot so ACME runs with EIP egress (enclave only orders at boot)
node /tmp/ali-rpc.mjs ecs RebootInstance RegionId=cn-beijing InstanceId=<new>
```

5. user_data on the new instance was replaced with **prod's exact user_data**
   (`DescribeUserData` of `i-2zefwa6bdimeg1rbcfsg`, 5476 b64 chars) *while
   stopped* — because the local `/tmp/ali-config.json` has the PayPal pairs
   **swapped** relative to prod/verify.html (prod `paypal_client_id=ARDDr…`
   matches verify.html `full`; `paypal_verified_client_id=AZXkz…` matches
   `verified`). **Do not redeploy from `/tmp/ali-config.json` without fixing
   the pairing.**
6. TLS came up on attempt from the EIP (poll #32 ≈ 4.5 min after reboot).

---

## 3. Remaining tasks (in order — do them as a cycle)

- [x] **T1 · E2E both flows live** — ✅ **both green** (2026-10-20). Recipe
  that works on this NixOS host:
  `CHROMIUM_PATH=/home/leo/.nix-profile/bin/chromium node scripts/e2e-sandbox.mjs verified`
  then the same with `full`. Two gotchas: playwright's bundled headless shell
  lacks distro libs (`libglib-2.0.so.0`) → must set `CHROMIUM_PATH`; and
  `… mjs both` **hangs in `ctx.close()`** after the first flow → run the two
  flows as separate processes. **Never `pkill -f e2e-sandbox`** — the pattern
  matches your own wrapping shell and kills it (use a `[e]`-bracket pattern).
- [x] **T2 · Live harness** — ✅ **90/90** with
  `REAL_REPORT=/tmp/report-verified.json` (83 offline + 7 live assertions).
- [x] **T3 · Console PII = 0** — ✅ verified two ways: (1) code audit — no
  email/payer/name value reaches any `log`/`kmsg` write (only `user_data`
  infra strings appear); (2) live reports — `verified` contains 0 identity
  strings. Serial console can still be eyeballed manually via ECS VNC
  (no headless API for it).
- [x] **T4 · Commit the disk artifact** — DONE mid-session by the user as
  `0e15b7a` ("m", pushed); CI run 39384204004 finished **success**, same
  digests re-attested. Nothing left to do here.
- [x] **T5 · Decommission old prod** — ✅ `i-2zefwa6bdimeg1rbcfsg` **Stopped**
  (ForceStop=true; the enclave has no ACPI handler but force-stop works).
  Prod TLS unaffected (200/ssl=0). Do not delete without asking the user.
- [x] **T6 · Audit round 2** (the cycle) — ✅ **2026-10-25 (v188/v188.1 cycle, §0.13)**: re-audit + new surfaces under the collusion model → **F1–F6 fixed** (zero-slot login fall-through, auditor-copy parity gate, missing HSTS, ZK summary-vs-proven-signal forgery, >100 MB zkey publish blocker, live-e2e double-prepare nonce race), all documented above with justifications; three deploy cycles, CI green, E2E ×3, full gates on the audited build. Residual/deferred WITH justification: (a) self-reported fields remain informational by design — code identity is decided exclusively by MRTD/RTMR silicon pins (v168 rationale, unchanged); (b) single-party ZK ceremony — a forged credential still requires an Intel-signed quote binding the same identity hash (circom.md §4); (c) optional TLS-leaf cross-check row stays optional so offline paste audits keep working — every other row is hardware/pin-bound; (d) `e2e-sandbox.mjs` left as-is (stale tool, superseded by `e2e-login-download.mjs` — documented trap).
  (prove the fixes hold under the collusion threat model), then audit the
  remaining surfaces not yet covered (e.g. bandwidth/rate-limit bypasses,
  attestation replay windows, boot-chain manifest gaps). Document findings →
  fix → CI green → redeploy (EIP dance per §2.3) → E2E → repeat. Items that
  cannot be fixed must be written down **with justification**.
- [ ] **T7 · Close the loop**: when done, summarize for the user; update
  AGENTS.md/HANDOVER.md state sections; consider `gravity_index` reporting is
  N/A here (no new third-party integration was added).
- [x] **T8 · Commit the state docs** — ✅ `HANDOVER.md` + AGENTS.md status
  refresh committed as **`6e1f71e`** and pushed (secrets-free: 0 matches for
  token/key patterns).

Definition of done for the whole mission: **no unfixed findings without a
written justification, CI green, live deployment running the audited build,
E2E + harness + PII all passing.**

---

## 4. Key runbooks (things that will bite you otherwise)

- **Alibaba RPC helper**: `node /tmp/ali-rpc.mjs <ecs|vpc|oss> <Action>
  Key=Value …` — args are `Key=Value` (**never `--Key value`**), region via
  `RegionId=cn-beijing`. Reads `~/.aliyun/config.json` (OAuth STS). On
  `InvalidSecurityToken.Expired`: run any `aliyun <product> <Action>` once to
  refresh, then retry. ⚠ `/tmp` helpers are **ephemeral** — if gone, the
  pattern is a 50-line HMAC-SHA1 RPC signer (see AGENTS.md API traps /
  `/tmp/ecs-call.mjs`).
- **OSS from outside mainland**: data-plane `PutObject/GetObject` is blocked;
  control-plane works. Upload path = HK bucket → relay instance → intranet PUT
  (or Cloud Assistant RunCommand with node-generated presigned URLs — never
  `sed` them).
- **Instance boot order for TLS**: config from `user_data` (IMDS
  `100.100.100.200`) → firewall → ACME DNS-01 **once at boot** → TLS. So:
  any config change = `StopInstance` → `ModifyInstanceAttribute UserData`
  (base64) → start; any EIP/egress change = reboot afterwards.
- **TLS check**: `curl -k --resolve login.airma.de:443:101.200.178.251
  https://login.airma.de/` (expect `200/ssl=0`). **Port 80 reality (probed
  2026-10-27, v193 debug round 1): `http://` is NOT ours anymore.** Alibaba's
  edge intercepts port 80 for this mainland EIP/domain and answers its own
  `403 Server: Beaver` “Non-compliance ICP Filing” page — verified from the
  raw IP with a forged `Host:` header too, so the enclave's `0.0.0.0:80`
  listener (main.rs:2482) is simply never reached. Nothing load-bearing:
  ACME is DNS-01, the flows are HTTPS-only, HSTS is pinned on every HTTPS
  response. A cold `http://` visit shows the block page until the browser
  has seen the HSTS header once; the real fix would be an ICP filing (a
  business decision, not a code change). The old `:80 → 308` expectation is
  retired.
- **Route table (v180+ router, main.rs:2457-2464)**: `/`, `/verify.html`,
  `/attest/login-session`, `/debug/envelope`, `/tls-cert.pem`, `/callback`,
  `/e2ee-blob` — **there is no `GET /report` and no `POST /generate`** (both
  retired with the v180/v187 flow rewrites; the next runbook line that says
  otherwise was stale). A report is produced ONLY by the login flow:
  `POST /attest/login-session` → PayPal → `/callback` auto-downloads the
  ciphertext. Unknown routes → 404, wrong method → 405, empty contract POST
  → 4xx — never 5xx (probed v193).
- **Attestation lookup**: `api.github.com/repos/<o>/<r>/attestations/sha256:<hex>`
  (unauthenticated path form; the `?subject=` query form 404s unauthenticated).
- **`DescribeInstances` ignores a singular `InstanceId` param** — it silently
  returns every instance in the region (bit me: polled the wrong instance
  after the EIP swap). List all + filter client-side, or pass the plural
  `InstanceIds` form.

## 5. Known-open risks / decisions for the user

1. **E2E is green on the new deployment** (T1–T3 + T5 done). Residual gap:
   the serial-console PII spot-check is manual (ECS VNC); console writes are
   code-audited PII-free instead.
2. **`e2e-sandbox.mjs both` hangs in `ctx.close()`** after the first flow —
   run each flow as its own process (recipe in T1 above).
3. **CF token rotation**: policy unknown; it broke silently between 08:27 and
   10:16 UTC today (or is IP-pinned and any egress change breaks it — both
   explanations fit; the EIP pin is the working theory the user confirmed).
   If ACME fails again: rotate token in Cloudflare (Zone.DNS:Edit on airma.de),
   patch `dns01_secret` into user_data, reboot **from the EIP**.
4. **Rollback recipe**: re-associate EIP to `i-2zefwa6bdimeg1rbcfsg` (its cert
   is still in RAM) — domain restores instantly.
5. **Billing**: 2 running instances + image + OSS buckets while in this state.
6. Repo push permissions exist via stored git credentials; `git credential
   fill` **hangs** (interactive helper) — don't use it.

## 6. Secrets inventory (paths only — never commit or echo these)

| What | Where |
|---|---|
| Prod enclave config (PayPal pair, CF `dns01_secret`, EAB, attestation key) | instance user_data (`DescribeUserData i-2ze4tvkuf12u933nsw8a`); mirrored at `/tmp/prod-config.json`, `/tmp/prod-ud.b64`, `/tmp/prod-ud186.b64` + `/tmp/prod-config186.json` (ephemeral) |
| Local (pair-swapped!) config | `/tmp/ali-config.json` |
| Alibaba STS/OAuth profile | `~/.aliyun/config.json` |
| Self-report RAM key (PutObject `boot/*` only, created 2026-10-24) | RAM user `pav-selfreport`; secret returned ONCE at creation — local mirror `/tmp/pav-ak.id` + `/tmp/pav-ak.secret` (ephemeral, 600) |
| OSS presign helpers | `/tmp/oss-url.mjs`, `/tmp/oss-puturl.mjs`, `/tmp/sign-oss.mjs` |

---

## 0.23 v216 cycle — dual-service redeploy + pin rotation: the auditor's provenance row (2026-11-08)

**Why**: the auditor's "GitHub provenance / initramfs" row was red. Root cause was
not the pipeline: the deployed disk predated `ead1d8d` ("Build the dual-service
disk with engine-correct flags", 2026-11-07 19:44 — 19 min after the deploy
commit `dece2ae`), so its measured `EFI/BOOT/initrd.img` was `b2789c24…` and the
public attestations API returns **404** for it. The current recipe reproduces
`8513c7ea…`, which the API resolves to **9 attestations** (identical to CI run
`42460523152` on the default branch; it reported 3 when first recorded and 9 on
re-check once the GitHub API recovered). Two workflow defects had also been
silencing attestations entirely and are fixed in this commit set:
`subject-name` was an unquoted YAML scalar containing `": "` (→ invalid file →
runs with **zero jobs**, no logs) and the trigger list omitted `alibabacloud`,
the branch the image ships from. `scripts/check-workflows.mjs` now fails any
workflow that would run zero jobs, contains that YAML construction, or filters
`push:` without the default branch.

| Item | Value |
|---|---|
| **Build lineage** | `bash build-tls-proxy-image.sh` (podman, Debian snapshot pinned) → disk `443ccfcf7c309045be1192b2e6e5b92efac3bd5ce953ad9ee45d5c863edd9456` (md5 `4736eafe11c5230ee2df9ab9a96c792d`), initramfs `8513c7ea0a62c760699a0e0995f5c174d81ca84c41eb0e80fe1d7f1f4a9e186e`, proxy bin `e9b157e821e20997c43242a412eed7906a740e575e3d944b115ae5797995e717` |
| **Reproducibility — proven, not asserted** | A second build via `CONTAINER_ENGINE=/tmp/podman-nocache.sh bash build-tls-proxy-image.sh` (**`--no-cache`**, wrapper injects the flag into `build` subcommands) produced **byte-identical** disk + initramfs + proxy binary. Two consecutive local builds, and the shipped image equals both. Wrapper needs `#!/usr/bin/env bash` on NixOS (there is no `/bin/bash`). |
| **Two-cycle swap** | Cycle 1 (`m-2zeibiq6bbe5x9n0o94c`, disk `9780b45d…`, pre-rotation `verify.html`) booted only to read the new quote → RTMR2 `954fc320…` → **`b48af75b…`**, self-report **`9cb1007d…`**; MRTD/RTMR0/1/3 held. Cycle 2 shipped `m-2ze2ncqumj1veapx9wt4` (disk `443ccfcf…`) with the rotated `verify.html`. `verify.html` is deliberately **not** in the measured chain, so its own edit rotates nothing — one rotation, not two. |
| **Re-arm order (again)** | `StopInstance --ForceStop` → `ReplaceSystemDisk --SystemDisk.Size 1` → `ModifyInstanceAttribute --UserData` (prod config, **byte-identical** readback, 4,477 B) → `StartInstance` → `/proxy/health` 200 in ~60 s. Images need `Features.NvmeSupport=supported` via the flat-wire RPC (`aliyun` CLI rejects the flag) or `ReplaceSystemDisk` refuses. |
| **Relay path** | HK bucket `paypal-tdx-relay-1792227992` (public endpoint, PUT `200`, ETag == MD5) → relay ECS `i-2zefiag79exwsshidi3z` → Beijing **intranet** PUT `200` + readback MD5 → `ImportImage` (flat `DiskDeviceMapping.1.Format=raw`). Both legs marked `RELAYPROXY-SUCCESS`. `RunCommand` limits: `--CommandContent` above the size cap is rejected (`CmdContent.ExceedLimit`) and must be sent with `--ContentEncoding PlainText`; oversized scripts go through a HK object + a tiny bootstrap command. |
| **Rotated pins (verify.html + `index.html` mirror + README digest)** | `EXPECTED_RTMR2` `954fc320…` → `b48af75b402c07cff61dd2e66aafe8cf0d8e8b8ac8a9ca5ddf21bdc4e0a731a83ce5fb4c50a10a1c1a011a7cac2d9838` (rotated with `node scripts/calculate-golden-rtmr.mjs --report /tmp/env216b.json --update`), `EXPECTED_ENCLAVE_SHA256` `da21fb45…` → `9cb1007d117561eef1d101125530b83aeca0ed4dcf6dff9b6bf7d2371a500d94`; `verify.html` = **265,825 B**, `55cac6bb9781852421ecf7b5b86f94d3eb87dc872b2126c47fc21ae480b2789b` == README == `index.html`. |
| **Live confirmation** | `GET /debug/envelope` on the redeployed VM reports `binary=9cb1007d…`, `disk_manifest["EFI/BOOT/initrd.img"]=8513c7ea…` (**the CI-attested digest**), `verify.html=55cac6bb…`, and a quote whose RTMR2 is `b48af75b…` with MRTD/RTMR0/1/3 unchanged. |
| **Offline auditor suite** | `node scripts/test-verify-security.mjs` → **500 passed / 0 failed** after the push to `main` published Pages (the pre-push run was 492/1, the single failure being the Pages parity row: `pages=5adc6a14…` vs `repo=55cac6bb…`). GitHub Pages now serves `55cac6bb…`, so that row classifies. **The live-attestation lookup was in a GitHub-side outage at push time** — `api.github.com/repos/…/attestations/sha256:<digest>` answered **504 HTML** (54,881 B) for `8513c7ea…`, `9cb1007d…` and the dead `b2789c24…` alike. Re-checked once it recovered: `8513c7ea…` → **200, count=9**; `9cb1007d…` → **200, count=11**; the pre-`ead1d8d` initrd `b2789c24…` → **404**, which is what proved the stale-image diagnosis rather than a pipeline bug. |
| **ZK-TLS / TLSNotary e2e — PayPal sandbox only** | The newest service (TLSNotary proxy, notary `101.200.178.251:8443`) exercised with `LIVE_NOTARY`/`LIVE_SERVER`/`LIVE_PATH` on the prebuilt `tls-proxy/target/debug/deps/live-…` binary (`cargo test --test live -- --ignored --nocapture` also works). **Passing, session + proof complete** (`test result: ok`), each logging `commit accepted` on the notary and a clean prover close: `sandbox.paypal.com/` → `301`, transcript 89 B sent / 5,528 B received; `sandbox.paypal.com/robots.txt` → `200`, 99 / 3,479 B; `www.sandbox.paypal.com/robots.txt` → `200`, 107 / 3,429 B; `www.sandbox.paypal.com/signin` → `200`, ~103 / ~38,000 B (3 runs of 5, one on a retry). **Intermittent (race, see below)**: `www.sandbox.paypal.com/` (302, empty body), `www.sandbox.paypal.com/signin` and `api-m.paypal.com/` (403, 4.5 KB) can end with prover `hyper::Error(IncompleteMessage)` plus a notary refusal `failed to receive proxy finished message caused by: unexpected end of file` (`/proxy/refusals` keeps the last 32). **Response size is not the discriminator** (4.5 KB fails while 3.4 KB passes on the same host), and the earlier 16 KiB `max_recv_data` theory is **wrong**: proxy mode carries no data limits at all — `crates/core/src/config/tls_commit/proxy.rs` holds only `server_name`, while `max_sent_data`/`max_recv_data` live on `MpcTlsConfig` (`…/tls_commit/mpc.rs`). ✅ **RESOLVED — it is a timing race at PayPal's edge, not a limit.** `www.sandbox.paypal.com/signin` (33 KB) passes **2 runs of 3** with the identical binary and identical path; a temporary raw-byte-dump test (deleted afterwards) received the **entire** 39,373 B response — headers plus the declared 34,442 B body — followed by a clean EOF, while a `/robots.txt` run that had passed under hyper died with `server closed during TLS handshake`. **Measured split (why, corrected by experiment):** commit 8–41 s of the session, TLS handshake 2–4 s for a 33 KB page, proof ~2 s. The commit phase is **MPC setup between prover and notary, not the notary's dial** — refuting the earlier "notary dials the site slowly" explanation: the notary logs its own connect at **35 ms** (`relaying TLS to www.sandbox.paypal.com (146.75.123.1:443)` right after `accepted`), TCP connect to PayPal from the operator host is 27–40 ms, and pinning an edge address changes nothing. **Distance to the notary is the lever**: the same prover and page against a loopback `tls-proxy` commit in **3.5 s** and finish in **6.1 s**, vs 8–41 s commit over the 215 ms link to `101.200.178.251`; the deployed box is a 2-vCPU spot instance, so its own number varies run to run. Nothing on the notary side truncates, and the failure window is the relayed TLS session itself. Consequence for operators: re-run before calling a failure a regression, and read `/proxy/refusals` to tell "the site closed on us" (`failed to receive proxy finished message`) from a refusal of ours. `tls-proxy/tests/live.rs` now retries by default (`LIVE_ATTEMPTS`, 3) and prints per-stage timings, so a flaky edge costs a retry instead of a red run; measured working: attempt 1 ended `session closed while the prover was connected` after a full `200 OK`, attempt 2 passed. Documented with the passing commands in `docs/tls-proxy.md`. **New public route `/proxy/attestations`** (v2xx): relays the child's `:8081/attestations` with each `server_name` fingerprinted exactly like `/proxy/refusals`, so an operator without a shell can see whether their session was recorded and under which id. Transcript bytes and signature stay on loopback. Fixing it exposed a latent bug in the child's own list, and the **first repair was wrong**: the stored envelope is **flat** (`Attestation` carries `#[serde(flatten)] body`, and `GET /attestations/{id}` serves `server_name` at the top level), so reading it under a `/body` key — the v217 image — still listed every session with a null host; the live origin answered `{"server_name": null}` for a session that had just passed. The working fix is `summarize_session()` reading the field at the top level, pinned by two unit tests in `tls-proxy/src/main.rs` and confirmed against a real loopback session (`{"server_name": "www.sandbox.paypal.com", "notarized_at": 1794160401}`). **No source/deploy mismatch either**: the old `/proxy/attestations` 404 was the *enclave's* allowlist (then only `/proxy/health` and `/proxy/refusals` were routed; that route exists now), and the health JSON is the enclave's supervision view, so neither implied a stale proxy binary. Local-build trap on NixOS: `openssl-sys` only links against the **ELFCLASS64** store output (`/nix/store/kysvfcf8d8v26rr32xfqji8ri2lczlqk-openssl-3.6.5/lib`, `machine=62`) — `8k5ax7v3…`/`gjwa2d1j…` are 32-bit and fail with `incompatible with elf64-x86-64`. |
| **OPEN — browser e2e blocked by PayPal, not by us** | `node scripts/e2e-sandbox.mjs verified` fails at `PayPal login did not navigate after 3 submit attempts`. Diagnosis: the authorize page now serves PayPal's anti-bot interstitial — **only** hidden inputs `adsddtoken`, `adsddsign`, `adsddm`, `adsddcaptcha` and **no `#email`/`#btnNext`/`#btnLogin`**, so the harness types into nothing. The same sandbox credentials log in fine when the *plain* `https://www.sandbox.paypal.com/signin` page is driven with `page.fill()` (landed on `/myaccount/summary`), which isolates it to the `signin/authorize` interstitial challenging the headless browser. **Headed retry done 2026-11-08** (`Xvfb :99` + `headless: false` copy of the harness, deleted afterwards): identical `step-1 status` / popup landing and the same three submits that never navigate, so this is **server-side anti-bot on the authorize popup, not headless detection**. A human-driven real browser is the only remaining route; no enclave change is implied. |

---

## 0.24 v217/v217b — `/proxy/attestations` cutover, and the list projection that took two tries (2026-11-08)

Two in-place cycles shipped this session. **Cycle v217** put the new
`/proxy/attestations` route on the live origin; **cycle v217b** replaced it hours
later because that route listed every session with a `null` host.

| Item | Value |
|---|---|
| **Why two cycles** | v217 carried a *wrong* repair of the child's `list`: it read `server_name` via `pointer("/body/server_name")`, but the stored envelope is **flat** — `Attestation` uses `#[serde(flatten)] body`, so `/attestations/{id}` serves `server_name` beside the signature at the top level. The live origin therefore answered `{"count":1,"sessions":[{"notarized_at":null,"server_name":null,…}]}` for a session that had just passed. Diagnosed by running the *shipped* binary against a loopback notary and comparing `GET /attestations` with `GET /attestations/{id}` (the latter has the host, the former did not). |
| **The fix** | `summarize_session(id, value)` in `tls-proxy/src/main.rs` reads `value.get("server_name")` / `value.get("notarized_at")` at the top level; `list` maps through it. Two unit tests pin it (`list_projection_reports_the_committed_host`, `list_projection_tolerates_a_record_without_a_host`) — the child had **no** test for `list`, which is exactly why the wrong repair survived a green build. |
| **Build lineage (v217b)** | `bash build-tls-proxy-image.sh` → disk `6293a7655e044e6406dd08203d604d8d8157698ce1292637f541914b819403a8` (md5 `95217859efc54117e548c71e69fd9cf7`, 55,574,528 B), initramfs `057dd43ee22a4fb4db7567f09edb5a4a7dd9ffc1e8d9e4a06056bddd800ca1d5`, proxy bin `b1d573f026770356feff2693c7abee4867d0fb75abc3e05a024fe691021c1658`. Verified in the initramfs payload: `/tls-proxy` == `b1d573f0…` and contains **no** `/body/server_name` string. (v217 was disk `5f1a7546…`, md5 `8f535e44…`, bin `a43c0124…`, image `m-2zec1dghhbv77kixm9yc`.) |
| **Relay path** | Presigned PUT from the operator host → HK bucket `paypal-tdx-relay-1792227992` (PUT `200`, ETag == local md5, both cycles) → relay ECS `i-2zefiag79exwsshidi3z` → Beijing **intranet** PUT `200` + readback md5 → `ImportImage` (flat `DiskDeviceMapping.1.Format=raw`). v217b relay leg: **10 s** end-to-end, `RELAYPROXY-SUCCESS`. |
| **Images** | v217 `m-2zec1dghhbv77kixm9yc` (Available, superseded and known-broken — do not redeploy) → v217b **`m-2ze7liy7l0dobz3gg77g`** (`paypal-tdx-esp-v217b-202611081908`, 1 GiB, UEFI, `Features.NvmeSupport=supported` via the flat-wire RPC `node /tmp/ecs-flat.mjs ImageId=… Features.NvmeSupport=supported` — the CLI rejects `--Features.NvmeSupport`). Import took **90 s**; NVMe flag is mandatory, the imported image defaults to `unsupported`. |
| **Prod swap (both cycles, same instance)** | `StopInstance --ForceStop true` (a graceful stop sat in `Stopping` for **260 s** — the enclave is PID 1 with no ACPI handler; force-stop landed in 10 s) → `ReplaceSystemDisk --SystemDisk.Size 1` → `ModifyInstanceAttribute --UserData` → **readback byte-identical to the pre-swap capture** (5,973 B b64, sha256 `11c9fcf6…`) → `StartInstance` → `/proxy/health` 200 at **t+48 s** both times. Disks: v217 `d-2ze2yp6ozth4elaer43u`, v217b **`d-2zeexizgfuircb08txou`**. |
| **Live confirmation (v217b)** | `GET /proxy/attestations` after one real session: `{"count":1,"sessions":[{"notarized_at":1794190428,"server_name":"host:0a191a6a","session_id":"0b9651bc…"}]}` — `host:0a191a6a` **equals** the first 8 hex of `sha256("www.sandbox.paypal.com")`, i.e. the same fingerprint `/proxy/refusals` uses, over the real committed name, with the transcript still loopback-only. `/proxy/health`, `/proxy/refusals`, `/` all 200; `/attestations` stays 404 on the public origin (loopback-only by design). |
| **Session timings (v217b)** | `www.sandbox.paypal.com/robots.txt` → commit accepted **7.7 s**, transcript 107 B sent / 3,429 B received, `200 OK`, proof complete, whole test **11.1 s** — consistent with the corrected "commit is 8–41 s and round-trip bound" story, not a dial. |
| **Rotated pins** | The new initramfs changed RTMR2: `b48af75b…` → **`424ae32ff148064bf0aade35894d02c5ddd971455a4d723490aed862e28342e4de99bc289f3f67f8ae3cb7e6d18dd3f6`** (`node scripts/calculate-golden-rtmr.mjs --report /tmp/env217b.json --update`), mirrored by hand into `index.html` (the script only rewrites `verify.html`), README digest `55cac6bb…` → `7d87bb50…`. MRTD/RTMR0/RTMR1/RTMR3 byte-held (`e0199499…` / `06a32a2f…` / `6fa03523…` / zeros) — only the disk changed. Offline auditor suite: 492/1 pre-push (the Pages row), **500 passed / 0 failed** once `main` republished (
commit `2235933`). |
| **Test coverage after the fix** | `cargo test` in `tls-proxy`: **2 unit + 5 session-integration passed**, live suite `1 ignored` (opt-in). Loopback confirmation used the real prover: `{"server_name":"www.sandbox.paypal.com","notarized_at":1794160401}`. |
| **Trap: `RunCommand` flag** | `--InstanceIds` is **rejected** by this CLI (`'--InstanceIds' is not a valid parameter or flag … Did you mean: InstanceId`); the working form is `--InstanceId.1 <id>` (RepeatList). Bare `--InstanceId` also does not populate the list. |
| **Trap: stale local binary** | `cargo test --bin tls-proxy` builds the **test harness**, not `target/debug/tls-proxy`. A loopback check run straight after a test session re-ran the *old* binary and showed the old `null` host — misleading "the fix did not work" evidence. `cargo build --bin tls-proxy` first. |
| **State left behind** | prod `i-2ze1zdxis0hcsg91qbh5` Running, EIP 101.200.178.251, image `m-2ze7liy7l0dobz3gg77g`, disk `d-2zeexizgfuircb08txou`; rollback image `m-2ze2ncqumj1veapx9wt4` (v216b) plus the superseded v217 image `m-2zec1dghhbv77kixm9yc`. Relay `i-2zefiag79exwsshidi3z` stopped (`--StoppedMode StopCharging`) after the legs. |

## 0.25 v218 — the enclave now honours a graceful stop (2026-11-08, later)

A graceful `StopInstance` used to sit in `Stopping` for **260 s** and only ended when the
operator passed `--ForceStop true`. Root cause was two-fold and neither half existed:

| Half | Why it was missing | Fix |
|---|---|---|
| **Receiver** | Debian's cloud kernel builds the ACPI button and evdev as **modules** (`CONFIG_ACPI_BUTTON=m`, `CONFIG_INPUT_EVDEV=m`; `CONFIG_ACPI_TINY_POWER_BUTTON` — the driver that signals PID 1 directly — is **not set** in Debian). The initramfs shipped neither `button.ko` nor `evdev.ko`, so a power-button press had nothing to deliver it to. | `PLATFORM_MODULES` in `build-initramfs-tools.sh` gained `button evdev`; `load_drivers()` modprobes both. Verified in the built initramfs: `drivers/acpi/button.ko` + `drivers/input/evdev.ko` are present. |
| **Handler** | This process is PID 1 and installed no handler. Worse, `enclave_init::poweroff()` is **not** a power-off — it is the fail-closed halt-and-park (self-report + sleep), so nothing could ever release the instance. | New `arm_shutdown_handling()`: a SIGTERM handler (PID 1 ignores it by default) and a watcher on `/dev/input/event*`. `is_power_press()` fires **only** on `EV_KEY/KEY_POWER/value==1`, and the node's `EVIOCGNAME` must contain `Power Button` — a release, repeat, another key, or another input device can never power the machine off. Both paths call `power_off_now()` → `reboot(RB_POWER_OFF)`, deliberately distinct from the parked `poweroff()`. |

**Ground truth (live, on the real TDX hypervisor):**

| Step | Result |
|---|---|
| Boot v218 after `ReplaceSystemDisk` | `/proxy/health` **200 at t+65 s**; all four routes 200; config intact (`enabled:true`, ports 8081/8443) |
| **Graceful** `StopInstance` (no `--ForceStop`) | **Stopped in 43 s** — down from 260 s + mandatory force-stop |
| `StartInstance` again | `/proxy/health` 200 in 57 s, `restarts:0`, fresh TDX quote (`configfs_tsm`) |

| Item | Value |
|---|---|
| Build lineage | disk sha256 `b499ca19b3b3859646d9c3260ba417e82e05440fc9fa2982824b2c39571b786d` (md5 `25050eb9718dc1901ca4d34f19a172be`, 55,574,528 B), initramfs `396fdf99efbf6c6ca553cb523ff8480f69a72415e08b065895a6d3c72b70b3ef`, enclave `/init` `cb94953e4eec939e80e049e984893b0d0ef71fe485f3732835c8bb9696575bf5` (contains `shutdown handling armed`, `ACPI power button pressed`), proxy bin `b1d573f0…` (unchanged) |
| Image / disk | **`m-2ze9lskiq4fprc48auuy`** (`paypal-tdx-esp-v218-202611081958`, 1 GiB, UEFI, `Features.NvmeSupport=supported` via the flat-wire RPC; import 70 s) / prod disk **`d-2ze7o6b0hjbwtye6xp1q`** |
| `user_data` | re-pushed after the swap, readback identical to the pre-swap capture (5,973 B b64, sha256 `11c9fcf6…`) |
| Pins rotated | `EXPECTED_RTMR2` `424ae32f…` → **`d35d263340656b3c37fc9156e1ec18557f3d709931d32435ea21aea815d980caa475e652a79d74bb85944433e4f910e7`**; `EXPECTED_ENCLAVE_SHA256` `9cb1007d…` → **`cb94953e…`** (both in `verify.html` **and** `index.html` — `calculate-golden-rtmr.mjs --update` only rewrites `verify.html`); MRTD/RTMR0/1/3 byte-held; README `verify.html` digest rotated. Offline auditor suite: 492/1 pre-push (Pages row), green after `main` republished. |

**New traps:**
- **`poweroff()` is not a power-off.** `enclave_init::poweroff()` halts and parks on purpose (fail-closed evidence). Anything that needs the instance actually released must go through `power_off_now()`.
- **A missing module looks exactly like a hostile hypervisor.** With `button`/`evdev` absent there is no error anywhere — the guest just never reacts. Check `lsmod`/initramfs contents before blaming the platform.
- **The input path is a safety surface.** Only `EV_KEY`/`KEY_POWER`/value `1` from a device whose `EVIOCGNAME` contains `Power Button` may trigger a shutdown; the two unit tests (`a_power_button_press_is_honoured`, `only_a_press_powers_the_machine_off`) pin the gate against a release/repeat/other key.

**Not proven by the v218 cycle (state honestly, do not assume):**
- **Stop mid-session.** The 43 s figure came from an idle instance (empty store). A power-off while a notarized session is in flight will still cut that session — `power_off_now()` does not drain, and the store is in-memory, so the session is lost by design. Only the *timing* with work in flight is unmeasured.
- **One sample.** 43 s is a single observation, not a distribution; the pre-fix 260 s was also a single observation.
- **No local reproduction.** This host has no `qemu-system-x86_64`, so the input gate is covered by the two unit tests and by the live hypervisor stop, not by a synthetic button press.
- **SIGTERM path is untested live.** The ACPI press is what the hypervisor sent; the signal handler is unit-reachable only, since nothing in the boot chain sends PID 1 a SIGTERM today.

## 0.26 v220 — a stop now drains in-flight sessions, and the drain itself had a bug (2026-11-08, later still)

### What the drain does

A notarisation in flight holds the prover's transcript and the proof of which host it came
from. Powering off through it destroys work the prover cannot recreate and gives them no
answer that says why. v220 makes the stop wait instead:

| Piece | Where | Behaviour |
|---|---|---|
| `active_sessions` counter | proxy | Incremented on accept, decremented by the session task itself, so no session slips between accept and spawn |
| `POST /drain` | proxy loopback API | Sets `draining`; **refuses new sessions** (logged on the refusal ring as `kind:"draining"`), leaves running ones untouched, returns the in-flight count |
| `drain_step()` | enclave | Pure gate: `Done` at 0, `Wait` under budget, `GiveUp(n)` at the budget |
| `DRAIN_BUDGET = 120 s` | enclave | Equal to the proxy's own `TLS_PROXY_SESSION_TIMEOUT`: a session that outlives it is already dead, and it stays well inside the platform's ~260 s stop window |
| `shutdown_worker` | enclave | The single path from "requested" to "off" for both the power button and SIGTERM; the signal handler only stores a flag (async-signal-safe) |
| `shutdown_watchdog` | enclave | Budget + 15 s hard stop, so a wedged or panicked drain can never leave the instance in `Stopping` |
| `/proxy/health` | enclave | Now relays `active_sessions`, `draining`, `sessions_ok/failed` — the stop is observable from outside while the instance is `Stopping` |

### The bug this cycle found on the hypervisor

**v219's first graceful stop hung for 7+ minutes in `Stopping` and needed `--ForceStop`.** The
drain ran on a `current_thread` runtime built with `.enable_time()` only; with the IO driver
disabled, tokio's `TcpStream` panics (`A Tokio 1.x context was found, but IO is disabled`), the
worker thread died, and nothing ever called `reboot(RB_POWER_OFF)`. `GetInstanceConsoleOutput`
returns empty on this instance type, so the only symptom was a stuck status.

Fixed by `drain_runtime()` → `.enable_all()`, pinned by
`the_drain_runtime_can_reach_the_loopback_api`, which uses the **production** builder — flipping
it back to `enable_time()` fails the test with exactly that panic (verified, then reverted).

### Measurements (live, v220, `m-2ze7c8jev53ikz43ybj8`)

| Scenario | Result |
|---|---|
| Idle graceful stop ×5 | **42, 42, 42, 43, 41 s** — the 43 s in §0.25 was not a one-off |
| Boot to `/proxy/health` 200 | 48–54 s, every cycle |
| Session held open, stop requested | Instance sat in `Stopping` with `active_sessions:1`; at **t+35 s** the press arrived and it reported **`draining:true` with `active_sessions:1`** — no cut |
| Same, session held 20 s *after* the drain began | Stayed `Stopping` with `a:1 d:true` from **t+35 to t+55**; released at t+55 → **Stopped at t+71** (drain + shutdown), only after the count reached 0 |

The press arrives **~27–35 s** after `StopInstance` is called (`d:false` until then), so an idle
42 s stop is roughly 27 s of hypervisor latency plus ~15 s of shutdown — not 42 s of drain.

| Item | Value |
|---|---|
| Image / disk | **`m-2ze7c8jev53ikz43ybj8`** (`paypal-tdx-esp-v220-202611082314`, UEFI, NVMe supported) / prod disk **`d-2ze7tjfd7n1dyg57s51y`** |
| Build lineage | disk md5 `6e095794e9e1c51e369cd2354edb56c9` (55,574,528 B, sha256 `58472d70…`), initramfs `8fa3f088…`, enclave `/init` `a729c82753a8691e60bba17d46f7fb73add2d5942383fd570e24425d89ac9cb7`, proxy bin `2148b101…` |
| Pins rotated | `EXPECTED_RTMR2` `d35d2633…` → **`44cfbca3c83ad95c…`**; `EXPECTED_ENCLAVE_SHA256` `cb94953e…` → **`a729c827…`** (verify.html **and** index.html); README `verify.html` digest → `8eb0ec0c…`. MRTD/RTMR0/1/3 unchanged. |
| Tests | enclave **40 passed** (drain gate ×2, drain runtime ×1); tls-proxy 2 unit + **7 integration**, including `drain_refuses_new_sessions_and_keeps_the_record` |
| `user_data` | re-pushed after the swap; readback equals the file minus the trailing newline (`len 5972`, sha `880ec5f9…`) |
| Superseded | v219 `m-2zebw9kc74cbersuejq2` — deleted; this section is the record of the hang |

**Traps:**
- **`enable_time()` is not enough for any runtime that talks to the network.** The panic is inside tokio's `TcpStream`, far from the builder line.
- **No console on this instance type.** `GetInstanceConsoleOutput` is empty, so a wedged PID 1 is invisible; the fix has to be measured from outside (`/proxy/health`) and guarded in-process (watchdog).
- **A "mid-session" test can silently not be one.** The first attempt released the socket at t+15, before the press arrived at t+27, so it measured another idle stop. Gate the release on observing `draining:true` *with* `active_sessions:1`.

## 0.27 The old box was the watchdog's "prod", and deleting it meant fixing that first (2026-11-08, end of cycle)

### What was asked and what it turned up

Delete stopped instance `i-2ze61uxzdt23qm6sx75e` (`paypal-auth-vm`, 20 GiB `cloud_auto`
delete-with-instance, no EIP, no data disks), then its image `m-2zeb9skvrja58qzpao8s`. The deletion
itself was clean — instance gone in one poll, disk released with it, image deleted after. What it
exposed is that **self-healing has been inert for days**:

- The OOS reconciler's contract is `a tagged instance exists (ANY status) -> do not touch it`. The
  `pav-watchdog=prod` tag was on the **stopped old box**, not on live prod. So every reconcile found
  a "prod", checked its EIP, and left the running box unmanaged: if `i-2ze1zdxis0hcsg91qbh5` had been
  evicted, nothing would have rebuilt it.
- Worse, `deploy-oos-watchdog.sh` bakes user_data from *the tagged instance* rather than from
  `dist/config.json`, precisely so a redeploy cannot silently undo a secrets push. With the tag on the
  dead box that safety feature worked against us: the first `deploy` this cycle baked the old box's
  **v207-era 4,376-byte config** into `pav-watchdog`, and both `pav-watchdog-hb` and `pav-spot-notice`
  still pinned the image about to be deleted. Deleting the image alone would have broken every
  relaunch path while `status` kept looking healthy.

### Order that made it safe

1. `add-tags pav-watchdog=prod` on live prod **first** — while both boxes were tagged the rule is
   "leave alone", so no window could spawn a duplicate or steal the reserved EIP.
2. `remove-tags` on the old box, so the reconciler's `.0` is prod and nothing else.
3. Re-baked: `pav-watchdog` now carries prod's live blob (**5,972 b64 chars, decoded sha
   `4fda21a7…`**, byte-equal to the running box), `pav-watchdog-hb` and `pav-spot-notice` both carry
   **`m-2ze7c8jev53ikz43ybj8`** (v220).
4. Deleted the instance, then the image.
5. `deploy-oos-watchdog.sh run` → `Success` with `{"instanceId":"i-2ze1zdxis0hcsg91qbh5",
   "eipStatus":"InUse"}`: it found prod, ensured the EIP, created nothing.
6. Second `deploy` (needed because the `.0` ordering was ambiguous on the first) re-baked from the
   now-only-tagged prod — that is the run whose blob matches.

`dist/config.json` was refreshed in the same motion: `spec.imageId` → v220, `capturedFrom` →
`{instanceId: i-2ze1zdxis0hcsg91qbh5, imageId: v220}`, `userDataB64` → prod's current blob, and
`spec.instanceName` normalised back to `paypal-auth-vm` (prod's own name had drifted to
`paypal-auth-vm-v209`; OOS keys on the **tag**, the FC path keys on the *name*, which is why the drift
mattered and why the FC zip was rebuilt too). That file is gitignored — it holds real secrets.

**Inventory after:** five self-owned images (`v220` live, `v218` rollback, `v217b`, `v216b`, `v216a`),
one `paypal-auth-vm*` instance (prod), tag on prod only.

### Leftover this exposed (not touched)

`DeleteImage` does **not** delete the image's backbone snapshot: 32 snapshots exist for 5 images.
**25 are orphans** (`SnapshotForImage-*` whose image name no longer exists, ~25 GiB, including
`v219`, `v217` and the just-deleted old box's `s-2zeb9skvrja58qzrv75g`), 5 match live images, and 2
are deliberate non-image forensic snapshots (`v172-forensic-bootprobe`,
`paypal-v172-esp-forensic-eip-boot`) that must stay.

**Traps:**
- **Tag ownership is the whole watchdog.** Verify `DescribeInstances --Tag.1.Key pav-watchdog` points
  at the *running* box before any cleanup that touches instances; a tag on a stopped box disables
  healing silently, and `deploy` will then bake that box's stale secrets.
- **Deleting an image leaves a 1 GiB snapshot.** Budget for it: image cleanup without snapshot
  cleanup frees the name, not the storage.

## 0.28 Sandbox e2e, prod rename, snapshot pile, and a selftest that hid its own error (2026-11-08, closing)

### Sandbox e2e — both hosts pass, first attempt

Run against the live notary (`LIVE_NOTARY=101.200.178.251:8443`, `cargo test --test live -- --ignored`):

| Host / path | Result |
|---|---|
| `api-m.paypal.com/` (production API) | **pass, attempt 1, 11.7 s** |
| `api-m.sandbox.paypal.com/` | **pass, attempt 1, 10.3 s** |
| `www.sandbox.paypal.com/signin` | **pass, attempt 1, 11.3 s** |

`/proxy/attestations` → `count:3` with three distinct `host:` fingerprints; `/proxy/health` →
`sessions_ok:3`. The `www.sandbox.../signin` page is the one this module's header warns fails "2 of 3
runs" on a 33 KB transcript — it passed, so the earlier flakiness is not currently reproducing.

**`sessions_failed` counts aborted sockets, not lost notarisations.** A stray `failed:1` appeared and
`/proxy/refusals` explained it exactly: `kind:"rejected", reason:"io error: commitment protocol failed
to receive request caused by: unexpected end of file"`. Proven by experiment — opening a TCP socket to
:8443 and closing it straight away increments `sessions_failed` and writes that same record
(1→2). So treat that counter as "connections that never became a session"; a passing prover run can
still leave one behind.

**The 8 h clock skew is expected, not new.** The enclave answers `Date: Mon, 09 Nov 2026 07:47 GMT`
while Cloudflare/Google/example.com all answer `23:48 GMT`. This is the documented provider clock
(Beijing wall time read as UTC); signed report times already come from PayPal's `Date` header (R3-3),
so only labelled fallback fields carry the skew.

### Housekeeping completed

- **25 orphan snapshots deleted** (0 failures). `DeleteImage` never removes the backbone snapshot, so
  the earlier image purge had left 1 GiB behind each. What remains is exactly 7: one per live image
  (v220, v218, v217b, v216b, v216a) plus the two forensic snapshots
  (`paypal-v172-esp-forensic-eip-boot`, `v172-forensic-bootprobe`). Guard used for the delete: snapshot
  name `SnapshotForImage-<image_name>` with `<image_name>` absent from the live image list.
- **Prod renamed** `paypal-auth-vm-v209` → **`paypal-auth-vm`**, so the name-based path (FC zip,
  `PROD_NAME`) and the tag-based path (OOS) now resolve to the same box (`i-2ze1zdxis0hcsg91qbh5`).

### Watchdog selftest: proves the rebuild, and was leaking boxes

`bash watchdog/deploy-oos-watchdog.sh selftest` builds a throwaway box from the live image with the
prod spec (verified: `cloud_auto 1 GiB` system disk, `eipStatus: InUse` — it never takes the EIP) and
then deletes it. The delete loop was broken in a way that hid itself: it retried `DeleteInstance
--Force true` five times at 4 s intervals with the error sent to `/dev/null`. A TDX spot cold start
takes longer than that, and the API answers **`IncorrectInstanceStatus.Initializing` while the
instance already reports `Status: Running`** — so the loop printed five innocuous `state: Running`
lines and left a billable box behind (one orphan had to be released by hand).

Fixed: retry over 24×5 s, print the refusal, and warn loudly if the box survives 120 s. Re-run:
creation `Success`, five `delete refused (Running): … Initializing`, then `delete accepted` →
`state: GONE`, and the `oos-selftest` tag list is empty afterwards.

**Trap:** on this platform `Status: Running` is not "ready" — `IncorrectInstanceStatus.Initializing`
is the only signal that creation is still in progress, and it is an *error* from the mutating call,
never a status you can poll for.

## 0.29 Two services, two targets: production login vs. sandbox notary (2026-11-09)

There are **two webservices** and they deliberately face different PayPal environments:

| Service | Reaches | Status |
|---|---|---|
| login / attestation (`src/main.rs`, `login.airma.de`) | **production** `paypal.com` only (`staging:false`) | live |
| TLS-notary proxy (`tls-proxy/`, `:8443`) | **`sandbox.paypal.com`** — the sandbox exists to exercise the notary | live |

So the sandbox account is *not* an input to the login page, and running the auditor driver
(`scripts/e2e-sandbox.mjs`) against prod is testing the wrong service. That run gets all the way to
PayPal and then stops, which is expected — the popup is production PayPal and the identity is a
sandbox identity:

```
1. loaded verify.html (trusted copy)               ✅
2. step-1: Login session ready, escrow ON (183BA8C8…) ✅
3. popup landed: https://www.paypal.com/signin/authorize?client_id=BAAKIQtHan_IwlC0KJeBICQ86HyaLghkcmyP9W42jfd2TjtugYHpYrfQFKp8
   credentials submit #1..#3
E2E FAILED: PayPal login did not navigate after 3 submit attempts
```

**The popup is production PayPal, and the account is a sandbox account.** Prod's config is
`staging:false` (checked from the instance's user_data), so `authorize` is built against
`www.paypal.com` with the production app; `api_base` likewise resolves to
`api-m.paypal.com` (line `let api_base = if state.staging {…}`). A `sb-…@personal.example.com`
account has no identity on the production host, so the form never navigates — "3 submit attempts"
is the automation retrying a page that was always going to refuse.

The credentials themselves are fine, proven separately: the same email/password on
`https://www.sandbox.paypal.com/signin` goes `#email` → `#btnNext` → `#password` → `#btnLogin` →
**`/myaccount/summary?intl=0`**, no alert.

Do not "fix" this by moving prod onto sandbox:
- `staging` is **boot configuration only** — no per-session override; `attest_login_session` takes
  `flow`, nothing else.
- Flipping prod to `staging:true` would send users to sandbox PayPal with the *production* client id,
  which PayPal rejects. It breaks the live login and does not make the driver pass. The login service
  stays production-only; the sandbox is the notary's target (§0.30).

What the login service proved while the driver was attached to it: trusted-page load, login-session +
escrow setup, and authorize-URL construction with the production app — everything up to the point
where a sandbox identity is supposed to be refused.

## 0.30 Notary e2e against sandbox.paypal.com — re-measured, first attempt (2026-11-09)

The sandbox service's e2e is the live relay test in `tls-proxy/tests/live.rs`, run against the
deployed notary:

```bash
LIVE_NOTARY=101.200.178.251:8443 LIVE_SERVER=www.sandbox.paypal.com LIVE_PATH=/signin \
  LIVE_ATTEMPTS=3 cargo test --test live -- --ignored --nocapture      # in tls-proxy/
```

```
--- attempt 1/3: www.sandbox.paypal.com/signin
[   0.2s] connected to notary 101.200.178.251:8443; committing www.sandbox.paypal.com
[  14.9s] commit accepted — the notary is relaying TLS to www.sandbox.paypal.com
[  16.8s] relayed response status: 200 OK
[  18.9s] transcript: sent 103 B, received 37998 B
response head: HTTP/1.1 200 OK | Connection: close | Content-Length: 33069
[  23.6s] prover finished: presentation complete
test live_relay_of_a_real_website ... ok        (1 passed, 0 failed, 23.56s)
```

So the whole MPC round-trip on a 33 KB sandbox page completed on the **first** attempt in 23.6 s —
no retry needed, which is the good side of the coin-flip noted in the header comment (2 of 3 runs
used to fail the handshake). Attestation landed on the notary:

```
count:4  sessions_ok:4  sessions_failed:9
latest: session_id 35fd70b6028973efdbbb8cd9a68cee5b  server_name host:0a191a6a  notarized_at 1794215223
```

`host:0a191a6a` is the redacted `www.sandbox.paypal.com` and now appears twice (this run plus the
earlier one); the two `api-m.sandbox.paypal.com` sessions are `host:5c868ab7`. `sessions_failed:9` is
unchanged by this run and counts the bare connect-and-close probes on :8443 (each records
`kind:"rejected", reason:"commitment protocol failed to receive request … unexpected end of file"`),
not failed relays.

Verification half re-run after the session: `node scripts/test-verify-proxy.mjs` → **44 passed,
0 failed** (the real `verify-proxy.html` audit path against RSA-2048-signed attestations, including the
"any field changed must fail" cases). Pins were untouched — this run changed no boot measurements.

## 0.31 Five more sandbox relay runs: 6/6 first attempt today (2026-11-09)

Same command as §0.30, five consecutive runs, no retry needed in any of them:

| run | attempt used | commit accepted | 200 OK | prover finished | 
|---|---|---|---|---|
| 1 | 1/3 | 8.6 s | 10.6 s | **13.2 s** |
| 2 | 1/3 | 6.1 s | 7.7 s | **11.8 s** |
| 3 | 1/3 | 8.3 s | 10.5 s | **15.3 s** |
| 4 | 1/3 | 7.1 s | 8.8 s | **11.4 s** |
| 5 | 1/3 | 8.0 s | 9.8 s | **12.5 s** |

Mean 12.9 s, min 11.4 s, max 15.3 s (the §0.30 run was 23.6 s — first run after a long idle,
committed at 14.9 s, so the outlier is the cold path, not the page). All five: `sent 103 B`,
`received 37993–37998 B`, `test result: ok`.

**That contradicts the note in `tls-proxy/tests/live.rs`** ("measured at 2 of 3 runs" failing the
relayed handshake). Today it is 6/6 first-attempt across two sessions of testing. Keep the retry
machinery — a CDN edge closing mid-handshake is a real failure mode and one afternoon does not
disprove the older measurement — but the comment now overstates the flakiness; treat the retry as
insurance, not as the expected outcome.

## 0.32 Auditing a LIVE attestation on the real page found a shipping defect (v221)

The notary's signed attestation is served only on loopback (`:8081`), which is firewalled from the
internet — so a deployed attestation cannot be pulled for audit from outside. To audit real bytes,
run the same binary locally as the notary and relay a real sandbox session through it:

```bash
TLS_PROXY_LISTEN=127.0.0.1:8443 TLS_PROXY_HTTP_LISTEN=127.0.0.1:8081 \
  TLS_PROXY_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt ./tls-proxy/target/debug/tls-proxy
LIVE_NOTARY=127.0.0.1:8443 LIVE_SERVER=www.sandbox.paypal.com LIVE_PATH=/signin \
  cargo test --test live -- --ignored --nocapture
curl -s localhost:8081/attestations/<id> > /tmp/live-proxy-attestation.json
```

Feeding that file to `verify-proxy.html` (headless chromium, `#attestationFile`) **failed**:

```
NOT VERIFIED — do not rely on this attestation
❌ Expected fields, in the signed order
   unexpected shape — duplicate keys: none; top-level order:
   enclave_pubkey_pem, notarized_at, received_b64, received_len, received_sha256,
   sent_b64, sent_len, sent_sha256, server_name, session_id, signature_alg,
   signature_b64, truncated, version
```

Alphabetical — and that is the bug. `ProxyState` stored the attestation as a `serde_json::Value`;
`Value`'s object is a `BTreeMap` (no `preserve_order`), so `Json(value)` re-serialised the document
sorted, while the signature covers the struct's declaration order. The page rebuilds the signed bytes
from the text it is given (that is its whole design — it cuts the body out of your bytes), so **no
attestation served by the live proxy could ever verify**. The hermetic test missed it because it
re-parsed into a typed `SignedBody` before verifying, which silently restores the order.

Fix (v221, `tls-proxy/src/main.rs`):
- `ProxyState::attestations` stores the **exact signed text** (`String`), not a `Value`
  (`serde_json::to_string(&Attestation)` — flattened body in declaration order, then the envelope).
- `GET /attestations/{id}` returns that text verbatim as `application/json` (a `Response`, not
  `Json`), so the bytes on the wire are the bytes that were hashed.
- `list` parses a copy for its three-field projection; it never rewrites what it serves.
- Regression test in `tests/session.rs`: asserts the served text carries the 14 keys in signed order
  **and** that the signature verifies over the body slice cut out of that text — byte-level, the way
  the page does it, so a re-sorting store fails the test instead of shipping.

Proof after the fix, same live path (fresh notary, real sandbox transcript):

```
VERDICT: Signature and digests verified — this record is intact
✅ Expected fields, in the signed order
✅ Signed bytes reconstructed from your input   SHA-256 f5c16053…  · 51190 bytes
✅ Enclave signature                            RSA PKCS#1 v1.5 · SHA-256 · key SHA-256 894b96af…
✅ Request digest      103 bytes   SHA-256 c2d43008…
✅ Response digest     37993 bytes SHA-256 3219b888…
✅ Notarized server name  www.sandbox.paypal.com (port 443, resolved by the enclave)
✅ Notarization time      2026-11-09T01:50:16Z
⚠️ Key bound to the enclave hardware — not checked here (the page verifies the record, not who
   holds the key; documented, expected for this page)
```

`cd tls-proxy && cargo test` → 2 unit + 7 session tests pass (including the new byte assertion); the
live test stays `#[ignore]` as designed.

**Not yet deployed.** The prod notary still runs the pre-v221 binary, so its attestations still come
out sorted and still fail the page. Shipping this needs the normal image path (`--features oci`,
pins/digest rotation, `ReplaceSystemDisk`) — treat §0.32 as fixed-in-source, unproven-on-prod until
that image ships.

## 0.33 `e2e-sandbox.mjs` now refuses a production-configured enclave (2026-11-09)

The driver's name invites the §0.29 mistake, so it now checks the target before opening a browser:
it POSTs a minimal `/attest/login-session` (fresh P-256 key, random nonce) and reads the **signed**
`paypal_environment` / `authorize_base` — the only place the boot-time `staging` flag is observable,
since no route exposes the config. `staging:false` ⇒ refuse, exit **2**, print why plus the notary
test that *is* the sandbox coverage:

```
❌ REFUSING TO RUN — https://login.airma.de is configured for production, not sandbox.
   authorize_base: https://www.paypal.com/signin/authorize
```

- `PAV_ENCLAVE_HOST` (new, shared with the flow script so both agree on the target)
- `PAV_ALLOW_PRODUCTION=1` for a deliberate production run (needs a real account, not `sb-…`)
- Unreachable host ⇒ preflight failure, exit 2, nothing launched (verified with `127.0.0.1:9`).

## 0.34 v221 — the notary now serves what it signed, and prod runs it (2026-11-09)

The signed-text fix from §0.32 is on the wire. Prod `i-2ze1zdxis0hcsg91qbh5` runs image
**`m-2zeg00pu0glst9auyfs3`** (`paypal-tdx-esp-v221b-202611090830`), and its envelopes still match the
pins — with RTMR2 rotated because the proxy binary inside the initramfs changed.

### Two cycles, same discipline as §0.26/§0.27

| | Cycle A (rotation source) | Cycle B (shipped) |
|---|---|---|
| Image | `m-2ze9lskiq4fq01u57kzk` (`…v221a-202611090818`) | **`m-2zeg00pu0glst9auyfs3`** (`…v221b-202611090830`) |
| Disk | sha256 `230ecd09…`, md5 `19ce6eeb…` | sha256 **`92062f78…`**, md5 `a8cb1af4…` |
| initrd | `a3cabed7…` | **`a3cabed7…`** (identical — reproducibility held) |
| Enclave `/init` | `a729c827…` (unchanged from v220) | `a729c827…` |
| tls-proxy bin | `4ea7d2e5…` (first build carrying v221) | **`4ea7d2e5…`** |

Cycle A captured `/debug/envelope` from prod after its own swap; `node scripts/calculate-golden-rtmr.mjs
--report envelope.json --update` rotated **`EXPECTED_RTMR2` `44cfbca3… → 7badda87c1706377…`** in
`verify.html` **and** `index.html` (both carry a copy; rotating one is a silent audit failure on the
other page). MRTD / RTMR0 / RTMR1 / RTMR3 byte-held, `EXPECTED_ENCLAVE_SHA256` unchanged (the enclave
binary did not move). README's `verify.html` row now reads **265,825 bytes / `c4c7beb6…`**.

Cycle B rebuilt the same binary/initrd onto an ESP carrying the rotated auditor; the live envelope
then byte-matched the new pin:

```
MRTD   e0199499…   RTMR0 06a32a2f…   RTMR1 6fa03523…
RTMR2  7badda87…   RTMR3 0000…       binary_sha256 a729c827…   initrd a3cabed7…
```

Prod swap: `StopInstance --ForceStop true` (Stopped in 10 s) → flat-RPC `ReplaceSystemDisk`
`--SystemDisk.Size 1` (new disk **`d-2zec5a2xwy7qjxo41r3o`**) → `ModifyInstanceAttribute --UserData`
with the **live** blob captured before the swap (`5972` b64 chars, decoded sha `4fda21a7…`, readback
byte-identical) → `StartInstance` → **`/proxy/health` 200 at t+60 s**. All five routes 200 with
`ssl_verify_result=0`.

### Live proof on the shipped image

| Check | Result |
|---|---|
| `www.sandbox.paypal.com/signin` via `101.200.178.251:8443` | **attempt 1/3**, 16.1 s, `200 OK`, 103 B → 38,004 B |
| `www.sandbox.paypal.com/checkoutnow` | **passed on attempt 3/3**, 302, 108 B → 3,931 B; attempts 1–2 aborted socket (they are the `sessions_failed:2` seen below) |
| `/proxy/attestations` | `count:2`, both `host:0a191a6a`, ids `ecee7ce6…`, `46fa87d8…` |
| `/proxy/health` | `sessions_ok:2 sessions_failed:2 running:true` |

The `checkoutnow` retries are the §0.31 caveat in the flesh: a small 302 transcript is not automatically
the easy case, and the retry machinery earns its keep. `live.rs`'s header was corrected in this commit —
it claimed 2 of 3 runs failed; the measured figure is 6/6 first attempt on `/signin` today, so read the
attempt number instead of assuming flakiness.

### The attestation audit, on the released bytes

`GET :8081/attestations/<id>` is loopback-only by design (the public origin serves the list and
fingerprints hosts, never transcript bytes; `/proxy/attestations/<id>` answers **404**), so a deployed
attestation cannot be pulled for audit from the internet. The proof therefore runs the **exact released
binary** — `tmp-tls-proxy-bin`, sha256 `4ea7d2e5…`, the same bytes inside the deployed initramfs — as a
local notary, relays a real sandbox session (4.7 s, 103 B → 37,992 B, attestation `745a8545…`), and
feeds that URL's response to `verify-proxy.html`:

```
VERDICT: Signature and digests verified — this record is intact
✅ 11 signed fields first, in order, then the key and signature
✅ Signed bytes SHA-256 40fdd1f046764b8d… · 51186 bytes
✅ Enclave signature  RSA PKCS#1 v1.5 · SHA-256 · key SHA-256 84f43322…
✅ request  103 bytes   SHA-256 c2d43008…
✅ response 37992 bytes SHA-256 16c4a184…
```

Same page, same record type, the binary that is actually deployed. `cargo test` in `tls-proxy` (2 unit +
7 session incl. the byte-order assertion) and the auditor suites (`calculate-golden-rtmr --selftest`,
`test-verify-proxy.mjs` 44/44) stay green.

### Self-heal was pointing at v220

`watchdog/dist/config.json` still said `spec.imageId = m-2ze7c8jev53ikz43ybj8`. Left alone, a spot
preemption would have rebuilt prod **on the pre-v221 notary** — the fix would vanish exactly when the
operator is least likely to look. Refreshed to `m-2zeg00pu0glst9auyfs3` (same live `userDataB64`), then
`bash watchdog/deploy-oos-watchdog.sh deploy` (templates + heartbeat chain `exec-ee4e1aac…`),
`deploy-spot-notice.sh deploy`, and a real reconcile: `Success {"instanceId":"i-2ze1zdxis0hcsg91qbh5",
"eipStatus":"InUse"}` — found prod, bound nothing, created nothing.

### Relay traps (re-hit and now written down)

1. **Presigned PUT must use the virtual-host form** — `bucket.oss-cn-…aliyuncs.com`. The path form
   answers `SecondLevelDomainForbidden` (or, for the same URL, a 403 at 64 KiB in).
2. **GET needs a GET-verb signature.** Reusing the PUT-presigned URL for a download returns a ~3.8 KB
   XML error body, which `curl -o` happily saves: the relay then "downloads" an error page. Sign the
   verb you will actually use.
3. **The Beijing image bucket is `paypal-tdx-image-1792145409`**, not `paypal-auth-vm` (that name is
   the *prefix* inside it). Both Beijing buckets refuse the public endpoint entirely
   (`PublicEndpointForbidden`), so the relay hop is mandatory; `aliyun oss cp` cannot be used from here.
4. Relay legs were green in seconds: `get 55,574,528 B md5 19ce6eeb…` → `put-http=200` →
   `readback` byte-identical (`READBACK-OK`), same for `a8cb1af4…`.

### State left behind

Prod `i-2ze1zdxis0hcsg91qbh5`, Running, image `m-2zeg00pu0glst9auyfs3`, disk `d-2zec5a2xwy7qjxo41r3o`
(1 GiB `cloud_auto`), EIP `101.200.178.251`, `user_data` `4fda21a7…`; images `v221b` (live), `v221a`
(rotation probe — delete once reviewed), `v220` (rollback), `v218`, `v217b`, `v216b`, `v216a`;
`relay188` stopped in economy mode. Local released-binary notary stopped; repo tree clean.

## 0.36 v222 — a prover can fetch their own transcript from anywhere (2026-11-09)

The notary attests a session and parks the record in guest RAM. Until now the only
way to that record was a shell on the VM (`GET :8081/attestations/<id>`) or the
public list, which deliberately withholds transcripts. A prover on a managed
importer therefore could not get the evidence they had just produced. v222 adds
the missing path:

```
GET https://<domain>/proxy/attestations/{id}?sent_sha256=<64hex>&received_sha256=<64hex>
```

### Why the capability is the transcript

TLSNotary gives this notary nothing to hand a prover after the session: the
protocol carries no prover-chosen nonce (checked in
`crates/core/src/lib.rs` — `VerifierOutput` is server name, transcript and
commitments), and the notary never speaks after `proof` finishes, so a
server-generated token could not reach the prover at all. What both sides
already hold is the revealed transcript: the prover built it, and the record
signs over `SHA-256` of its two halves.

So presenting **both digests** is the capability — a knowledge proof, not a
password. The public list never carries them, a wrong pair is answered exactly
like an unknown id (same status, same body minus the id the caller supplied), and
the rendered record is relayed as **text**, never re-serialised, because the
signature covers the stored field order (v221).

| Call | Answer |
|---|---|
| both digests match | `200` the signed record, byte-for-byte |
| one digest, or a malformed one | `404 {"error":"no such attestation in this boot"}` |
| unknown id | same `404` |
| loopback `:8081/attestations/{id}`, no query | unchanged: served, operator access |
| `:8081` half pair | `400 sent_sha256 and received_sha256 go together` (client bug, not an oracle) |

`tls-proxy/tests/live.rs` now prints the pair on success — the prover harness is
the only party that can compute it, which is the point.

### Build and pins

| | Cycle A (rotation source) | Cycle B (shipped) |
|---|---|---|
| Image | `m-2zeexizgfuirnhijit17` (`…v222a-202611090942`) | **`m-2ze484qn2p2c3udbhxhb`** (`…v222b-202611090952`) |
| Disk | sha256 `dd66129e…`, md5 `38980bdb…` | sha256 **`cd89b087…`**, md5 `536544d5…` |
| initrd | `3c883019…` | **`3c883019…`** (identical) |
| Enclave `/init` | `0616aed1…` (changed: new route + relay) | `0616aed1…` |
| tls-proxy | `a13eabe7…` (changed: gated get) | `a13eabe7…` |

Both components moved this time, so **two** pins rotated, not one: `EXPECTED_RTMR2`
`7badda87… → 4de4917a…` and `EXPECTED_ENCLAVE_SHA256` `a729c827… → 0616aed1…`
(`index.html` is a byte-copy of `verify.html`; both were updated, then re-checked
identical). MRTD / RTMR0 / RTMR1 / RTMR3 held. `verify.html` is now
**265,825 bytes / `43de8479…`** (README row updated). Live envelope after the B
swap matched every pin, `/proxy/health` 200 at **t+60 s**.

Promotion took the documented two cycles: import A → swap prod → capture
`/debug/envelope` → rotate → rebuild B → relay → import → swap again. Disk
`d-2ze024y1756n7282gb2y`, `user_data` re-pushed (`5972` b64, sha `4fda21a7…`).

### Proof on the shipped image

| Check | Result |
|---|---|
| `www.sandbox.paypal.com/signin` via `101.200.178.251:8443` | attempt 1/3, 16.5 s, 200 OK, 103 B → 37,998 B |
| `www.sandbox.paypal.com/checkoutnow` (on B) | attempt 1/3, 25.3 s, 302, 108 B → 3,931 B |
| public list | `host:0a191a6a`, ids `96cb9cc6…` (A) and `41a1f827…` (B) |
| gated download (A record) | `200`, 52,081 B; audit page: **"Signature and digests verified"** (digests `c2d43008…` / `205a6e96…`) |
| gated download (B record) | `200`, 6,664 B; audit page: **"Signature and digests verified"** (digests `dcbe9990…` / `a66ec0e7…`) |
| no digests / wrong digest | `404` both, same shape |

The two live records were fetched over the public origin from this machine —
no shell on the VM, no loopback hop.

Local pre-deploy smoke on the debug build pinned the same behaviour end to end:
gated read byte-identical to the ungated one, wrong digest `404`, half pair
`400`, another session's id with this pair `404`.

Tests: `tls-proxy` 3 unit (incl. the digest matcher and the "one right, one
wrong / prefix / junk / empty-pair" cases) + 7 integration (the gated read is
asserted against a session the real binary recorded); enclave
`download_guards_are_width_and_hex_only`,
`download_relay_does_not_reorder_signed_bytes`,
`download_answers_404_when_no_proxy_is_configured`.

### Traps re-hit (all cost a round trip)

1. **OSS V1 signature covers Content-Type.** A presigned PUT signed with an
   empty content type and sent with `application/octet-stream` answers
   `SignatureDoesNotMatch`; send no `Content-Type` at all.
2. **A Hong Kong bucket's `-internal` endpoint is unreachable from a Beijing
   relay** (curl `http_code=000` after 20 s). Use the HK **public** endpoint for
   that leg; only the Beijing leg is intranet.
3. **The importer looks under `paypal-auth-vm/`** — a correctly uploaded object
   at the bucket root still fails `InvalidOSSObject.NotFound`. The relay PUT
   must use the prefixed key.
4. **`DescribeInstanceAttribute` does not return `UserData`** (empty on this
   account); `DescribeUserData` does. Capture before the swap, re-push after.
5. Artifacts stay inside the built image: `podman cp` them out, or the output
   directory silently keeps the previous cycle's files (their hashes look fine).

### State left behind

Prod `i-2ze1zdxis0hcsg91qbh5`, Running, image `m-2ze484qn2p2c3udbhxhb`, disk
`d-2ze024y1756n7282gb2y`, EIP `101.200.178.251`. Watchdog `dist/config.json` and
all three OOS templates now name v222b; a real reconcile answered
`Success {"instanceId":"i-2ze1zdxis0hcsg91qbh5","eipStatus":"InUse"}` (created
nothing). Images kept: v222b (live), v222a (rotation probe), v221b, v220
(rollback), v218, v217b, v216b, v216a. `relay188` running for the transfer;
stop it economically when done. Probe-image cleanup is the operator's call — same
as v221a, which was deleted with its snapshot on request.

## 0.37 v223 — the attestation names the TLS key, and the code can be sealed to it (2026-11-09)

A report used to carry the TLS *certificate* but never said, in so many words,
"this is the key this instance holds". v223 publishes both halves of that
statement — `session_context.tls_public_key_pem` (SPKI) and
`tls_public_key_sha256` — in the data-free `/debug/envelope` report and in the
login report alike, and accepts the PayPal code sealed to that key:
`GET /callback?state=…&code_enc=<base64 RSA-OAEP/SHA-256>`.

### What it buys

The key is RSA-4096, generated **in RAM on every boot** and never written to
disk (the ACME key and the listener key are the same object). So a seal made to
a verified report's key can only be opened by the instance that report
described. That is the two-step hand-off the user asked for:

1. audit the report (measurements, TLS key fingerprint) **before any user data
   exists** — `/debug/envelope` is exactly that;
2. seal the code to the key that report named and send it in place of `code`.

A replaced VM, a swapped image, or a later boot answers `400 cannot open the
sealed code`: its key was born after the attestation the user checked.

### Refusals, verified live on v223b

| Attempt | Answer |
|---|---|
| sealed to the **current** report's key (bogus `state`) | `403 Invalid or expired session` — i.e. the seal opened, and the failure is the state, not the ciphertext |
| sealed to a **previous boot's** key, replayed | `400 cannot open the sealed code with this boot's TLS key` |
| sealed to an unrelated key | same `400` |
| `code` **and** `code_enc` in one request | `400 send the code either sealed (code_enc) or in the query, not both` |
| ciphertext of the wrong length, or not base64 | `400`, bounded before any RSA operation |

The query form (`code=…`) is untouched, so nothing that worked before v223
changes shape. `verify.html` was not modified: the key lives in the signed
report it already renders, and the README documents the `openssl pkeyutl`
recipe and the URL shape.

### Release

| | Cycle A (rotation source) | Cycle B (shipped) |
|---|---|---|
| Image | `m-2zedfw4w7k4n7bfsgsso` (`…v223a-202611091045`) | **`m-2ze9lskiq4fq22uadm3j`** (`…v223b-202611091057`) |
| Disk | sha256 `08997886…`, md5 `c234d209…` | sha256 **`4e35437a…`**, md5 `acba09dc…` |
| initrd | `722f1848…` | **`722f1848…`** (identical) |
| Enclave `/init` | `5acc1eb5…` | `5acc1eb5…` |
| tls-proxy | `a13eabe7…` (unchanged — v222's binary) | `a13eabe7…` |

Rotated: `EXPECTED_RTMR2 4de4917a… → 068f0efc…` and `EXPECTED_ENCLAVE_SHA256
0616aed1… → 5acc1eb5…`; MRTD / RTMR0 / RTMR1 / RTMR3 held. `verify.html` is now
**`f8bd612c…`** (README row updated). Prod disk `d-2ze2zxb3t87jivl7tge`,
`user_data` re-pushed (`4fda21a7…`), `/proxy/health` 200 at **t+55 s** both
cycles. Live reports: key fingerprint `e0f08349…` on A, `c3a50c8e…` on B — the
per-boot rotation is visible in the attestation itself, which is the point.

Watchdog `dist/config.json` and all three OOS templates moved to v223b; a real
reconcile answered `Success {"instanceId":"i-2ze1zdxis0hcsg91qbh5","eipStatus":"InUse"}`.

### Traps hit this cycle

1. **A stopped relay cannot run Cloud Assistant** — `relay188` was stopped for
   economy after v222, and every transfer silently produced no output until it
   was started again. Check `Status` first.
2. **One relay invocation must stay under the ~60 s RunCommand default.** The
   HK GET (public endpoint, ~25 s at 2.2 MB/s) plus the Beijing PUT does not
   fit; splitting GET and PUT into two calls works, because `/tmp` survives.
3. **The HK presigned PUT can 403 at 64 KiB** with a freshly signed URL
   (`SignatureDoesNotMatch` semantics vary with the attempt). Regenerating the
   URL and retrying succeeded; always confirm `put_hk=200 sent=<full size>`
   before trusting the object.
4. **A truncated hash is not a hash.** Substituting a pin from a 16-character
   preview silently wrote a fabricated 64-hex value into `verify.html`;
   `grep -c <true hash>` caught it. Always paste the full digest from
   `sha256sum`.

Test coverage: `cargo test` 44/44, including a seal/open roundtrip
(`a_code_sealed_to_the_reported_key_opens_and_a_foreign_key_does_not`) that also
pins the refusal of a foreign key, junk base64, wrong-size seals and tampered
ciphertext.

### State left behind

Prod `i-2ze1zdxis0hcsg91qbh5`, image `m-2ze9lskiq4fq22uadm3j`, disk
`d-2ze2zxb3t87jivl7tge`. Images kept: v223b (live), v223a (rotation probe),
v222b, v221b, v220 (rollback), v218, v217b, v216b, v216a. `relay188` running.

---

## 0.38 — v224: the seal step and the attested-key row land in verify.html

**Ask.** (a) Put the seal step in `verify.html` — take the attested key, encrypt
the PayPal code in the browser, open the callback in one click. (b) Show the
attested TLS key fingerprint and flag any report whose key differs from the one
this browser sealed to. (c) Delete the v223a rotation probe and the older
v216/v217 probes.

**No enclave change, no redeploy.** Everything here is the auditor page plus
cloud housekeeping; the deployed image stays `m-2ze9lskiq4fq22uadm3j` (v223b),
whose `/callback` already accepts `code_enc`.

### (a) The seal card (`#sealCard`)

The audit's 🔑 row fills `#sealKeyInput` with `session_context.tls_public_key_pem`.
The user pastes the PayPal redirect URL (or a bare code) and presses
**“Seal the code and open the callback”**:

1. `parseCallbackUrl` takes `code` **and** `state` from the pasted URL — the two
   can never be paired by hand wrongly, and the code never travels in the clear.
2. WebCrypto `importKey('spki', …, {name:'RSA-OAEP', hash:'SHA-256'})` then
   `encrypt({name:'RSA-OAEP'}, …)`. **Empty OAEP label; MGF1-SHA-256** — the exact
   parameters `rsa_oaep_open` in `src/main.rs` sets (`Padding::PKCS1_OAEP`,
   `set_rsa_oaep_md(sha256)`, `set_rsa_mgf1_md(sha256)`).
3. Ciphertext (512 B for RSA-4096) is shipped as **standard base64 with padding**
   — `code_enc` is decoded with `STANDARD`, not URL-safe, and `encodeURIComponent`
   protects the `+`.
4. The page records `{host, sha256, at}` in `localStorage` under
   `pav_sealed_tls_key_v1` and navigates to `/callback?code_enc=…&state=…`.
   **The code itself is never stored** (checked by test).

Honest limit, stated on the card: the user has to see the code before the enclave
does. The flow is “log in in another tab, press Esc/Stop when PayPal bounces back
to `/callback?code=…`, copy that URL”. Without that (or a redirect_uri you
control), the enclave consumes the code on arrival and there is nothing to seal —
the card cannot manufacture that property.

### (b) The attested-key row (`#tlsKeyCheck`)

Rendered after the TLS-certificate row, from the report:

- `sha256(SPKI DER of tls_public_key_pem)` vs `tls_public_key_sha256` —
  **self-consistency**, refused when they disagree (internally inconsistent
  report).
- vs the remembered seal: **different fingerprint ⇒ audit FAILS** with
  “DIFFERENT BOOT — this is not the VM you sealed to”, naming both fingerprints
  and the host the seal was made for. The TLS key is minted in RAM per boot and
  never persisted, so a different key is a different (or rebooted) instance.
  No sealed record ⇒ informational green row with the fingerprint.
- A report with no key at all (pre-v223, or listener not up) is an amber skip,
  never a pass.

### Verification actually run

- **Wire compatibility:** node WebCrypto (same parameters as the page) sealed a
  code; `openssl pkeyutl -decrypt … oaep/sha256/mgf1-sha256` opened it to the
  plaintext. 512 B ciphertext, 684-char base64.
- **Live, against prod:** a browser-style seal to the live key
  (`c3a50c8e…`) answered **403 invalid session** (the seal opened; the junk state
  failed), while the same shape sealed to a foreign key answered **400 “cannot
  open the sealed code with this boot’s TLS key”**. Declared vs computed
  fingerprints matched (`c3a50c8e…`).
- **Page-level:** `node /tmp/test-seal-page.mjs` eval’d the real page script with
  DOM stubs and drove the actual button — 16/16, including “the shell recipe
  opens it to the PayPal code”, “the code is NOT stored”, “no key → refuses”,
  “code without state → refuses”, “a different key is called out”. (That script
  is an ad-hoc harness, not committed.)
- `scripts/test-verify-security.mjs` **492 passed / 0 failed** once the README
  digest was rotated (the Pages check needs the push). `scripts/test-verify-proxy.mjs`
  44/44.
- `verify.html` 283,700 B / `1f3c8ba0d34b571483fc1e0f7d9807bd0867587d4fd0b354cb0f7125acfd4432`,
  `index.html` byte-identical, README digest row updated. No pin rotated — the
  page does not feed RTMR2 (it ships on the unmeasured ESP).

### (c) Probe cleanup

Deleted with `DeleteImage … --Force true`, then their snapshots:

| Image | Snapshot |
|---|---|
| `m-2zedfw4w7k4n7bfsgsso` (v223a) | `s-2zedfw4w7k4n7bfn3f9i` |
| `m-2zeibiq6bbe5x9n0o94c` (v216a) | `s-2zeibiq6bbe5x9n2a552` |
| `m-2ze2ncqumj1veapx9wt4` (v216b) | `s-2ze2ncqumj1veappt8v1` |
| `m-2ze7liy7l0dobz3gg77g` (v217b) | `s-2ze7liy7l0dobz3krl2y` |

9 images / 9 snapshots → **5 / 5**, still 1:1: v223b (live), v222b, v221b, v220,
v218. `DescribeInstances` confirmed nothing but prod (`m-…uadm3j`, Running) and
the stopped `relay188` before deletion. Note the CLI's `DescribeImages` fails with
`InvalidOperation.NotSupportedEndpoint` for `cn-beijing-i`; `/tmp/ecs-call.mjs`
(signed RPC, `RegionId=cn-beijing`) works.

`relay188` left **stopped** (economy mode) after this cycle.

---

## 0.39 — v225: sealed redirect (no race), second seal slot, seal harness in CI

**Ask.** (a) Make the seal flow work without racing the redirect — the enclave
hands the user's browser a `redirect_uri` the browser controls, so the code
arrives sealed by construction. (b) Commit the page-level seal harness as
`scripts/test-seal-page.mjs`. (c) Extend the DATA-FREE report with a second seal
slot so a code and a custom nonce can be bound to the same boot in one step.

### (a) Caller-selectable, allowlisted `redirect_uri`

- `Config.seal_redirect_uris` (aliases `paypal_redirect_uris`, `redirect_uris`)
  is parsed once at startup into `AppState.allowed_redirect_uris`; bad entries
  warn + drop. The default `/callback` URL is always present.
- `normalize_redirect_uri` deliberately does **not** normalise (no trailing
  slash, no case folding): PayPal compares byte-for-byte and so does the
  allowlist, so a "helpful" rewrite would silently target an unregistered URI.
  https only, no query/fragment/userinfo/space.
- `/attest/login-session` takes an optional `redirect_uri`, rejects anything
  off-list with 400, signs the accepted value into `signed_fields`, and binds it
  into the untrusted `state` as `"u"`. `/callback` re-validates `"u"` against the
  allowlist and uses it for the token exchange (previously the exchange would
  have used the fixed value and failed for any other redirect). Old state tokens
  without `"u"` fall back to the default.

### (b) Second seal slot

- New independent RSA-4096 boot key (`seal_pubkey_pem` / `seal_private_key`),
  generated after the TLS key, before the listener serves.
- Both reports publish `session_context.seal_slots = {code:{pem,sha256},
  nonce:{pem,sha256}}`; the code slot is the TLS key, the nonce slot the new key.
- **The slots also travel in the signed login response** (`signed_fields.seal_slots`)
  so the page can seal on the return leg with **no attestation fetch** — that
  keeps v180's rule intact ("no pre-login attestation"; the harness asserts the
  page never references `/debug/envelope` again) and means the page seals to a
  key this enclave signed, not to a key read off an unverified route.
- `/callback` accepts `nonce_enc`, opened with the nonce key only (a code sealed
  to the nonce key answers 400, and vice versa — `the_two_seal_slots_do_not_interchange`).
  The nonce is canonicalised like `custom_info` (≤512 B, empty → `NONE`) and the
  login report signs `user_nonce` + `user_nonce_sha256`.

### (c) Page

- Login card: checkbox `#sealedRedirectToggle` sends
  `redirect_uri = location.origin + location.pathname`; the enclave-signed value
  must equal it or the page reports **REDIRECT SUBSTITUTION**.
- Marker `pav_sealed_login_v1 = {host, redirect, state, p_enc, slots, nonce, at}`
  (never the code). On return, `finishSealedLogin()` seals code (and optional
  nonce), verifies each slot's signed `sha256` against the sealed fingerprint,
  clears the code from the address bar, stores the nonce commitment as
  `pav_sealed_nonce_v1 = {sha256, at}`, and opens `/callback?code_enc…&nonce_enc…&state…`.
- Seal card: new `#sealNonceInput` (optional), so a pasted redirect URL seals
  both slots by hand too. New audit block "6c": slot PEM→sha256 self-consistency
  for both slots, plus `report.user_nonce_sha256` == the nonce this browser
  sealed (missing/mismatch = hard fail, `#nonceCheck` row).

### (d) The harness is committed

`scripts/test-seal-page.mjs` (two modes, both offline and deterministic):

- `card` — pasted key/code/state, the button driven through the page's own
  script with DOM stubs; opens the result with `openssl pkeyutl`.
- `sealed-return` — seeds the login marker, sets `location.search` to a real
  PayPal return URL, and checks that the page jumps to `/callback` on its own
  with the code sealed and absent from the URL; also pins the slot
  self-consistency comparison and fails if the page fetches anything.

CI: `.github/workflows/build-attest.yml` runs both modes right after the
`verify.html` security suite.

### Verification

- `nix-shell -p openssl pkg-config --run "cargo test"` → **46 passed, 0 failed**
  (includes the two new unit tests).
- `node scripts/test-seal-page.mjs card` → green; `sealed-return` → green.
- `scripts/test-verify-security.mjs` **492 passed / 1 failed** — only the Pages
  parity check, which resolves once this commit lands on `main`.
  `scripts/test-verify-proxy.mjs` 44/44.
- `verify.html` 299,638 B / `11435c5e28c7e22acac20c5d109ede8214a405ed404cac9e21f6d53b626eb9f1`,
  `index.html` byte-identical, README digest row rotated. No pin rotated (the
  page ships unmeasured).

### Deployment

Shipped the same day — see §0.40. (Before the rotation this section noted that
v223b had neither feature; that caveat no longer applies.)

---

## 0.40 — v225 deployed: two seal slots and the sealed redirect are live

**Ask.** Rebuild and rotate the enclave image so the second seal slot and the
caller-chosen redirect go live.

### Release

| | Value |
|---|---|
| Image | **`m-2ze907s3a43t8l3sdh9r`** (`paypal-tdx-esp-v225c-202611091609`) |
| Disk | sha256 **`462dbedd…`**, md5 `dea0b4d1…` (49,283,072 B, QCOW-less RAW ESP) |
| Prod disk | `d-2ze06rpqpzc6zztfu0fk` (1 GiB `cloud_auto`) |
| Instance | `i-2ze1zdxis0hcsg91qbh5`, EIP `101.200.178.251`, TLS 200 at **t+50 s** |
| Config | `user_data` re-pushed while stopped — 6,160 B b64, `seal_redirect_uris` read back |

Two rotations happened. The **first** image (`m-2ze9kw63…`, disk `0e92986b…`)
was already serving when a live probe showed the nonce refusal saying *"cannot
open the sealed nonce with this boot's **TLS key**"* — the nonce slot opened with
the nonce key, so the diagnostic named the wrong slot. Since the live disk must
be bitwise reproducible from the repo, a wording fix is still a new disk: the
source was corrected (`rsa_oaep_open` now takes the slot name), `cargo test`
re-pinned the message in `the_two_seal_slots_do_not_interchange`, and the second
build (`m-2ze907s3…`) became prod. The first image and its snapshot were
deleted.

### Live verification (both boots)

```
GET /debug/envelope → session_context.seal_slots.code.sha256 == tls_public_key_sha256
                    → seal_slots.nonce.sha256 is a DIFFERENT key
POST /attest/login-session  redirect_uri=<Pages URL>  → 200, signed_fields carries
     redirect_uri + both slots, signature verifies (PKCS1-SHA256 over sorted JSON)
POST /attest/login-session  redirect_uri=https://evil.example/steal → 400
     "redirect_uri is not one of this enclave's allow-listed redirect URIs …"
POST /attest/login-session  redirect_uri=http://…                     → 400
     "redirect_uri must be an https:// URL with no query string, fragment or userinfo"
POST /attest/login-session  (no redirect_uri)                         → 200 (default)
GET /callback?code_enc=<sealed to code slot>&state=<live>  → opened, then
     500 "Token exchange failed with PayPal"  (the fake code was decrypted)
GET /callback?code_enc=<sealed to NONCE slot>&state=<live> → 400
     "cannot open the sealed code with this boot's TLS key"
GET /callback?…&nonce_enc=<sealed to CODE slot>            → 400
     "cannot open the sealed nonce with this boot's nonce key"
GET /callback?…&nonce_enc=<sealed to NONCE slot>           → 500 PayPal (opened)
```

The `/callback` probes used a real session minted by the same boot, so they
prove the slots are independent end-to-end and not just in unit tests. Per-boot
keys rotated as designed: code `ca62bb3e…`/`407530d7…`, nonce `514f6f74…`/
`11ad5fa0…` across the two boots.

### Traps hit this cycle

1. **`DescribeImages` returns TotalCount 0 by ImageId** on this endpoint but
   finds the image by `ImageName` — the import helper's ID path silently looks
   empty until the name path is used (`/tmp/ecs-call.mjs`, `RegionId=cn-beijing`).
2. **`RunCommand` needs `--InstanceId.1`, not `--InstanceIds`** — the plural flag
   is rejected outright by this CLI build.
3. **A 49 MB HK GET does not fit in one RunCommand**, even with `--Timeout 300`
   (the invocation fails with an empty output at the ~60 s mark). Ranged
   resumption (`curl -C -`, one invocation per ~45 s, checking `stat -c%s`) took
   5 rounds the first time and 1 the second.
4. **The Beijing intranet PUT must be detached.** `setsid … &` inside the
   command, then poll a status file: a foreground PUT outlives the invocation
   too, and the object is still written correctly, but the tool call reports
   failure and the retry risk doubles the upload.
5. **`StartInstance` immediately after `ReplaceSystemDisk` is dropped** — the
   instance stayed `Stopped` for two minutes until start was re-issued. Always
   poll for `Running` rather than assuming the start stuck.
6. **`python3` is not on this host**; mutation-testing a page guard needs node.

### State left behind

Prod `i-2ze1zdxis0hcsg91qbh5` (Running) on **`m-2ze907s3a43t8l3sdh9r`**, disk
`d-2ze06rpqpzc6zztfu0fk`. Images/snapshots back to **5 / 5**: v225c (live),
v223b (rollback), v222b, v221b, v220 — v218 and the uncorrected v225 were
deleted with their snapshots. `relay188` **Stopped** (`StopCharging`).
Staging objects `paypal-tdx-relay-1792227992/disk225.raw|disk226.raw` and
`paypal-tdx-image-1792145409/paypal-auth-vm/disk225.raw|disk226.raw` remain.
Local `/tmp/pav-userdata*.{b64,json}` (mode 600, live secrets) and the OSS
presigner `/tmp/oss-sign.mjs` remain — delete before handing this box on.

### Still manual

**PayPal must register the auditor URL** as a Return URL for the app
(`https://leonardopedro.github.io/verifiedUniqueAliases/verify.html`), or the
checkbox path dies at the authorize screen. The enclave side is already live and
allowlisted; see README → *Adding a sealed-redirect URI*.

---

## 0.41 — rotation is one command, and the custom-domain redirect (2026-11-09)

### `rotate-alibaba.sh`

The v225c rotation was run by hand, and each hop had a failure mode that boots
the wrong bytes: a truncated OSS upload, an import from a stale object, a
`user_data` push before the swap (discarded with the old disk). The sequence is
now a checklist script with a **digest gate per hop**, refusing to continue
until the previous one proves itself:

| Phase | Gate |
|---|---|
| preflight | `verify.html` == `index.html`, config JSON parses, instance exists, tree maps to a commit |
| build | disk sha256/md5/size + binary sha recorded (fails if the ESP did not assemble) |
| stage | OSS `Content-Length` == local size **and** `ETag` == local md5 — on the HK object *and* on the Beijing object (relay legs), or `RELAY_MODE=direct` |
| import | `Description` read back and must carry the local `sha256=`, `Features.NvmeSupport=supported`, status `Available` |
| rotate | `StopInstance --ForceStop` → `ReplaceSystemDisk --SystemDisk.Size 1` → `ModifyInstanceAttribute --UserData` → readback sha256 → start; prints the rollback disk |
| verify | HTTPS 200, `boot_measurements.binary_sha256` == the binary just built, `check-manifest-parity.mjs` → **PARITY OK** |

Two calls the CLI cannot make are committed as `scripts/`: `ecs-rpc.mjs` (the
CLI rejects `Features.NvmeSupport`) and `oss-presign.mjs` (the relay legs need
presigned HK PUT/GET and Beijing intranet PUT). `import-alibaba-image.sh` now
honours `ALI_IMAGE_NAME` so the checklist can name the image.

Exercised live, read-only: `--dry-run` (all six phases, digests of the deployed
disk) and `--from verify` → `binary f2ea2d1b…` matches the envelope,
**PARITY OK**. The write phases were **not** re-run (prod was already on v225c);
they are the literal §0.40 command sequence plus assertions.

### Custom domain: CNAME → raw is not enough

A plain CNAME at `raw.githubusercontent.com` looks like it serves the auditor,
but the browser validates the certificate against the custom hostname and raw's
cert covers only `*.githubusercontent.com`:

```
$ curl --resolve audit.airma.de:443:185.199.108.133 \
    https://audit.airma.de/leonardopedro/verifiedUniqueAliases/main/verify.html
curl: (60) SSL: no alternative certificate subject name matches target hostname 'audit.airma.de'
```

A proxied CNAME (`airma.de` is on Cloudflare — `vick/teagan.ns.cloudflare.com`)
fixes only the certificate. It still **relays the origin's content type**, and
raw sends:

```
content-type: text/plain; charset=utf-8
x-content-type-options: nosniff
content-length: 301312          ← the right bytes, the wrong type
```

With `nosniff` the browser refuses to execute it: the visitor sees the HTML
source and no seal flow runs. jsDelivr's `/gh/` path answers the same way. So a
custom domain needs a front that emits `text/html` — a ~20-line Cloudflare
Worker (snippet in README → *Hosting the page on a custom domain*), Netlify,
nginx, or GitHub Pages' own CNAME. Verified for all candidates: the bytes are
the committed page, sha256 `b9cce40b…`, identical to the copy inside the
measured ESP.

**Not done, because it needs the account owner:** the Worker + record, then the
config-only rotation (no rebuild):

1. deploy the Worker on `audit.airma.de/*`, serving `text/html`;
2. add `https://audit.airma.de/leonardopedro/verifiedUniqueAliases/main/verify.html`
   to `seal_redirect_uris` (Stop → `ModifyInstanceAttribute --UserData` → Start);
3. register the same string as the PayPal app's Return URL.

Then verify: `curl -I` shows `text/html`, page digest == `b9cce40b…`,
`/attest/login-session` returns it signed, and a real login lands back on that
page and jumps to `/callback?code_enc=…`. Note `@main` is mutable behind a
permanently registered Return URL — pin `@<commit>` if the page must be frozen
per release.

### Browser E2E for the sealed redirect: blocked, precisely

No browser on this host, no PayPal account credentials here, and PayPal answers
**HTTP 403** at the authorize screen to a request from a datacenter IP (body
echoes the `redirect_uri` and `state` but serves no login form). The enclave
side is proven by curl (signed `redirect_uri`, both slots, slot interchange
refused); the browser leg needs a human session after the Return URL is
registered.

### Cleanup state

`/tmp/pav-userdata.b64` and `/tmp/pav-userdata-v225.json` deleted (live
secrets). Staging OSS objects (`disk225.raw|disk226.raw` in both buckets) remain
— deleting them needs the relay started, which costs more than they do.
`/tmp/pav-userdata.json` (30 Oct, superseded) remains.

---

## 0.42 — v226: the landing page links the page that can actually seal (2026-11-09)

### What shipped

The enclave landing (`https://login.airma.de/`) had one button: *Download
verify.html* from `raw.githubusercontent.com`, which lands as `file://` — a copy
that can **never** receive a PayPal code, so the sealed redirect was unreachable
for anyone who followed the page they arrived on. It now has a second, blue
button — *Open verify.html in this browser* →
`https://leonardopedro.github.io/verifiedUniqueAliases/verify.html` — and a
fourth step telling the user to tick **Let this page receive the code and seal
it** before logging in. The GitHub-served copy is `text/html`, so it executes
and can be the Return URL.

The custom-domain idea was dropped after measurement: a plain CNAME to raw
fails certificate validation, and a **proxied** CNAME fixes only TLS — raw (and
jsDelivr) send `text/plain` + `nosniff`, so the browser renders source and runs
nothing. README → *Hosting the page on a custom domain* now states the real
requirement (`text/html`) and carries a ~20-line Worker for an operator who
wants a custom hostname.

### Two rotations, both driven by `rotate-alibaba.sh`

| | image | disk sha256 | binary | RTMR2 |
|---|---|---|---|---|
| v226 | `m-2ze3vnn8vo8p7rpaunsi` (deleted) | `08e1c9bc…` | `04cdf40c…` | `3ca54e8d…` |
| **v226b (live)** | **`m-2ze4m8a0ea3g4p7s5eqy`** | **`19e1a0d0…`** | `04cdf40c…` (identical) | `3ca54e8d…` (held) |

1. **v226** carried the landing change. Binary → initrd → **RTMR2 rotated
   `068f0efc…` → `3ca54e8d…`** (MRTD/RTMR0/1/3 held), so the pins in
   `verify.html`/`index.html` were stale and every user would have been shown
   the *"this auditor copy is stale"* warning.
2. Pins rotated with the documented procedure (`calculate-golden-rtmr.mjs
   --report … --update`: `EXPECTED_RTMR2` and the informational
   `EXPECTED_ENCLAVE_SHA256` → `04cdf40c…`), page mirrored to `index.html`,
   `README` digest rows moved to `b9cce40b…` / 301,928 B, pushed so Pages
   rebuilds.
3. **v226b** rebuilt the ESP with the rotated page only: binary came out
   **byte-identical** and RTMR2 stayed `3ca54e8d…` — the reproducibility claim
   holding across a page-only release, which is what lets the pin be rotated
   before the final deploy.

Prod: `i-2ze1zdxis0hcsg91qbh5`, disk **`d-2zebrw0u4iota2v51ovo`**, user_data
pushed and read back byte-identical (6,160 B b64, sha256 `946cfb4d…`).

### Live proofs

- landing serves **both** buttons (`Download verify.html` + `Open verify.html in
  this browser` → the Pages URL);
- envelope `boot_measurements.binary_sha256 = 04cdf40c…` == `EXPECTED_ENCLAVE_SHA256`;
- live RTMR2 `3ca54e8d…` == `EXPECTED_RTMR2` (parsed from the quote by
  `calculate-golden-rtmr.mjs --report`, not taken from the envelope's word);
- envelope `disk_manifest.verify.html = b9cce40b…` == repo page == what Pages
  serves;
- `check-manifest-parity.mjs` → **PARITY OK** (6 same, `NvVars` excluded);
- suites: security **500/500**, proxy **44/44**, seal-page `card` and
  `sealed-return` both green.

### Trap found (now fixed in the script)

The first `stage` run died on the HK presigned PUT with
`InvalidAccessKeyId`. The profile is an **OAuth-mode** login: only an `aliyun`
CLI call refreshes the STS token in `~/.aliyun/config.json`, and the build had
outlived the token. `rotate-alibaba.sh` now pokes `aliyun sts GetCallerIdentity`
before presigning. (The relay legs themselves worked first try: HK PUT → relay
intranet PUT → HEAD on the Beijing object, all `ETag == md5`.)

### State left behind

Live image `m-2ze4m8a0ea3g4p7s5eqy` (v226b), rollback `m-2ze907s3a43t8l3sdh9r`
(v225c); 6 images / 6 snapshots after deleting v226 and its snapshot.
`relay188` **Stopped** (`StopCharging`). `/tmp/pav-prod-*.{b64,json}` and the
report captures deleted. Staging objects `disk225.raw|disk226.raw` still sit in
both buckets (deleting them needs the relay started).

### Still manual

1. **PayPal Return URL** for `https://leonardopedro.github.io/verifiedUniqueAliases/verify.html`
   — without it the sealed path dies at the authorize screen.
2. A **custom hostname**, if wanted: needs a Worker/Pages CNAME (README), then a
   config-only allowlist push — no rebuild.
3. The **browser E2E** for the sealed redirect: PayPal answers 403 to this
   host and there is no account or browser here.

---

## 0.43 — v227: the enclave's own callback is the only return leg (2026-11-09)

### The correction

The v226 landing linked the GitHub Pages copy so PayPal could hand *that page*
the code. That was wrong on grounds of trust, not of mechanics: an origin
outside the measured image can change under a Return URL that PayPal keeps
forever, so "a stable https URL" is an assurance the attestation never makes.
Only the repository bytes are checkable, and `raw.githubusercontent.com` serves
them as a download — it cannot execute, which is the property being relied on.

**Return URL stays `https://login.airma.de/callback`.** The callback is not just
the default, it is the point: PayPal hands the code straight back to the attested
process over TLS, so nothing sits between PayPal and the exchange, and
`https://login.airma.de/tls-cert.pem` lets the visitor save **the certificate
that connection actually used** and compare its fingerprint with the padlock in
their own browser. The report repeats that PEM as
`session_context.tls_certificate_pem`, so the key a sealed `code_enc` must name
is the key of a certificate the user held in their hand.

### What changed

- **Landing** (`LANDING_HTML`): the blue *Open verify.html in this browser*
  button and its step 4 are gone; the second button is now
  **Download this connection's TLS certificate** (`/tls-cert.pem`, served as
  `application/x-pem-file`, `attachment`), with the padlock-fingerprint
  instruction and the statement that PayPal returns to
  `https://login.airma.de/callback`. Steps are three again.
- **Page**: `pageRedirectUri()` no longer tells users to "use the GitHub Pages
  copy"; it explains the file:// limitation and that the enclave's `/callback`
  is the default return leg. The two *UNTRUSTED AUDITOR ORIGIN* messages now
  point at the saved local file only. The seal toggle survives for operators who
  host the page themselves — it is just no longer the recommended path.
- **Config**: `seal_redirect_uris` trimmed to `["https://login.airma.de/callback"]`
  (14 keys, 6,064 B b64, readback sha256 `7a1d1c09…`). No rebuild was needed for
  this — it rides the rotation's own user_data push.
- **README**: the old "register the Pages URL as Return URL" checklist and the
  custom-domain/Worker recipe are replaced by *Redirect URIs: the enclave owns
  the return leg* — the measured `text/plain`/`nosniff` and
  `SSL: no alternative certificate subject name` facts stay, the encouragement
  to host the auditor does not.
- **CI**: three new checks in `test-verify-security.mjs` — the landing never
  links a Pages auditor, it offers `/tls-cert.pem` and names the callback, and
  `pageRedirectUri` may not recommend a Pages copy again. Security suite is
  **503 passed, 0 failed**.

### A real bug in the rotation script

Phase 3 polled a **stopped** relay: `RunCommand` against a `Stopped` instance
never returns an InvokeId, so the leg waited out its 30-minute budget and died
with `relay leg failed: TIMEOUT`. The help text had always said
"`ALI_RELAY_INSTANCE_ID` — stopped cn-beijing relay", and cleanup leaves it
`Stopped` (`StopCharging`) after every rotation, so this would have hit every
future run. `relay_ensure_running()` now starts it, waits for `Running`, and
gives the cloud agent 15 s before the first command.

> Local `cargo test` cannot run on this host (`openssl-sys` needs system
> libssl-dev); the containerised build is the compile gate, and it compiled and
> reproduced.

### Two passes, as before

| | image | disk sha256 | binary | RTMR2 |
|---|---|---|---|---|
| v227b | `m-2ze2yp6ozth4ynfqp7a6` (superseded) | `c813d013…` | `f2c29e9d…` | `faba03c0…` |
| **v227c (live)** | **`m-2zej7uzl9mr49avdfwyj`** | **`9f3238e1…`** | `f2c29e9d…` (identical) | `faba03c0…` (held) |

The landing edit is compiled in, so pass 1 rotated **RTMR2 `3ca54e8d…` →
`faba03c0…`** (MRTD `e0199499…`, RTMR0 `06a32a2f…`, RTMR1 `6fa035…`, RTMR3 held)
and the pins were rotated against the live quote (`EXPECTED_RTMR2`,
`EXPECTED_ENCLAVE_SHA256` → `f2c29e9d…`). Pass 2 shipped the rotated page: the
binary came out byte-identical, so the pin held — the property that makes a
page-only release safe.

Live after the swap: envelope `binary_sha256 = f2c29e9d…` == pin; envelope
`disk_manifest.verify.html = c36d8a7e…` (302,528 B) == repo == Pages;
live RTMR2 `faba03c0…` == `EXPECTED_RTMR2`; deployed ESP == the local disk
(`PARITY OK`); landing carries `/tls-cert.pem` and no Pages auditor.

### State

Live `i-2ze1zdxis0hcsg91qbh5`, image `m-2zej7uzl9mr49avdfwyj`; rollback
`m-2ze4m8a0ea3g4p7s5eqy` (v226b, pins of that era — expect the stale-auditor
warning if you roll back without rotating them). Superseded v227b image and its
snapshot deleted; relay stopped again; `/tmp` config and report captures removed.

### Still needs the operator

1. **PayPal app**: keep the Return URL at `https://login.airma.de/callback` —
   nothing to add, and do **not** add the Pages URL.
2. **Browser E2E**: PayPal answers 403 to this host, so the real login round trip
   still needs a human with an account.

---

## 0.44 — v228: the certificate download is provable before login (2026-11-09)

### What the check found

v227 made `/tls-cert.pem` the visitor's proof of the channel, but nothing tied
that download to the attestation. Writing the binding check exposed two gaps on
the live service, both fixed here:

1. **`/debug/envelope` carried no `tls_certificate_pem` at all.** The pre-login
   report named the TLS *key* (v223) but not the certificate, so an auditor could
   only check the download against a report after completing a PayPal login.
   The envelope now carries the same PEM the callback report does — public
   handshake bytes, no new exposure.
2. **`/tls-cert.pem` serves the full chain** (leaf + 2 intermediates, 3 PEM
   blocks at 6,870 B), not a single certificate. That is the right thing to
   serve (`openssl verify -CAfile` then works), so the check compares the leaf
   and reports the chain length rather than demanding one block.

The download is also confirmed to be the *live handshake leaf*, which is the
claim the landing actually makes ("match it against your padlock"): pass 1 saw
`7923cb77…`, pass 2 `9a5949a9…` — the certificate rotates per boot with ACME,
which is precisely why the report has to name it.

### The check

`scripts/check-live-tls-cert.mjs` fetches the landing, the PEM, the envelope and
the real TLS handshake, then compares DER (leaf) — plus `--report <file>` for an
archived report. It fails if the landing stops linking `/tls-cert.pem`, stops
naming `login.airma.de/callback`, links a third-party auditor again, serves a
non-PEM body or the wrong content-type, or if any of the three certificates
disagree.

Wired in twice:
- **Every rotation**, as the last gate of phase 6 (`rotate-alibaba.sh`) — a TLS
  proxy in front of the enclave, or a report built before the certificate was
  loaded, cannot ship silently.
- **Daily in CI** (`.github/workflows/live-cert-check.yml`, `17 5 * * *`, plus
  manual dispatch with a URL input), because this is a property of the deployed
  service that no build-time test can observe.

### Pages is no longer a trusted auditor, anywhere

`trustedAuditorContext()` is now `file://` only. The Pages mirror was still
whitelisted as a key-generating origin — the leftover of the v226 design — and
it is an origin its owner can republish, so it grants nothing. The banner and
`untrustedOriginError()` say "served over the network", not "served by the
enclave", since both cases are the same threat. Legal-document links and the
Pages *reading* mirror are untouched; `zk.html` keeps its own copy of the gate
for its own origin and was deliberately not changed.

**Harness bug fixed while doing this:** the offline suite evals `verify.html`,
then `zk.html`, which re-declares `trustedAuditorContext`. Every isolation test
was therefore exercising **zk.html's** rule, not the auditor's — the Pages entry
could have stayed here indefinitely with the suite green. The suite now captures
the auditor's function before zk.html is evaluated.

### Two passes

| | image | disk sha256 | binary | RTMR2 |
|---|---|---|---|---|
| v228 | `m-2ze2z2xb3t87rovbbm8t` (superseded) | `335af4bf…` | `406cdcb3…` | `a2b7baf1…` |
| **v228b (live)** | **`m-2ze907s3a43tcv075rd2`** | **`4aad2dd9…`** | `406cdcb3…` (identical) | `a2b7baf1…` (held) |

RTMR2 rotated `faba03c0… → a2b7baf1…` (MRTD `e0199499…`, RTMR0 `06a32a2f…`,
RTMR1 `6fa035…`, RTMR3 held) because the envelope field lives in the binary;
pins were rotated against the live quote, and pass 2 shipped the rotated page
with the binary byte-identical.

Live after the swap: envelope `binary_sha256 = 406cdcb3…` == pin; live RTMR2
`a2b7baf1…` == `EXPECTED_RTMR2`; envelope `disk_manifest.verify.html =
71e71f9f…` (303,074 B) == repo == Pages; `certificate download == live handshake
== report` at phase 6 on both passes; `PARITY OK`; security **496/0**, proxy
**44/0**, seal `card` and `sealed-return` green.

### The login round trip could not be run here

No Chromium or Playwright in this environment, and the live enclave is
production-configured — `scripts/e2e-sandbox.mjs` refuses to drive it by design
(a sandbox identity cannot complete a production login). PayPal also answers 403
to this host. What *was* verified about the leg without a PayPal session:
`GET /callback` with no session returns **403 "Invalid or expired session"** —
the route exists, is sealed to a live session and refuses bare input. The real
round trip still needs a human with a PayPal account in a browser.

### State

Live `i-2ze1zdxis0hcsg91qbh5`, image `m-2ze907s3a43tcv075rd2`; rollback
`m-2zej7uzl9mr49avdfwyj` (v227c, RTMR2 `faba03c0…` / binary `f2c29e9d…` —
rolling back also means restoring that era's pins). Superseded v228 image and
its snapshot deleted; relay stopped; `/tmp` config and report captures removed.

---

## 0.45 — v229: the ZK handoff is files, and /callback is probed live (2026-11-09)

### The last Pages dependency in the trust path

`zk.html` still trusted `leonardopedro.github.io` as a key-generating origin and
accepted the audited identity over a `postMessage` **pinned to that origin** — so
after v227/v228 removed Pages from the auditor, the prover still ran on an origin
its owner can republish. Both halves are gone:

- **zk.html**: the gate is `file://` only (`TRUSTED_AUDITOR_HOSTS` deleted), the
  message listener and its origin allowlist (`ZK_HANDOFF_ORIGINS`) are removed,
  and the handoff arrives as a **bundle file** loaded through
  `#zkHandoffBundleFile` → `zkHandoffFromBundleFile()`. It runs the same
  fail-closed path as the paste box (`zkIdentityFromReportText` →
  `zkStashIdentity`: band, hash re-derivation, SIGNED raw-hash cross-check), so
  the bundle is re-verified regardless of who produced it. A file that is not a
  handoff is refused by name.
- **verify.html**: `openZkProver()` and the 250 ms postMessage retry loop are
  replaced by two explicit artifacts — ① **Save zk.html** from
  `raw.githubusercontent.com`, ② **Download the audited identity bundle**
  (`zk-handoff.json`, carrying the canonical report text + the audited hash,
  i.e. exactly the old payload). `ZK_PROVER_URL` now points at raw, and no
  origin is posted to at all.

The offline suite drives the new path rather than just grepping for it: it
captures the bundle via a stubbed `Blob`, feeds it to zk.html's own loader with
a stubbed `FileReader`, and asserts the re-derived identity and hash match — plus
a negative case (a non-bundle file is refused). Security suite: **501 passed,
0 failed** (five new checks).

**Known limitation, unchanged by this release:** `zk.html` and `zk-rsa.html` are
not on the ESP, so they have no `disk_manifest` row — `build-alibaba-image.sh`
ships only `verify.html` (v167/v205 rationale: the enclave no longer serves the
page). The prover's integrity anchor is therefore the repository digest
published in README (`zk.html` = `06d0fe31…`, 111,997 B), which is what a user
compares their saved copy against. Putting it in the manifest would mean
measuring a file the enclave never serves.

### A live check for the return leg

`scripts/check-live-callback.mjs` probes the only PayPal Return URL there is:
`/callback` bare and with `?code=bogus&state=bogus` must both answer **403** with
the *same* sealed plain-text line naming where to restart, and
`?error=access_denied` must answer **400** saying no code was exchanged. It also
rejects an HTML body, a `text/html` content-type, a body over 300 chars, and any
leak of `panic`/stack/`axum`/`hyper` markers or a code/credential echo.

Runs in the rotation's phase 6 (after the certificate check) and daily in the
same workflow. First live run: 403 / 403 / 400, identical refusals — OK.

### Release

Single pass this time: the binary did not change (`406cdcb3…`, RTMR2 `a2b7baf1…`
held, MRTD/RTMR0/1/3 unchanged), so **no pin rotation** — only the disk moved.

| | image | disk sha256 | binary | RTMR2 |
|---|---|---|---|---|
| **v229 (live)** | **`m-2zefbu7nyrwv18mu8o31`** | **`d834fb3a…`** | `406cdcb3…` (unchanged) | `a2b7baf1…` (held) |

Live after the swap: envelope `disk_manifest.verify.html = c36666d5…`
(302,273 B) == repo == Pages; certificate download == handshake == report
(`a727745d…`); callback refusals sealed; `PARITY OK`; security **501/0**, proxy
**44/0**, seal `card` and `sealed-return` green.

### Still needs the operator

The real PayPal login round trip cannot run from this environment: no Chromium or
Playwright is installed, the enclave is production-configured (so
`e2e-sandbox.mjs` refuses it by design — a sandbox identity cannot complete a
production login), and PayPal answers 403 to this host. The callback leg is
verified structurally (bare/forged/denied input all refused in sealed plain
text), but nobody has watched a real `code` come back and seal correctly yet.

### State

Live `i-2ze1zdxis0hcsg91qbh5`, image `m-2zefbu7nyrwv18mu8o31`; rollback
`m-2ze907s3a43tcv075rd2` (v228b, same binary and RTMR2 — pins still apply).
Superseded v228b image and its snapshot deleted; relay
stopped; `/tmp` config and report captures removed.

---

## 0.46 — v230: the notary was missing from the disk, and is now tested live (2026-11-10)

### What the test found before it could test anything

Asked to exercise the newest webservice (the TLSNotary proxy), the first probe
was the deployed one:

```
GET https://login.airma.de/proxy/health
{"service":"tls-proxy","enabled":true,"running":false,
 "last":"spawn failed: No such file or directory (os error 2)","restarts":0}
GET /proxy/attestations → 503
```

`enabled: true` was only the *config's* wish. `build-alibaba-docker.sh` invoked
`podman build -f Dockerfile.alibaba` without `--build-arg TLS_PROXY=1`, so
Dockerfile.alibaba took its documented `TLS_PROXY=0` default, left `/tls-proxy-bin`
empty and never installed the binary — while the production `user_data` still
said `services.tls_proxy.enabled: true`. The v216 dual-service disk (built by
`build-tls-proxy-image.sh`, which does pass the arg) was replaced at **v227**,
and v227/v228/v229 consequently shipped a PayPal-only disk onto a config that
asked for two services. PID 1 retried a file that was not there, every boot,
for three releases — and nothing in the rotation noticed, because every gate
looked at the PayPal service.

### The fix (two halves, deliberately)

1. **The build** (`build-alibaba-docker.sh`): `--build-arg TLS_PROXY="${TLS_PROXY:-1}"`.
   Default on, because the deployed config enables the service; `TLS_PROXY=0`
   still works for a deliberate PayPal-only deployment and now prints a warning
   saying so.
2. **The gate** (`scripts/check-live-notary.mjs`, new): asserts the thing that
   was false — `/proxy/health` must report `enabled: true` **and** `running: true`
   (and names the usual cause when it does not), the session port from that
   response must accept a TCP connection, and `/proxy/attestations` must answer
   200 with the documented `{count, running, sessions[]}` shape. It runs in the
   rotation's verify phase (after the certificate and callback checks) and as a
   third step in the daily `live-service-checks` workflow.

The first draft of the list check asserted a bare array; the live route answers
an object. The failure was caught by the gate itself during pass 1 and fixed
before the release — the shape now asserted is the one in the source
(`Attestation` flattened under `count`/`running`/`redaction`/`sessions`).

### Release

RTMR2 moved (the initramfs now carries the proxy binary); MRTD/RTMR0/1/3 and the
PayPal binary did not. Two passes, as always when a pin moves.

| pass | image | disk sha256 | RTMR2 |
|---|---|---|---|
| 1 (pin rotation) | `m-2ze3p7ienfczexh43acn` (`paypal-tdx-esp-v230-202611100246`) → built, swapped, pin read live | — | `3d58e6da…` |
| **2 (live)** | **`m-2ze1wtngcskhet1y3lnn`** (`paypal-tdx-esp-v230b-202611100258`) | **`b3295c41…`** | **`3d58e6da…`** |

Pin rotation: `EXPECTED_RTMR2` `a2b7baf1…` → `3d58e6da…`; `EXPECTED_MRTD`,
`EXPECTED_RTMR0/1/3` and `EXPECTED_ENCLAVE_SHA256` (`406cdcb3…`) unchanged.
Page `verify.html`/`index.html` 302,610 B, `7a6d9bd3…`; README rows updated.

Rotation verify, all green: `PARITY OK`; certificate download == handshake ==
report; `/callback` refuses junk in sealed plain text; **notary spawned,
listening and serving its list**; security **508/0**, proxy **44/0**, seal
`card` + `sealed-return`.

### The live prover sessions (the actual test)

`cargo test --manifest-path tls-proxy/Cargo.toml --test live -- --ignored --nocapture`
with `LIVE_NOTARY=101.200.178.251:8443`, built locally against nix OpenSSL
(`OPENSSL_DIR` → `nix build nixpkgs#openssl.dev`, because this box has no system
headers):

| target | attempt | time | status | transcript |
|---|---|---|---|---|
| `www.sandbox.paypal.com/signin` | **1/3** | 35.0 s | `200 OK` | 103 B → 37,996 B |
| `sandbox.paypal.com/` | 2/3 | 57.0 s | `301 Moved Permanently` (expected — the sandbox apex redirects; the harness does not follow) | 89 B → 5,532 B |
| `sandbox.paypal.com/robots.txt` | 1/3 | 22.1 s | `200 OK` | 99 B → 3,479 B |
| `www.sandbox.paypal.com/robots.txt` | 1/3 | 11.6 s | `200 OK` | 107 B → 3,428 B |

The capability URL the harness prints was then fetched from this machine (not
the VM): `GET /proxy/attestations/e183297a…?sent_sha256=…&received_sha256=…`
→ **200, 52,081 B**. The record verifies offline the way the service documents:
rebuilt the signed bytes in declaration order, `crypto.verify("sha256", …)`
against `enclave_pubkey_pem` → **valid (RSA-PKCS1-v1_5-SHA256)**, `sent_b64` and
`received_b64` re-hash to the advertised digests, and the received transcript
begins `HTTP/1.1 200 OK`. One retry on the bare-apex target is the documented
edge-closing behaviour, not a regression.

### State

Live `i-2ze1zdxis0hcsg91qbh5`, image `m-2ze1wtngcskhet1y3lnn`, EIP
`101.200.178.251`; notary `:8443` up, API `127.0.0.1:8081`. Rollback: the pass-1
image (`paypal-tdx-esp-v230-…`, same RTMR2, old page). v229 image and snapshot
deleted; relay stopped; `/tmp` config and record captures removed.

---

## 0.47 — v231: the notary's key is now named by the attested report (2026-11-10)

### The caveat v230 shipped with

A TLSNotary record is signed by the notary's per-boot RSA key, and the record
carries that key. `verify-proxy.html` checked the signature and said, honestly,
that it could not check whose key it was. That left the chain short: the record
proved "signed by K", and nothing tied K to the enclave. The record could have
been produced by anyone who held a key.

### The fix: one hop, no new trust anchor

The enclave's attestation report already is a hardware-anchored statement: its
quote's `report_data` commits to the enclave identity key, `/init` and the disk
manifest, and its body is signed by that identity key. So the notary key is now
named *inside* that body:

1. **Proxy** — new `GET :8081/pubkey` returns
   `{pubkey_pem, pubkey_sha256, algorithm, signature_alg}`, where
   `pubkey_sha256` is SHA-256 over the **SubjectPublicKeyInfo DER** (not the PEM
   text), so any verifier that re-encodes the key lands on the same bytes.
2. **Enclave** — `attested_proxy_key()` fetches that route while minting a
   report and publishes
   `session_context.proxy_signing_key = {available, algorithm, signature_alg,
   pubkey_pem, pubkey_sha256, reported_sha256}` in **both** reports: the
   data-free envelope and the post-login callback report. The fingerprint is
   recomputed from the PEM with the existing `pubkey_fingerprint()`, and the
   child's own claim is kept beside it as `reported_sha256`, so a disagreement is
   visible rather than silently repaired. When the second service is absent the
   field is `{available:false, reason:"…"}` — never an invented key.
3. **Auditor** — `verify-proxy.html` gained a second input (the report) and turns
   the old warning into a check: the record's key PEM and fingerprint must equal
   the report's, otherwise the audit fails closed. The page still states what it
   cannot do — verify the report's own quote — and points at `verify.html`.
4. **Gate** — `scripts/check-live-notary.mjs` now fetches `/debug/envelope` and
   asserts the report names the notary key and that the fingerprint is
   SHA-256(SPKI DER) of the PEM it published, so a regression fails the rotation.

Tests: `tls-proxy/tests/session.rs` asserts `/pubkey` names the exact record key
and the advertised fingerprint is the DER hash (8 passed); `test-verify-proxy`
covers matching / wrong-key / wrong-fingerprint / `available:false` / garbage
reports (53 passed); `cargo test` 46 passed; security 501/0; seal card +
sealed-return; workflows.

### Release (two passes)

Both binaries changed, so RTMR2 moved as well as the PayPal binary.

| pass | image | disk sha256 | note |
|---|---|---|---|
| 1 | `m-2ze5go7984ubmq6epai0` | `bd07dd67…` | pins read live; verify green |
| **2 (live)** | **`m-2zedx7ou4muj4ulruuxz`** (`paypal-tdx-esp-v231b-202611100418`) | **`c15b3197…`** | page + pins in the ESP |

Pins: `EXPECTED_RTMR2` `3d58e6da… → c436335f…`, `EXPECTED_ENCLAVE_SHA256`
`406cdcb3… → 33308970…`; MRTD/RTMR0/1/3 held. `verify.html`/`index.html`
302938 bytes, `4d9cd6f21d93cfdbf20e4fd18b4af219cff4ce37fb506a278ac7bf2fcb9a17c4`. Rollback: the pass-1 image (same binary and RTMR2, earlier
page).

**Pass 2's scripted verify aborted on a transient ACME failure**, not on the
image: the guest booted with the notary listening on :8443 while :443 stayed
closed (`000` from 04:20), because issuance at boot is a retry loop with no
self-signed fallback ("Running + dark"). It healed by itself at 04:47:51 with no
intervention — the retry backoff is 15 s → 300 s. Every verify step was then
re-run by hand against the live instance and passed:

- running binary `33308970…` == built; `PARITY OK` (ESP == `disk-alibaba.raw`, `c15b3197…`)
- certificate download == live handshake == report (`5d492667…`)
- `/callback` refuses missing/forged input in sealed plain text
- notary enabled, spawned, listening, list readable, **key named by the report** (`3b5c5557…`)

### The live notary test (again, on the new deployment)

`LIVE_NOTARY=101.200.178.251:8443` against `www.sandbox.paypal.com/signin`:
attempt 1/3, 16.2 s, `200 OK`, 103 B → 37,998 B, presentation complete.
Record `15f8386a…` fetched from this non-VM machine (HTTP 200, 52,081 B) and
checked end to end:

| check | result |
|---|---|
| record signature (RSA-PKCS1-v1_5-SHA256) | **VALID** |
| record key fingerprint | `3b5c55575569c231e2f2e4ceafd937bfa3ed61db6d1a0144cc1bfbeffa8cb999` |
| fingerprint named by `/debug/envelope` | **identical** |
| notary's own `reported_sha256` | **identical** |
| `proxy_signing_key.pubkey_pem` == record's `enclave_pubkey_pem` | **true** |
| report binary | `33308970…` (matches the pin) |

So a record signed by the notary now resolves to the same measured VM the PayPal
flow attests, and `verify.html` remains the one place the quote and pins are
checked. Notary restart caveat: a new key is minted, and the envelope is cached
15 minutes, so a stale report names the previous key and the page fails closed —
fetch a fresh report.

### State

Live `i-2ze1zdxis0hcsg91qbh5`, image `m-2zedx7ou4muj4ulruuxz`, EIP
`101.200.178.251`; PayPal service on :443, notary on :8443 (api 127.0.0.1:8081).

---

## 0.48 — v232: the two caveats from v231 are closed (2026-11-10)

### 1. A restarted notary no longer leaves a report naming a dead key

The 15-minute `/debug/envelope` cache existed to keep TD-quote generation off the
request path (v180). It was keyed on time only, so after a notary restart the
cached body kept naming the previous boot's key, and `verify-proxy.html` failed
its (fail-closed) binding check until the window expired.

The cache now remembers *what* it published: `CachedEnvelope { at,
proxy_key_sha256, body }`. Every request probes the child's loopback
`GET /pubkey` — 4 s timeout, no quote, no measurement work — and
`envelope_cache_fresh()` re-mints the moment the live fingerprint differs:

| cache state | live notary key | served |
|---|---|---|
| < 15 min, same fingerprint | same | cached body (no quote cost) |
| < 15 min, different fingerprint | new | **re-minted** |
| < 15 min, cached "no key" (`""`) | any key | **re-minted** |
| < 15 min | unreachable | cached body |
| ≥ 15 min | anything | re-minted |

An unreachable notary deliberately does NOT invalidate: a process that cannot
answer has not minted a new key, and re-minting per request would turn a crashed
child into a quote generator — the exact DoS surface v180 removed. The probe
costs one loopback GET, already bounded per-IP by `record_egress` (8 KiB/request,
25 MB/hour).

`verify-proxy.html`'s MISMATCH row now says what to do: re-fetch the report (a
key change re-mints it) and check again; a second mismatch means the record
really is not covered. Unit tests: `security_tests::envelope_cache_follows_the_notary_key`
(covers all five rows plus window expiry) and the live proof below — two
requests 2 s apart return byte-identical bodies, so the cache still suppresses
quotes, and both name the running key.

### 2. Boot no longer goes dark for half an hour

v231 pass 2 sat "Running + dark" for 27 minutes: :8443 was up, :443 closed,
because issuance at boot is a retry loop with no self-signed fallback (a
self-signed cert would be a lie the padlock cannot expose — that stays). Two
real defects made the window that long:

* **Every retry registered a new ACME account.** `obtain_certificate_in_ram`
  built the directory + account + order in one function, so each backoff round
  created another account and another order at the CA — the behaviour that
  *causes* per-account and per-IP rate limits. It is now split:
  `open_account()` runs once per boot and `obtain_certificate_in_ram(&key,
  &account)` re-orders on that same `Arc<Account>`.
* **The backoff was blind.** A flat 15 s doubling to 300 s, whatever failed. Now
  `acme_backoff(attempt, err, jitter)` reads the failure: a CA refusal
  (`rateLimited`, "too many", duplicate certificate, pending order, "retry
  after") waits 5 min → 30 min, while everything transient (DNS not propagated,
  network blip, CA 5xx) retries 10 s → 120 s with up to 25 % jitter. A refusal
  is waited out instead of hammered; a hiccup is not punished with a 5-minute
  nap. `security_tests::acme_backoff_separates_refusals_from_hiccups` pins both
  branches. Retries publish `acme attempt N: …` to the self-report sink (first
  3, then every 10th) and advance the stage to `acme-retry-N`, so a dark box
  explains itself in the bucket instead of needing `GetInstanceConsoleOutput`.

`rotate-alibaba.sh` also stops treating a booting guest as a failed image: the
`200` poll now runs for `VERIFY_WAIT_SECS` (default 1500 s, was a hard 10 min)
and prints progress every minute, with a pointer to the self-report sink on
timeout. That window is a legal boot state — v231 pass 2 needed 27 minutes and
was healthy.

### Release (two passes, both green on the first attempt)

| pass | image | disk sha256 | note |
|---|---|---|---|
| 1 | `m-2zeg6aswcjkklkjjiku6` | `ea1b79de…` | pins read live; verify green, HTTPS in 45 s |
| **2 (live)** | **`m-2zeiafiaongj0n5dolkf`** (`paypal-tdx-esp-v232b-202611100726`) | **`4f123cae…`** | page + pins in the ESP |

Pins: `EXPECTED_RTMR2` `c436335f… → 1e52cff6…`, `EXPECTED_ENCLAVE_SHA256`
`33308970… → defbdd21…`; MRTD `e0199499…`, RTMR0 `06a32a2f…`, RTMR1 `6fa03523…`,
RTMR3 zero — all held. `verify.html`/`index.html` byte-identical, 302,938 B,
`d5f2cd35…`. Both boots reached `200` in 45 s; no dark window at all this time.

### Live checks on v232b

- `PARITY OK` (deployed ESP == `disk-alibaba.raw`, `4f123cae…`); cert download ==
  handshake == report; `/callback` sealed refusals; notary gate green with the
  report naming key `d28f79f6…`.
- Prover on `www.sandbox.paypal.com/signin`: 200 OK, 103 → 38,004 B, record
  `9850c0d2…` fetched from this non-interactive machine (200, 52,089 B),
  signature **VALID**, binding **VERIFIED** against `d28f79f6…`, report binary
  `defbdd21…`.
- `cargo test` 48/48 (2 new), proxy session 8/8, `test-verify-proxy` 53/0.

### Remaining, known, not fixed here

- **The stale-cache path is proven by unit test, not live**: restarting the
  notary needs the child to exit, and nothing outside the enclave can make it
  (that is deliberate). The decision logic is pure and covered; the wiring is one
  probe + one re-mint.
- **GitHub Pages is behind** (`7a6d9bd3…`, the v230-era page) and has not picked
  up any of today's pushes, so `test-verify-security.mjs` Test 46 fails on drift
  while every other check passes (500/1). The repo copy is the trusted one — the
  pages copy is explicitly outside the trust model — but the gate stays red until
  the Pages build for `main` lands.

---

## 0.49 — v233: GitHub Pages is gone, and the notary can be cycled (2026-11-10)

### Why Pages had to go (user directive, 2026-11-10)

The project published `verify.html`, `zk.html`, `zk-rsa.html`, `privacy.html`,
`terms.html` and the whole `zk/` artifact set on
`leonardopedro.github.io/verifiedUniqueAliases/`, **and the security suite gated
on that copy**. The directive: *Pages must not be used by this project, because
it leads to a false sense of safety.* The trace backs it up:

- The Pages build of `main` had been **failing** every run since the crash
  before v231 (`pages build and deployment` → step `Upload artifact` → failure),
  while the github.io copies kept serving the **v230-era page** (`7a6d9bd3…`).
  Nothing said so: the site simply looked like the auditor, with old pins.
- So the "served-auditor drift gate" (Test 46) was checking a host that (a) is
  not deployed by any of this project's pipelines, (b) is not measured by any
  attestation, and (c) had already been stale for hours twice (v192, v231) while
  looking authoritative. A second, unmeasured copy of the page that *claims* to
  be pinned is worse than no second copy.

**What changed:**

| Was | Now |
|---|---|
| `verify.html`/`zk.html`/`zk-rsa.html`/legal docs on Pages | repo only, fetched over `raw.githubusercontent.com` |
| `zk.html`: `ZK_BASE = '…github.io/…/zk/'` | `ZK_BASE = 'https://raw.githubusercontent.com/…/main/zk/'` (raw sends `ACAO: *`; wasm 2.9 MB, zkey parts 60 MB + 45 MB, both under raw's 100 MB cap; `?v=` cache-busters still 200) |
| `privacy.html` / `terms.html` (Pages-only HTML) | `PRIVACY.md` / `TERMS.md` in the repo, linked as GitHub blob (rendered), so the auditor's "Legal:" line points at a document nobody has to trust |
| `origin/main` = "Pages source branch" | mirror of `alibabacloud` for readers; **no Pages origin in the project** |
| Test 46 = "Pages copy == repo verify.html" (network, flaky, red whenever the Pages build stalled) | Test 46 = **"no GitHub Pages dependency"**: no shipped page or `src/main.rs` may contain a `github.io` URL, the auditor must take `zk.html` from raw, `zk.html` must take its artifacts from raw, the legal docs must be `PRIVACY.md`/`TERMS.md`, and `.nojekyll` must be gone |
| `PAGES_PARITY` / `PAGES_VERIFY_URL` / `PAGES_ZK_ARTIFACTS` env in CI | removed (`build-attest.yml` has no Pages env) |
| Auditor may run key flows from "`file://` or the pinned Pages copy" | `file://` only — which the page already enforced (`location.protocol === 'file:'`); only the prose was wrong |

`zk.html`, `zk-rsa.html` and the auditor are still *standalone files the user
saves and opens*, so nothing about the audit changes: the page already refused
to generate keys anywhere but `file://`.

### The notary can now be cycled without rebooting (v233)

`POST /proxy/restart`, gated on `services.tls_proxy.restart_token` from the
instance config (header `X-Proxy-Restart`). Without a token the route does not
exist and answers `404`; a wrong token gets the same `404` — a caller who cannot
use it is not told it is there. The supervisor `select!`s between `child.wait()`
and a `Notify`, kills and re-execs on request, resets its backoff to 1 s (a
requested cycle is not a crash), and keeps counting in `/proxy/health`
(`restarts`). The token is compared as a SHA-256 of both sides so a guess costs
the same work whatever its length. Unit test:
`security_tests::proxy_restart_requires_the_configured_token`.

This is what makes the v232 cache fix **provable live**, which was its one open
caveat: `scripts/check-live-proxy-restart.mjs` shows, in five steps,

1. two fetches inside the window are byte-identical (the cache still suppresses
   TD quotes),
2. `POST /proxy/restart` → `202`, `/proxy/health` `restarts 0 → 1`, notary back
   up,
3. the next fetch — still inside that window — names the NEW key, with a newer
   `timestamp_ms` and a different enclave signature (re-minted, not spliced),
4. the named key, its PEM and the report's own `reported_sha256` agree,
5. the re-minted body is cached again (the re-mint did not disable the cache).

### Release

| pass | image | disk sha256 | note |
|---|---|---|---|
| 3 | `m-2ze7sffsyqktt4k7dvmt` | `b48e86b7…` | Pages removal + restart route, binary `6c9b3f5f…` |
| **4 (live)** | **`m-2ze2yp6ozth582t22n3n`** (`paypal-tdx-esp-v233b-202611100851`) | **`ee291132…`** | page + pins in the ESP |

Pins: `EXPECTED_RTMR2` `1e52cff6… → 45de4b4a…`, `EXPECTED_ENCLAVE_SHA256`
`defbdd21… → 6c9b3f5f…`; MRTD `e0199499…`, RTMR0 `06a32a2f…`, RTMR1 `6fa03523…`,
RTMR3 zero — held. `verify.html`/`index.html` byte-identical, 303,020 B,
`90480d0f…`. Both passes: `HTTPS 200 (after 45s)`, `PARITY OK`, cert ==
handshake == report, sealed `/callback` refusals, notary named in the report.

### Live checks on v233b

- `check-live-proxy-restart.mjs`: **OK** — `697ab9dc… → 64a96900…`, cache
  served identical bytes before and after, re-mint inside a 132-second-old
  window.
- Landing page over HTTPS links `PRIVACY.md`/`TERMS.md` (github.com blob) and
  `verify.html` (raw) — zero `github.io` links.
- `raw.githubusercontent.com` serves `zk/identity_escrow.wasm` (2,863,855 B),
  `…zkey.part0` (60,000,000 B) and `…vkey.json` with `access-control-allow-origin: *`,
  and `?v=` cache-busters still return 200.
- `cargo test` 49/49 (new: restart-token gate), `test-verify-security` 505/0
  (Test 46 rewritten, and the suite is green for the first time in this cycle
  because nothing depends on a Pages build any more), `test-verify-proxy` 53/0,
  `check-workflows` 3/3, `check-relay-targets` OK.

### Notes for the next operator

- The restart token is in the instance `user_data` (write-only from here — read
  it with `aliyun ecs DescribeUserData`). Rotating it is a config-only change,
  but it only takes effect on the next boot (config is read at boot).
- `pages build and deployment` was failing on `main` at that point; **§0.50 finds
  the cause (committed `/nix/store` symlinks) and fixes it — v234 brings Pages
  back for `privacy.html`/`terms.html` only.**

---

## 0.50 — v234: Pages is back for the legal pages, and the freeze is diagnosed (2026-11-10)

### The directive changed

v233 removed GitHub Pages from the project entirely. The user then asked for it
back for one purpose: hosting the **extra information** — the privacy policy and
the user agreement. v234 draws the boundary instead of dropping the origin:

- **Pages publishes** `privacy.html` and `terms.html` (repository root, next to
  the landing/auditor copies) — that is what the landing page and `verify.html`
  link to.
- **Pages never publishes audit bytes.** `verify.html`, `zk.html`, the witness
  wasm and the Groth16 proving key still come from `raw.githubusercontent.com`
  and are pinned by SHA-256 inside those pages. Test 46 now asserts BOTH halves:
  every `github.io` link in a shipped page must be `/privacy.html` or
  `/terms.html`, and the prover/artifact base must stay on raw.
- `PRIVACY.md`/`TERMS.md` were deleted once, and that broke the deployed v233b
  landing, which still links `github.com/…/blob/main/PRIVACY.md` — the links
  404'd the moment v234 was pushed (checked live). They were restored as
  compatibility copies and **removed again in §0.51**, after pass 5 shipped a
  landing that links the hosted pages.

### Why the Pages build had been failing (root cause, not a guess)

`git ls-files -s` showed two **committed symlinks**:

```
120000 … result      -> /nix/store/q1fgk31h…-openssl-3.6.5
120000 … result-dev  -> /nix/store/f0lcjigad…-openssl-3.6.5-dev
```

Jekyll's safe build refuses symlinks that leave the repository, so the built-in
`pages build and deployment` workflow failed at **step 4, "Build with Jekyll"**
(step 5 "Upload artifact" is skipped, which is why the earlier note blamed the
wrong step). The last successful deployment stayed live for months while every
push reported a red Pages run.

Evidence (public API, no auth needed for run/job metadata):

```
GET /repos/leonardopedro/verifiedUniqueAliases/actions/runs?branch=main
  42779700771  pages build and deployment  failure
GET …/runs/42779700771/jobs
  build: 3 Checkout success · 4 Build with Jekyll FAILURE · 5 Upload artifact skipped
  deploy: skipped
```

Fix: `git rm --cached result result-dev`, `/result` + `/result-dev` in
`.gitignore`, and a new `_config.yml` whose `exclude:` keeps `zk/`,
`output-alibaba/` and `build-scripts/` out of the published site (the proving key
parts plus the released disk image are ~160 MB of binary that a web page must
never serve, and the build runs on every push).

### ZK prover re-verified against raw (user request)

End-to-end, with the artifacts fetched from `raw.githubusercontent.com` exactly
as `zk.html` fetches them (BASE + name + `?v=<pin>`):

| Step | Result |
|---|---|
| `identity_escrow.wasm` | 200, 2,863,855 B, `ACAO: *`, sha256 `b8ce562f…` == page pin == committed file |
| `…zkey.part0` / `part1` | 200, 60,000,000 B / 45,429,603 B, `ACAO: *` |
| assembled zkey | sha256 `e320086d…` == page pin == committed part0+part1 |
| witness + `groth16.fullProve` | proof in 2.9 s, 271 public signals, `verified=1`, hash bits == report hash |
| `groth16.verify` | true with the vkey **embedded in `zk.html`** and with `zk/identity_escrow_vkey.json` (byte-identical) |
| escrow decrypt | ciphertext decrypts to the exact identity JSON |

### Rotation now proves the envelope cache too

`rotate-alibaba.sh` phase 6 runs `scripts/check-live-proxy-restart.mjs`, taking
`services.tls_proxy.restart_token` from the config it just pushed. A config
without a token fails the rotation with an explicit message (the restart path
must be exercisable from outside), and a cache that stops following the notary
key fails the release instead of an auditor's binding check later.

Checks this pass: `node --check` on the changed scripts, `bash -n` on the
rotation, `test-verify-security` re-run after the link/pin change.

---

## 0.51 — v234 pass 5: the landing links Pages, so the Markdown copies go (2026-11-10)

### Release (two cycles — the pin rotation was caught, not assumed)

| pass | image | disk sha256 | note |
|---|---|---|---|
| 5A | `m-2zeggtx23lhbjgtv2pj6` (`paypal-tdx-esp-202611101011`) | `f59c65bd…` | landing links Pages; ZK pin gate in preflight; **pins stale** |
| **5B (live)** | **`m-2zehwizs08eo6wszxhsi`** | **`216df463…`** | same binary `cfafb15d…`, ESP carries the rotated pins |

Cycle A deployed the new binary (`cfafb15d…`, `/debug/envelope` ==
`sha256sum paypal-auth-vm`) with `PARITY OK`, `HTTPS 200`, cert == handshake ==
report, sealed `/callback` refusals (403/400, identical bodies for missing vs
forged input), notary serving, and the **new `check-live-proxy-restart.mjs`
step running inside the rotation** — but its TD quote carried **RTMR2
`5dfcc495…`** while `verify.html` still pinned `45de4b4a…`. That is a *hard*
audit failure: a new binary means a new initrd, RTMR2 rotates, and every visitor
would have died on the silicon row while the service looked perfectly healthy.

So the sanctioned two-cycle procedure ran for real:

1. `calculate-golden-rtmr.mjs --report <cycle-A envelope> --update` →
   `EXPECTED_RTMR2 45de4b4a… → 5dfcc495…` (MRTD `e0199499…`, RTMR0 `06a32a2f…`,
   RTMR1 `6fa03523…`, RTMR3 zero — held); `EXPECTED_ENCLAVE_SHA256`
   `6c9b3f5f… → cfafb15d…`; `index.html` mirrored (byte-identical),
   `verify.html` **303,002 B `de4fbc53…`**, README digest rotated, committed
   `0dc6c53`.
2. Cycle B rebuilt (binary byte-identical) and swapped to `m-2zehwizs08eo6wszxhsi`
   — RTMR2 held at `5dfcc495…`, which is the whole point of the second cycle.

The verify phase on 5B: `running binary matches the build`, `auditor pins match
the live quote (RTMR2 5dfcc495…, binary cfafb15d…)`, `PARITY OK`, TLS leaf
`50bea236…` == `/tls-cert.pem` == handshake == report, sealed callback refusals,
notary serving, restart re-mint. Exit 0.

### The gate that would have shipped the stale pins

Nothing compared the live TD quote with the pins in the page being shipped, so
`rotate-alibaba.sh` phase 6 now fetches `/debug/envelope`, recomputes RTMR2 with
`calculate-golden-rtmr.mjs`, and **dies** when it disagrees with
`EXPECTED_RTMR2` (or when `EXPECTED_ENCLAVE_SHA256` != the binary just built),
with the fix spelled out in the message. Writing it caught two of its own bugs
before they could mislead a later operator: a 192-hex pattern for a 48-byte
(96-hex) TDX RTMR read the pin as empty and failed a *correct* deployment
(`125a083`), so an empty pin now fails with its own message.

### A release gate for the ZK pins (`scripts/check-zk-pins.mjs`)

`zk.html` refuses to prove unless the bytes it downloads hash to the constants
baked into the page, but nothing compared those constants with the *committed*
artifacts — a rotated wasm/zkey or a rotated pin that forgot the other half
would build, pass every other check, and fail only in a user's browser. The new
script hashes `zk/identity_escrow.wasm` and the concatenation of
`ZK_ZKEY_PARTS` in fetch order (the pin covers the assembled key), asserts the
parts are under GitHub's 100 MB limit and **tracked by git** (an ignored part
never reaches raw, however right the digest is), and that `ZK_BASE` is raw.
It runs in `rotate-alibaba.sh` phase 1 and fails as a negative test when either
pin is off by one byte. Rotation preflight refuses to start on a mismatch.

### `PRIVACY.md` / `TERMS.md` removed

The deployed landing links
`https://leonardopedro.github.io/verifiedUniqueAliases/{privacy,terms}.html`
directly — live-checked against the running instance: those two `href`s are the
only legal links on the page, so the Markdown copies have no consumer left.
Removed: the README digest rows and `sha256sum` lines go with them. The legal
text now exists once, as the hosted HTML pages.

### Pages, after the `_config.yml` fix

Run `42784643688` (sha `8f443f6`) and `42785339581` (sha `bcd5d18`): **all
green** — `Build with Jekyll` success, `Upload artifact` success, `deploy`
success. Live:

```
/ (verify.html)  200  303,002 B  de4fbc53…   == repo (run 42792730857, sha 125a083)
/privacy.html    200    4,673 B  e570784f…   == repo
/terms.html      200    3,663 B  9e8daa06…   == repo
```

The landing on the running instance links
`…github.io/verifiedUniqueAliases/privacy.html` and `…/terms.html` and nothing
else legal — that is what made the `PRIVACY.md`/`TERMS.md` removal safe.
