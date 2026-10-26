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
  https://login.airma.de/` (expect `200/ssl=0`; `:80` → `308`).
- **Report endpoint**: `GET /report` just redirects to `/`; the JSON is
  produced by **`POST /generate`** from the landing page (one-time) — the e2e
  harness intercepts it from the page traffic.
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
