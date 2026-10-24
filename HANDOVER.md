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
| **self_report sink ENABLED (2026-10-24 21:25 UTC)** | ✅ Prod config (user_data) now carries `self_report` → HK bucket `paypal-tdx-relay-1792227992`, prefix `boot`, signed by a dedicated **write-only RAM key**: user `pav-selfreport`, policy `pav-selfreport-put` = `oss:PutObject` on `acs:oss:*:*:paypal-tdx-relay-1792227992/boot/*` ONLY (live-probed: in-scope PUT 200, out-of-scope 403). Pushed via `Stop → ModifyInstanceAttribute --UserData → Start` (readback matched, 5,836 B b64); first boot published `boot/(none)-1792905904-stage.json` + `boot/latest.json` (`schema pav-selfreport/1`, `stage: config`, `ok: true`). **Known gap**: `egress_lockdown()` (main.rs:206) flushes the nftables output chain BEFORE `selfreport::serving()`, so the success heartbeat — and any halt after lockdown — is silently dropped; pre-lockdown stage/ACME-failure/halt docs land (proven by the `boot/prod/*-halt.json` history from 2026-10-23). Fix = sink-IP allow rule in the lockdown set or publishing the heartbeat before lockdown — needs a rebuild + deploy cycle. Listing needs `aliyun oss ls oss://…/boot/ --endpoint oss-cn-hongkong.aliyuncs.com` (bare `ls` 403s). Config generator `deploy-alibaba.sh` does NOT yet emit `self_report` — next deploy would drop the sink unless wired in. |
| **v185.1 gates (2026-10-24 19:5x UTC)** | ✅ offline **196/0** · live-envelope **204/0** (`REAL_REPORT=/tmp/live-report.json`) · cargo **20/0** · `check-manifest-parity` **PARITY OK** · served == README == local == `14a54222…` (163,150 B) over https **and** http/IP · **live PayPal sandbox e2e PASS ×2** — verified (19:56:43) AND full (19:57:31) buttons: login → consent → callback → claim → green → downloaded. |

---

## 1. Mission & threat model

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
- [ ] **T6 · Audit round 2** (the cycle): re-audit everything fixed in round 1
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
| Prod enclave config (PayPal pair, CF `dns01_secret`, EAB, attestation key) | instance user_data (`DescribeUserData i-2zefwa6bdimeg1rbcfsg`); mirrored at `/tmp/prod-config.json`, `/tmp/prod-ud.b64` (ephemeral) |
| Local (pair-swapped!) config | `/tmp/ali-config.json` |
| Alibaba STS/OAuth profile | `~/.aliyun/config.json` |
| Self-report RAM key (PutObject `boot/*` only, created 2026-10-24) | RAM user `pav-selfreport`; secret returned ONCE at creation — local mirror `/tmp/pav-ak.id` + `/tmp/pav-ak.secret` (ephemeral, 600) |
| OSS presign helpers | `/tmp/oss-url.mjs`, `/tmp/oss-puturl.mjs`, `/tmp/sign-oss.mjs` |
