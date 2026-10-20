# HANDOVER — paypal-auth-vm security audit cycle (2026-10-20)

Audience: the next LLM/agent continuing the work. Read **AGENTS.md** first for
architecture, threat model, and live-tested API traps; this file is the *state
of play* + *what to do next*. Everything here was verified on 2026-10-20
(UTC times given). **No secrets are stored in this file** — see §6 for where
the real credentials live.

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
- `verify.html` — MRTD/RTMR pinning, code & preflight pins, **app pins**
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

### 2.2 Production (Alibaba, cn-beijing)

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
| OSS presign helpers | `/tmp/oss-url.mjs`, `/tmp/oss-puturl.mjs`, `/tmp/sign-oss.mjs` |
