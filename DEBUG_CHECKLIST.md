# Debug Checklist: Confidential VM Attestation Issues (Alibaba Cloud Intel TDX)

> **Scope.** This branch is **pure-play Intel TDX on Alibaba Cloud ECS**
> (`ecs.c9i.large`, `ConfidentialComputingMode=TDX`). The GCP and OCI stacks,
> the cargo feature flag, and every AMD/Google evidence path were deleted in
> v180 (see `AGENTS.md`, `audit.md` §3). The auditor rejects a report without a
> hardware-signed TDX quote at the first gate.
>
> An earlier version of this file documented GCP SEV-SNP + vTPM diagnostics
> (`enable-guest-attributes`, `tpm2 nvread 0x01c00002`, `sev-guest`). Those
> commands, and the scripts they referred to (`deploy-gcp.sh`,
> `gcp-config-check.sh`, `verify_enclave.sh`, `README_GCP_ATTESTATION_FIX.md`),
> were removed with that stack. They are retained only as history at the
> bottom of this page.

---

## Current root of trust

| | |
|---|---|
| Platform | Intel TDX (no TPM, no vTPM, no `/dev/sev-guest`) |
| Quote source | `configfs_tsm` (`tdx_guest`), read via `/sys/kernel/config/tsm/report` |
| Signing chain | **PCK certificate → QE report → Intel TDX Root CA** |
| Measurement | `MRTD` + `RTMR0..3`, pinned in `verify.html` |
| Auditor | `verify.html` — Intel-only; a non-TDX report fails closed immediately |

Two consequences that surprise people coming from the TPM world:

- **There is no EK certificate and no NVRAM index.** Nothing to `tpm2 nvread`.
- **There is no PCR 15 / disk-manifest measurement.** The boot manifest is
  bound into the quote's RTMR registers instead, and `verify.html` compares
  the reported `disk_manifest` against its own pinned copy.

---

## Diagnostic commands (all verified working from the operator host)

### 1. Is the enclave up at all?

```bash
curl -s --max-time 20 https://login.airma.de/debug/envelope | head -c 400
```

A healthy enclave returns JSON whose `attestation_report.enclave_config.boot_measurements`
carries `binary_sha256` and the `disk_manifest`. No output, or a non-JSON body,
means the enclave is not serving — go to the serial console (step 3) before
looking at anything in the auditor.

### 2. Instance state and its config

```bash
# Find the prod instance by NAME — the id changes on every spot recreate.
# (`--InstanceIds` on DescribeInstances returns EMPTY in this CLI: list and
#  filter client-side. AGENTS trap, re-hit several times.)
aliyun ecs DescribeInstances --RegionId cn-beijing \
  | jq -r '.Instances.Instance[] | "\(.InstanceId) \(.InstanceName) \(.Status)"'

# The enclave's config IS the user_data (base64 JSON). Read it back:
aliyun ecs DescribeUserData --RegionId cn-beijing --InstanceId <ID> \
  | jq -r '.UserData' | base64 -d | jq .
```

**Red herring:** the `UserData` field of `DescribeInstanceAttribute` /
`DescribeInstances` is `null` even when user_data is set. `DescribeUserData`
is the API that reports it.

### 3. Boot logs (serial console)

```bash
aliyun ecs GetInstanceConsoleOutput --RegionId cn-beijing --InstanceId <ID> \
  | jq -r '.ConsoleOutput' | base64 -d
```

**The field is `ConsoleOutput`, not `SerialConsoleOutput`** — the latter reads
back empty. This lags by minutes and is capped at 64 KiB, so it shows recent
boot only. Healthy sequence:

```
[INIT] ... module loads ...
ACME certificate obtained in RAM successfully
HTTPS server listening on 443
selfreport: ... stage=serving
```

`ACME certificate obtained in RAM` **not** appearing is the most common
cause of a dark `:443` — see §Failure modes.

### 4. Boot heartbeat (the console-free channel)

The enclave publishes per-stage boot status to OSS, signed by a write-only
RAM key (`pav-selfreport`, `oss:PutObject` on `.../boot/*` only):

```bash
aliyun oss ls oss://paypal-tdx-relay-1792227992/boot/ \
  --endpoint oss-cn-hongkong.aliyuncs.com
aliyun oss cat oss://paypal-tdx-relay-1792227992/boot/prod/latest.json \
  --endpoint oss-cn-hongkong.aliyuncs.com
```

**Bare `ossutil ls` 403s** — the endpoint flag is required. **Use `oss cat`,
not `oss cp … -`**: the `-` form is rejected here (`not support flag form -`)
and a `cp` to a local path can silently produce a 0-byte file.

Note the known gap fixed in v186: `pin_sink_network()` must run *before* the
nftables output flush, or the success heartbeat is silently dropped. If
`boot/latest.json` is stale but the serial console shows `serving`, suspect
the sink allow-rule rather than the enclave.

### 5. TLS / ACME

```bash
curl -sI https://login.airma.de/ | head -3
curl -s https://login.airma.de/tls-cert.pem | openssl x509 -noout -subject -dates
```

The leaf SHA-256 here **must equal** the one inside a live login report's
`session_context.tls_certificate_pem` — that equality is what the audit's
channel row checks.

### 6. The gates themselves

```bash
node scripts/test-verify-security.mjs                 # static + fixture harness
CHROMIUM_PATH=$(command -v chromium) \
  node scripts/e2e-login-download.mjs                # live browser login → download → audit
```

The harness reads `verify.html`, `index.html`, `zk.html`, `zk-rsa.html` and
`src/main.rs` directly, so it catches a stale pin or a drifted `CALLBACK_CONTENT`
without a deploy.

---

## Failure modes

| Symptom | First place to look |
|---|---|
| `curl` to `/` returns nothing | serial console (step 3) — is it still in ACME? |
| `/` serves but `/debug/envelope` is empty | enclave panicked after listen; serial console |
| `boot/latest.json` stale, console says `serving` | `pin_sink_network()` ordering; sink allow-rule |
| Audit shows **red** on a single row | read the *gate's* message, not the feature (see v178 pattern below) |
| `Identity preimage violation` on an honest login | JSON byte contract — key order / null handling (v178) |
| `DescribeUserData` returns 0 bytes | known CLI quirk right after a push; **the boot is the test** |
| Plain HTTP `Host: login.airma.de` → 403 HTML | Alibaba Beaver ICP-filing interception, **not** the enclave; probe `http://101.200.178.251/` with no Host rewrite |
| `InvalidAccessKeyId` on any `aliyun` call | OAuth STS in `~/.aliyun/config.json` expires (~1 h); **one** `aliyun …` call re-mints it |
| `SecurityTokenExpired` on a relay transfer | presigned URLs embed the STS token — regenerate them immediately before arming, never ahead of time |
| PayPal: *“this action is not supported … (invalid client_id or redirect_uri)”* | the **Live app's** Log in with PayPal feature, not the uploaded credentials — see below |

---

## PayPal rejects the authorize URL (`invalid client_id or redirect_uri`)

First, rule the credentials out — they are separable from the authorize page:

```bash
# 200 = the client_id/secret pair really is a LIVE REST app on this account.
# 401 invalid_client = it is a sandbox app, or the secret is the sandbox one.
curl -s -o /dev/null -w '%{http_code}\n' -u "$CID:$SEC" \
  -d grant_type=client_credentials https://api-m.paypal.com/v1/oauth2/token
```

A valid pair still gets that page, because `signin/authorize` only accepts a
client_id whose **Log in with PayPal** feature is enabled and approved with a
matching Return URL. The enclave sends `redirect_uri = https://<domain>/callback`
(`src/main.rs`, from `config.domain`) — so for EACH app in `EXPECTED_APPS`
(`verify.html`), in the **Live** tab of developer.paypal.com:

1. App → *Features* → enable **Log in with PayPal** → *Advanced Settings* →
   **Return URL** exactly `https://<domain>/callback` (no trailing slash).
2. **Approval Status** must read *Approved* — PayPal reviews it, up to 7 business days;
   while pending the authorize page fails with this exact error.
3. *Information requested from customers*: tick the fields the flow's scope asks for
   (`full` asks `openid profile email address`; `verified` asks only
   `…/services/paypalattributes`). An unpermitted scope fails here too.
4. Fill *Privacy policy URL* and *User agreement URL* (required to save the feature).
5. A sandbox Return URL does **not** carry over to Live; it is entered per environment.

Discriminator: click **verified only** first. It requests the smallest scope, so if
it renders the PayPal login form while **full profile** does not, the problem is
step 3 on the PII app rather than the Return URL. Note also that PayPal forbids
logging in with the account that OWNS the app — test with a different buyer account.

---

## Deploy-order rules (HANDOVER §0.6) — getting these wrong looks like a config bug

1. `user_data` is **disk-bound**: a push is discarded by any later
   `ReplaceSystemDisk`, and a push while `Running` may be ignored.
   Correct order: **Stop → ReplaceSystemDisk (if any) → ModifyInstanceAttribute --UserData → Start**.
2. `DescribeUserData` may read 0 bytes immediately after a good push. Do not
   re-push on that basis; confirm via the boot instead.
3. Relay re-arm: **Stop → Replace → UserData → Start**, only on the
   stock-Debian relay (`paypal-tdx-relay179e`). The custom-image relay
   (`oss-relay-tmp2`) never executes `user_data` — do not use it for transfers.

---

## Historical: the GCP SEV-SNP era (retained for context)

Everything below applied to the **retired** GCP stack. It is kept because the
*architectural lesson* still matters when reading the older audit reports.

### The two-key model (GCP vTPM)

The confusion that cost the most time: people assume the Attestation Key and
the Endorsement Key should match. **They should not.**

| Key | Purpose | Source (GCP) |
|---|---|---|
| **EK Certificate** | Proves "this is real GCP hardware" | NVRAM `0x01c00002`, Google-signed |
| **Session AK** | Signs TPM quotes for this session | Created via `tpm2_createprimary` |

A check comparing the EK cert public key to the session AK public key will
**always fail** — that is correct behavior, not a forgery. Guides that tell you
to search persistent handles (`0x81010001`) or call `tpm2_createak` are
designed for a different provisioning model than GCP's.

### The GCP launch gap

GCP required `enable-guest-attributes=TRUE` at instance creation for the
`sev-guest` driver to bind to the vTPM interface. Without it, the Rust code
saw empty NVRAM, no TPM devices appeared, `modprobe sev-guest` failed
silently, and attestation spun forever — while the console still said
"Confidential VM". Selecting a confidential machine type was not sufficient.

### The current stack has neither problem

Intel TDX on Alibaba has no TPM, no NVRAM, and no guest-attributes flag. The
equivalent "did the hardware interface come up" question is simply: does
`/sys/kernel/config/tsm/report` exist and does `configfs_tsm` produce a quote?

---

## Triage pattern: the failing gate is not the failing feature (v178 incident, Alibaba TDX)

**Symptom:** "I didn't get the attestation downloaded at the end of the login."

**Wrong first instinct:** debug the download logic (`downloadReportFile`, the
`?afterlogin=1` path, browser download permissions).

**Right first instinct:** in this system a missing artifact is almost always a
**symptom of a red gate** — the report download is deliberately suppressed
unless every audit row is green. Find the first ❌ / thrown error (browser
console + the status lines), not the downloader.

**Root cause (v178):** cross-implementation JSON byte drift. The enclave
hashed `serde_json::to_string(&minimized)` of the PayPal identity struct
(field order `user_id, sub, verified_account, payer_id`), but the report
embedded the same record through `serde_json::json!` — whose map reorders keys
**alphabetically**. The auditor recomputed the hash from the report's key
order (`JSON.stringify` of the parsed object preserves the text order), so the
bound hash and the recomputed hash could never match and *every honest login*
tripped `IDENTITY PREIMAGE VIOLATION`:

```
quote-bound  53dd6264…   <- struct order    {"user_id":…,"sub":…,"verified_account":…,"payer_id":null}
recomputed   a9f5e639…   <- alphabetical    {"payer_id":null,"sub":…,"user_id":…,"verified_account":…}
```

**Diagnosis recipe (works for any hash-binding mismatch):**
1. Reproduce in a real browser — `CHROMIUM_PATH=$(command -v chromium) node
   scripts/e2e-login-download.mjs` — and SAVE the payload the gate rejected
   (the script writes `/tmp/claimed-report.json`).
2. Hash each candidate serialization offline and see which one matches the
   bound value — that identifies the exact byte contract the other side used.
3. Fix the side that is *supposed* to define the contract (here: the auditor
   must reconstruct the canonical struct layout, since the report carrier may
   reorder keys) and pin the layout with a test on the producing side
   (`security_tests::paypal_identity_json_layout_pinned`).

**Why the tests didn't catch it:** the fixtures were self-consistent — the
report object and the expected hash both used the same key order. The
regression fixture now carries the LIVE shape (alphabetically keyed object):
a fixture that serializes like the producer cannot see producer/consumer drift.

**Rules that generalize:**
1. A missing output ⇒ read the gate output first; the downloader is rarely the bug.
2. Hashing "the same JSON" across two implementations is a **byte contract**
   (key order, null handling, whitespace). Pin it on one side, reconstruct it
   canonically on the other.
3. Fixtures must include the *live* serialization shape, not the pretty one.
4. Fail-closed UX must NAME the failing gate — that is what turned this
   incident into a one-line triage once a browser repro existed.
