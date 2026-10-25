# AGENTS.md - Status Guidelines for PayPal Auth Confidential VM

## Branch Layout (updated 2026-10-16)

| Branch | Status | Contents |
|---|---|---|
| **`alibabacloud`** (default branch) | ✅ Active line of work | Alibaba Cloud / **aliyun CLI** stack: `Dockerfile.alibaba`, `build-alibaba-docker.sh` (the build; wraps `build-alibaba-image.sh` + `build-initramfs-tools.sh`), `deploy-alibaba.sh`, `import-alibaba-image.sh`, `build-scripts/create-alien-deb.sh`. **Legacy (do not use for deploys)**: `build-alibaba.sh`, `build-alibaba-disk.sh` and `build-alibaba-simple.sh` are retired hard-fail stubs (v184/v185 — they produced non-bootable/unused artifacts) |
| `oraclecloud` | 🧊 Archive — do not develop here | Former `main`: Oracle OCI stack (`Dockerfile.oci`, `build-oci-*.sh`, `deploy-oci.sh`, `import-oci-image.sh`), the v161–v162 security hardenings, and the `oasis/` Sapphire + SEV-SNP sub-project |
| `origin/main` | 🧊 Archive ref — unchanged on GitHub | `oraclecloud` content minus the final `capture-golden-pcrs.mjs` commit |

- **The OCI files are NOT on this branch.** `build-oci-*.sh`, `Dockerfile.oci`, the v161+ `verify.html`/`scripts/` tooling and `oasis/` live only on `oraclecloud`. To resume Oracle work: `git switch oraclecloud`.
- OCI local build state (host `ol10/` staging, `.build-provenance`, qcow2/UKI/initramfs images, `node_modules/`) was deliberately deleted from this worktree on 2026-10-16 — it is all gitignored/regenerable (`bash build-oci-docker.sh`, `bash extract-ol10-platform.sh`).
- Alibaba/aliyun CLI work happens **here**; see "Alibaba Cloud Platform Notes" below for the packaging → import → deploy workflow.

---

## Project Overview

`paypal-auth-vm` (crate name: `paypal-auth-vm`) is a hardware-attested Rust service that provides a secure bridge for PayPal OAuth tokens across **multi-cloud confidential compute**:

| Cloud Provider | Architecture | Root-of-Trust | Key Driver |
|---|---|---|---|
| **GCP** (Confidential VM) | AMD SEV-SNP via vTPM | Google EK Cert + Session AK | Standard TPM 2.0 |
| **Alibaba Cloud** (ECS.c9i.large) | Intel TDX | PCK Certificate (PCK chain → Intel SGX/TDX Root CA) | Custom provisioning stack |

Supported build target: **Alibaba Cloud Intel TDX, compiled unconditionally** (the `alibabacloud` cargo feature was removed in v180; GCP/OCI paths are deleted from this branch — see audit.md §3).

### Login Flow (v183 — no pre-login attestation, PKCE-bound)

The old **pre-flight** (`POST /attest/preflight`, one TD quote per unauthenticated click) is **removed** — it was a trivially reachable enclave resource-exhaustion surface. The flow is now:
1. Trusted auditor copy (file:// / GitHub Pages) generates the ECDH keypair + nonce, then calls **`POST /attest/login-session`** — S_enc-signed fields only (app, scope, environment, `state`, **`code_challenge`/S256**), **no quote minted**; the ONLY thing stored server-side is this login's **PKCE verifier** (bounded table, TTL 600 s, enclave-RAM-only, never echoed).
2. The browser builds the PayPal authorize URL from the audited-app allow-list **including `code_challenge` + `code_challenge_method=S256`** (R3-1 — the auditor hard-REFUSES a challenge-less login: the owner holds the PayPal client secret and observes the redirect code, so without PKCE they could exchange the code directly and read the identity in plaintext); the client session travels inside the OAuth **`state`** token (base64url JSON `{v,p,n,f,c,r}`).
3. After PayPal, **`/callback`** resolves the PKCE verifier for the state (fail-closed — forged/expired states never reach PayPal), exchanges the code with `code_verifier` (PayPal enforces), zeroizes it, then mints the hardware quote — gated behind the PayPal-verified code exchange (**PayPal is the attacker filter**) — binding `report_data[32..64] = SHA-256(P_client ∥ Nonce_client)` and returning the report E2EE'd to `P_client`. Signed `timestamp_ms` comes from PayPal's `Date` header when available (the platform clock is provider-controlled and runs +8 h off — R3-3).
4. `/debug/envelope` is served from a **15-minute boot cache**; it is no longer part of any login path (kept for pin-rotation tooling only).

The auditor is **Intel-TDX-only** (audit.md §5.1): reports without a hardware-signed TDX quote are rejected outright; the AMD VCEK/ASK/ARK and Google NVRAM EK verification paths are deleted.

### Hardware Roots of Trust Compared

| Component | GCP AMD SEV-SNP | Alibaba Intel TDX / AMD Rome |
|---|---|---|
| **Hardware Key** | Google-provisioned EK/AK (NVRAM) | PCK from Intel PKI OR VCEK from AMD KDS |
| **Key Source** | NVRAM index `0x01c00002` | TPM NV endorsement hierarchy OR online query |
| **Quote Mechanism** | TPM quote via `tpm2_quote` (session-bound) | TPM quote via standard `tpm2-quote` flows |
| `/dev/sev-guest` | **Not available** on GCP vTPM | Not applicable (Intel TDX) |
| ConfigFS TSM | Times out / unavailable | Not required |
| Persistent AK handle | `tpm2_getcap handles-persistent` → empty | Must create session AK via `tpm2_createprimary` |
| Kernel module path | N/A (uses unified TPM path) | Optional `modprobe intelpsfw`, `tsm` |

The project uses a **single codebase** with conditional compilation to support both platforms.

---

### 🏆 Current Accomplishments

- **Pure-Play Intel TDX** (v180): multi-cloud abstractions, the cargo feature flag, and every AMD/Google evidence path are purged from source, CI and initramfs (audit.md §3). The auditor rejects non-TDX evidence at the first gate.
- **Correct GCP vTPM Attenuation Model** (v145): Resolved fundamental misunderstanding about two-key attestation. The enclave uses the correct model: Google EK Certificate (NVRAM `0x01c00002`, static silicon proof) is separate from the Session Signing AK (created fresh per-attestation via `tpm2_createprimary`, dynamic quote signer). Keys intentionally do not match.
- **Full EK Certificate Retrieval**: The 1560-byte Google EK/AK CA Certificate is retrieved from NVRAM index `0x01c00002` without truncation using unbounded `tpm2 nvread`. Systematic scanning across indices `0x01c00002`, `0x01c00001`, `0x01400001`, and more.
- **Hardened TPM Quote Verification**: Full binary parsing of `TPMS_ATTEST` in audit flow verifies the hardware-signed nonce from raw TPM quote message, neutralizing session replay and forgery attacks.
- **PCR 15 Software Binding**: Strict verification of `disk_manifest` hash against hardware PCR 15, ensuring running code matches GitHub provenance.
- **PCR Composite Digest**: Auditor manually reconstructs expected SHA-256 hash of all quoted PCRs (0, 4, 8, 9, 15) and verifies against signed `TPMS_ATTEST`.
- **Native DHCP Implementation**: Complete rewrite of network acquisition from shell scripts into pure Rust. Uses `socket2` with `SO_BINDTODEVICE` for reliable broadcast UDP on interfaces lacking IP bindings, including full BOOTP packet construction, lease parsing, and route application (with GCP-specific `/32` MTU handling).
- **Three-Path AMD Hardware Root Acquisition**: Automatic 3-path fallback strategy when acquiring SNP reports — NVRAM scan (systematic NV index discovery), TPM quote auxblob inspection, and ConfigFS TSM interface. Includes automatic VCEK fetch from AMD Key Distribution Service (KDS) based on extracted chip ID.
- **Intel TDK Adapter**: Module (`intel_tdx.rs`) providing PCK certificate retrieval stubs, platform availability checks, and readiness detection for Alibaba ECS infrastructure.
- **PID 1 Hardened Init Pipeline**: All filesystem lifecycle logic lives in `enclave_init` module within PID 1 before Tokio runtime starts. Handles mount ordering (`/dev` first so kmsg works), aggressive driver discovery via recursive `insmod` scanning of `/lib/modules`, and EFI partition measurement (dynamic device scanning).
- **Egress Hardening & Firewalling**: nftables ruleset enforcing strict TCP/UDP port filtering. TLS pinning enforced at transport layer via embedded `google_ca.pem` and `paypal.pem` compiled into binary via `include_bytes!`. DNS resolution hardcoded via `reqwest::resolver::resolve` to prevent hijacking. Bandwidth throttled per-IP and globally.
- **Secure Time Synchronization**: RTC pre-seeded to epoch 2026 prevents TLS cert validation failure on cold-boot machines. HTTPS-based time fetch serves as clock source after initial boot; timezone stripped from Date header.
- **Stable Build OS**: Build system, kernel image, initramfs pinned to Debian 13 (Trixie) using snapshot.debian.org. Reproducible via multi-stage Docker synthesis engine.

---

## 🚧 Project status: DEVELOPMENT / DEBUG PHASE (user-mandated 2026-10-22)

This service is **not production-final — it is actively being improved and
hardened**. Brief webservice downtime during builds, image rollouts,
placement retries and attestation debugging is **expected and acceptable**;
do not let outage-avoidance block experiments or rollbacks. Prefer rolling
forward with fixes over preserving uptime. (The instance/snapshot/image
rollback path should still be kept in place so any experiment can be
undone.)

## ⚠️ Critical Architectural Knowledge: GCP vTPM Two-Key Model

This is the single most important piece of knowledge for any agent working on this project.

### The Two-Key Model
On GCP Confidential VMs, TPM attestation uses **two intentionally different keys**, never the same by design:

| Key | Source | Lifecycle | Purpose |
|---|---|---|---|
| **Google EK Certificate** | NVRAM `0x01c00002` (permanent, Google-signed) | Boot-only read | Silicon Identity Proof — proves this is real GCP Confidential VM hardware |
| **Session Signing AK** | Fresh key created each boot via `tpm2_createprimary` | Per-attestation random | Quote Signer — signs the TPM Quote containing PCR values + nonce |

A check comparing the EK cert public key to the session AK public key will **always fail** — this is not a forgery attack, it is the architecture's expected behavior.

### Why No Persistent AK Handle?
GCP Confidential VMs (n2d with AMD SEV-SNP) **do not pre-provision persistent Attestation Key handles** in TPM NVRAM (`0x81010001`, `0x81010002`, etc. are all empty). Running `tpm2 getcap handles-persistent` returns an empty list. Attempting `tpm2_readpublic -c 0x81010001` fails with error `0x18b` ("handle is not correct for the use").

### Correct Verification Chain
1. **EK Certificate** (from report field `google_ak_cert_pem`): Verify it is issued by `EK/AK CA Intermediate` under Google's CA hierarchy → proves silicon identity
2. **TPM Quote** (signed by session AK): Verify `TPMS_ATTEST` structure, PCR composite digest, and session nonce → proves measurement integrity for *this* session
3. **Do NOT** compare EK cert key to session AK key — they are intentionally different

### Platform Constraints: What Does NOT Work
- **`/dev/sev-guest`**: Missing on GCP vTPM. GCP abstracts AMD SEV-SNP entirely behind its own vTPM abstraction layer.
- **`tsm` / `amd_tsm` kernel modules**: Loadable but non-functional within the GCP vTPM abstraction.
- **ConfigFS TSM path** (`/sys/kernel/config/tsm/report`): Available but times out; cannot be relied upon.
- **`tpm2_getcap handles-persistent`** standalone binary: Not present in initramfs. Always use the `tpm2` binary directly (`tpm2 getcap handles-persistent`).
- **`tpm2_createak`**: Tool exists but `-D` (digest) flag is invalid for this version.
- **GCP Compute Metadata API for hardware attestation**: Removed. Hypervisor-controlled endpoint is not trusted for root-of-trust establishment.

---

## Alibaba Cloud Platform Notes

### 🚨 Golden rules (2026-10-23 — every one of these cost hours at least once)

1. **The reserved EIP must be associated with the VM, always.** The Cloudflare
   DNS-01 token is source-IP-restricted to `101.200.178.251`
   (`eip-2zet05jbat6wr6rp7elrc`); without the EIP the enclave can NEVER get a
   certificate, no matter how good the image is. No EIP ⇒ no TLS ⇒ dark box.
   Check the EIP **before** you judge an image (see the ACME section below).
2. **"Running + dark" is never proof of a broken image or a wedged host.**
   Fail-closed halts sleep forever and the ACME retry loop serves nothing.
   Get positive evidence (ESP `boot-probe.log`, or a boot log that reaches the
   probe) before declaring a regression.
3. **The serial console is a 64 KiB head-capped buffer that never rolls and
   never resets per boot**, and it is **emptied when the instance stops**.
   Check the timestamps inside a capture against the boot under test; poll it
   only while the instance is `Running`; never plan a diagnosis around reading
   it after a self-poweroff.
4. **Never A/B two images without EIP parity.** A same-hour comparison where
   only one instance held the reserved EIP proves nothing about the images
   (this exact mistake produced the false "v172 is broken" verdict on
   2026-10-22).
5. **Only a bucket outside mainland China is readable from the operator
   host.** The relay bucket `paypal-tdx-relay-1792227992` lives in
   **`oss-cn-hongkong`** and is the designated operator-facing sink (PUT and
   GET both work from the operator host and from a mainland ECS guest).
   Objects in the mainland buckets (`paypal-tdx-image-…`, `paypal-tdx-img-…`)
   are **write-only from the operator side**. Never build a forensic loop that
   needs to read a mainland object.
6. **Never `grep` a raw block device.** Stream it through
   `tr -c '[:print:]' '\n'` with a bounded `dd` range (see the ESP recipe
   below) — `grep -aob` on `/dev/vdb` treats the whole device as one "line"
   and OOM-kills the guest (3.6 GB RSS observed).

### 🖥️ Instance & Disk Policy (user-mandated 2026-10-21 — apply on every deploy)

1. **Confidential VM: 1 GiB system disk, in-place disk rewrites only.**
   - The prod enclave instance keeps a **1 GiB `cloud_auto` system disk**.
   - Redeploying = **rewrite the disk of the SAME instance**
     (`ReplaceSystemDisk` with the new image id) — **never** stop/release/
     create a replacement Confidential VM as long as its disk is 1 GiB.
     The old instance may be kept stopped as a rollback, but new deploys
     never spin up new Confidential VMs.
   - Trap: the `aliyun` CLI's `ReplaceSystemDisk` exposes neither size
     nor category flags and silently defaults to **20 GiB** (the `DiskSize`
     RPC name is also wrong — the real API parameter is **`SystemDisk.Size`**
     in GiB, sent flat via the hand-signed `/tmp/ecs-call.mjs` RPC together
     with `SystemDisk.Category=cloud_auto`). Always verify
     `DescribeDisks … Size==1GiB` before starting the box.
   - **Overshoot is IRREVERSIBLE**: once a disk is >1 GiB, both
     `ReplaceSystemDisk` (`InvalidSystemDiskSize.ValueNotSupported`) and
     `ResizeDisk` (`InvalidDiskSize.TooSmall`, param name `NewSize`) refuse
     any smaller size. The only recovery is role-swapping to another
     instance that still has a 1 GiB disk (EIP move — proven 2026-10-21).
   - Trap: always `RebootInstance --ForceStop true` — the enclave PID 1
     does not ACK graceful ACPI shutdown, so a default (graceful) reboot
     hangs in `Stopping` for minutes and applies late.
2. **Relay VM: minimal hardware, 1 GiB disk, economy-stopped when idle.**
   - The relay must use the **smallest/cheapest instance type** that can
     shuttle the ~46 MiB image and a **1 GiB system disk**.
   - It must be **stopped in Economy mode immediately after each
     transfer** (`StopInstance --StoppedMode StopCharging`) — it must
     never idle in the running state.
3. **Relay VM: spot / preemptible, in-place disk rewrites only.**
   - Create it with `InstanceChargeType=PostPaid` +
     `SpotStrategy=SpotAsPriceGo` (spot pricing, no protection period).
   - **Updating the relay image = rewrite the disk of the SAME relay
     instance** (`StopInstance` → `ReplaceSystemDisk --ImageId <new relay
     image>` → `StartInstance`), exactly like the Confidential VM in
     item 1. **Never create a new relay VM (or release the old one) to
     roll out a new image** as long as it has only a 1 GiB disk —
     user-mandated 2026-10-22. Same rule for the Confidential VM:
     in-place disk rewrite, never a replacement instance.
   - `InstanceChargeType=Spot` is rejected (`InvalidInstanceChargeType
     .NotFound`); spot billing is `PostPaid` + `SpotStrategy` only.
   - **Proven in-place rollout (2026-10-22)**: `StopInstance` →
     `ReplaceSystemDisk --ImageId <new>` (hand-signed RPC; the CLI exposes
     no usable size flag) → `ModifyInstanceAttribute UserData <self-test>`
     → `StartInstance` → poll status. Same instance id, VPC, EIP all kept.
   - **`user_data` does NOT re-run on a plain stop/start** (verified
     2026-10-23): after the instance's first boot, cloud-init is already
     marked configured, so `ModifyInstanceAttribute UserData` + `StartInstance`
     executes **nothing** — a perfect silent no-op (no artifact, no error).
     The `ReplaceSystemDisk` step is what re-arms it. When a relay test
     produces no artifact, check this before hunting a curl/network bug.
   - **A relay script must not start with `exec >>/var/log/… 2>&1`**: if that
     redirect fails at that point in boot, bash exits immediately and nothing
     upstream is reached. Write a "started" marker to the artifact sink FIRST,
     then do the work, then write the result — so a silent script death is
     distinguishable from a failed upload.
   - **The relay can stop itself seconds after `StartInstance`** (observed
     2026-10-23: `Starting` → `Stopped` within ~15 s, three cycles, no artifact,
     empty console). Treat "I started the relay" as unproven: always require a
     marker object in the bucket before believing the script ran, and prefer the
     enclave's own self-report for anything that must be reliable.
   - A >1 GiB disk **cannot** be downsized by `ReplaceSystemDisk`
     (`InvalidSystemDiskSize.ValueNotSupported`, hit on the 40 GiB relay):
     the new disk keeps the old disk's size/category (40 GiB
     cloud_efficiency). Accept it; do not recreate the VM just to shrink.
   - A guest-side `systemctl poweroff` leaves `StoppedMode=KeepCharging`
     (still bills while stopped!) — always follow up with
     `StopInstance --StoppedMode StopCharging` to flip it to economy
     (verified 2026-10-22 on the relay).
   - Relay self-test convention: user_data powers OFF on success and
     **hangs in `Running` on any FAIL** — instance status is the
     pass/fail signal, since serial console output is lost on stop.
     Verified: HK Range-GET md5 == intranet PUT 200 on the dnsfix image.

### Target Instance Type: ecs.c9i.large (2 vCPU / 4 GiB, Intel TDX) in cn-beijing-i
- Live-proven 2026-10-23: spot `ecs.c9i.large` (SpotAsPriceGo, SpotDuration=0 — no protection period, no minimum time) with `SecurityOptions.ConfidentialComputingMode=TDX` boots the ESP image end-to-end and produces a **genuine hardware-signed TD Quote** (5007 B via configfs_tsm, provider=tdx_guest). MRTD/RTMR1/RTMR2 byte-identical to the xlarge; **only RTMR0 differs** (ACPI/platform config is per-shape) — a shape change therefore rotates exactly the RTMR0 pin.
- Cheapest TDX shape in Beijing (live spot 2026-10-23): **c9i.large $0.012/h** < c8i.large $0.013/h < g9i.large $0.015/h < g8i.large $0.017/h < r9i.large $0.020/h < c9i.xlarge $0.024/h (former default). 8th-gen is NOT cheaper than 9th-gen here despite the lower generation. TDX is enabled **per shape**, not per family — always probe a new shape with `/debug/envelope` before switching. Everything (bucket, image, instance) must live in one region
- TDX is real but **unexposed to userspace**: no `/dev/tdx-guest`, no `/sys/module/tdx_guest`, no `/sys/bus/platform/drivers/tdx`. The only reliable probe is the kernel banner (`Memory Encryption Features active: Intel TDX`) read from `/dev/kmsg` — see `intel_tdx::kernel_log_reports_tdx()`. The boot log prints every probe (`TDX probe: …=false`) so the serial console diagnoses it directly
- **Imported images must be flagged NVMe-capable or the launch is refused**: `RunInstances` fails with `The specified instance type requires NVMe but the image does not support NVMe` until `Features.NvmeSupport=supported` is set (the flag is an image attribute — the guest itself has NVMe built into Debian's cloud kernel, no module needed)
- Alibaba Cloud does **not** expose `/dev/sev-guest` or ConfigFS TSM interfaces out of the box for Spot instances

### IMDS delivery (config via `user_data`)
- Alibaba's metadata service is `http://100.100.100.200` (not `169.254.169.254`)
  and serves **plain HTTP only** — the nftables ruleset must allow
  `ip daddr 100.100.100.200` *and* outbound `tcp dport 80`, otherwise the
  enclave times out on config, panics as PID 1 and enters a reboot loop. Both
  rules are in `setup_firewall()` (2026-10-16 fix)
- `RunInstances --UserData` takes base64; the metadata endpoint returned the
  raw JSON in the live test, but `fetch_config()` accepts either form
- Reading it back: `DescribeInstanceAttribute` returns an **empty
  `UserData` field** — the config is only visible through the dedicated
  `DescribeUserData` API (`UserData.Value`, base64). An empty
  `DescribeInstanceAttribute` response does NOT mean the instance is
  unconfigured.

### ACME DNS-01 ONLY works from the reserved EIP (2026-10-22, user-confirmed)
- The `dns01_secret` (Cloudflare API token) is **IP-restricted to the reserved
  EIP** (`eip-2zet05jbat6wr6rp7elrc` = `101.200.178.251`). From any other
  source IP the API answers `9109 "Cannot use the access token from location:
  …"`, and `InRamAcmeManager::dns01_publish` surfaces that as its generic
  `Cloudflare zone not found` error (it reads `result[0].id` from the error
  body). The token itself verifies fine (`/user/tokens/verify`) — only the
  source-IP check fails, so the symptom looks like a missing zone.
- Therefore **the reserved EIP must be associated with the enclave VM** for
  boot-time cert issuance (and renewal) to work. An instance without the EIP
  ALWAYS ends in `ACME certificate failed: Cloudflare zone not found. Retrying
  …` and serves nothing — that is expected behavior, not an image bug. Moving
  the EIP to another instance silently breaks ACME for whoever loses it.
- **Debugging order for a dark instance:** (1) EIP association, (2) token
  state, (3) only then the image. A same-hour A/B of two images is invalid if
  only one held the EIP during its ACME window — 2026-10-22: exactly this
  produced a false "v172 image is broken" verdict (vm-2 ran v172 without the
  EIP and was killed before its ACME retry could succeed; the known-good boot
  then had the EIP from the start and greened out in 4 min).

### Boot diagnosis: the 64 KiB console trap + the ESP probe transcript
- `GetInstanceConsoleOutput` returns a buffer that is **head-capped at 65,536
  bytes and frozen when full** — it does not roll, and it does not reset per
  boot. A fetch can return a capture from hours and several boots ago (seen:
  a buffer fetched at 16:25 still showed a 15:14 boot tail). Always check the
  wall-clock timestamps INSIDE the capture against the boot being debugged
  before concluding anything.
- Verbose TDVF/OVMF firmware can eat the whole budget before the kernel prints
  anything (a boot that "froze at kernel 0.595 s" is usually just the cap).
  Likewise a log line landing at offset ~65505 (e.g. `BOOT-TIME TDX QUOTE
  PROBE`) proves NOTHING about what followed. The 2026-10-22 "all v170+ images
  wedge at the probe banner" conclusion was exactly this artifact: the same
  capture for v169 (2.7 KB less firmware noise) shows the probe PASSING
  (`QUOTE PROBE OK (5006 bytes, source=configfs_tsm)`).
- Reliable boot channel: the boot quote probe appends its transcript to the
  ESP (`/boot/efi/boot-probe.log`, per boot): `PROBE start`, `attempt n/8: no
  quote (status=…)`, `probe done: quote=<bool> attempts=N`, `BOOT QUOTE PROBE
  OK (N bytes, source=…)`, `ccel: …`, `FAIL-CLOSED: …`. Read it via an online
  snapshot of the system disk + the relay instance (attach the snapshot disk,
  grep the raw block device — no mount/toolchain needed).
- Fail-closed halts do NOT stop the instance: `enclave_init::poweroff()`
  deliberately sleeps forever (evidence preservation, no reboot). So
  `Status=Running` + dark ports is the expected signature of a fail-closed
  halt OR of the ACME retry loop — never treat "Running + dark" as proof of a
  wedged host.
- **Reading the ESP from a snapshot without mounting anything** (works on the
  minimal relay image): the ESP is GPT partition 1 = LBA 2048, 41 MiB:
  `dd if=/dev/vdb bs=512 skip=2048 count=83968 | tr -c '[:print:]' '\n' |
  grep -aE 'BOOT-TIME TDX QUOTE PROBE|attempt [0-9]/8|probe done: quote|
  BOOT QUOTE PROBE OK|FAIL-CLOSED|ccel:'`.
  `grep -aob` (or any line-oriented `grep` straight on the device) treats the
  whole 20–40 GiB device as a single line, buffers it, and OOM-kills the
  guest — always bound `count` and strip binary through `tr` first.
- **A guest-side verdict channel must leave the mainland or hit the control
  plane.** A `user_data` script CAN `PUT` to
  `$BUCKET.oss-cn-beijing-internal.aliyuncs.com` (intranet, works), but the
  operator cannot read that object back (see below), so it is only a useful
  sink if a same-region host later reads it — not as an answer channel.
  The one channel that always returns to an outside operator is instance
  state: end the script with `poweroff -f` on success and `sleep infinity` on
  failure, then read `Status` (`Stopped` vs `Running`).

### 🚫 Evidence channels from an operator host outside mainland China

| Channel | From outside mainland | Notes |
|---|---|---|
| ECS/RPC control plane (`DescribeInstances`, `DescribeUserData`, `GetInstanceConsoleOutput`, snapshots, EIP) | ✅ works | the only always-available path |
| **HK bucket** `paypal-tdx-relay-1792227992` (`oss-cn-hongkong`) | ✅ works both ways | presigned PUT+GET verified 2026-10-23 for a mainland guest and the operator host — **this is the exfil sink to use** |
| Mainland buckets (`oss-cn-beijing`) | ❌ read blocked | `GetObject` → 403 `AccessDenied` (vhost) / `PublicEndpointForbidden` (path style); `*.oss-accelerate.aliyuncs.com` → `InvalidRequest "OSS Transfer Acceleration is not configured on this bucket"` |
| `aliyun oss ls` (bucket list) | ✅ works | cross-region listing is fine — it is *object* operations that fail |
| `aliyun oss ls/stat` on an object | ❌ | always targets `oss-cn-hongkong`; 403 blames your bucket (see API traps) |
| Instance serial console | ⚠️ image-dependent | prod: 64 KiB head-capped and can be 100% TDVF firmware noise; the relay image returns **empty `ConsoleOutput`** (no serial console in its cmdline) while `LastUpdateTime` still advances |
| `RunCommand` / cloud assistant | ❌ on the relay | `DescribeCloudAssistantStatus` returned an empty set for `OthersLinux_64` |
| Enclave boot self-report → HK `{prefix}/latest.json` | ✅ works | `src/selfreport.rs`; signed PUT from the guest, presigned GET from the operator host (see the self-report section) |

So the guest→operator channel that actually works is: **guest PUTs to the HK
bucket, operator presigned-GETs it**. Verified 2026-10-23
(`forensic/channel-test.txt`: PUT 200, GET returned the body).
Two further console facts, both verified the same day: the response field is
**`ConsoleOutput`** (reading `.Output` silently yields `''`), and an empty
string does not mean "no boot" — `LastUpdateTime` keeps advancing.

### Boot self-report (`src/selfreport.rs`) — the dark-box channel (2026-10-23)

A dark enclave now reports its own state to the **Hong Kong** bucket, so
"why is it dark?" is answerable from the operator host minutes after a boot,
with no console, no snapshot, no relay, and no in-VPC helper.

- **What it publishes**: `{prefix}/latest.json` (stable, poll this) plus
  `{prefix}/{host}-{unix}-{kind}.json` (history). `kind` is `stage`
  (progress heartbeat), `fatal` (a retry-loop failure such as an ACME error),
  `ok` (TLS in RAM, serving) or `halt` (fail-closed, with the exact reason).
- **Payload**: `schema`, `kind`, `ok`, `stage`, `reason`, `ts_unix`,
  `uptime_s`, `hostname`, `kernel`. Stages in order: `mount` → `cmdline` →
  `drivers` → `measure` → `firewall` → `harden` → `network` → `config` →
  `probe` → `acme` → `serving`. So a halted box says exactly how far it got.
- **Never any secret**: the payload carries status strings and counters only —
  no token, key or config value. `payload_never_contains_sink_secrets` and
  `live_roundtrip_when_enabled` pin that and the wire format.
- **Best effort by construction**: each upload runs on a detached thread with
  a 10 s timeout, so a dead network costs one kmsg line and can never delay,
  alter or abort a boot decision. `enclave_init::poweroff()` publishes the
  recorded reason **once** and then parks as before.
- **Signed in-guest, not presigned**: a presigned URL embeds an STS token that
  dies within hours — exactly how stale `user_data` URLs failed silently here.
  The enclave signs each request itself (OSS V1, HMAC-SHA1).
- **Configuration** (any one of, in precedence order): `/boot/efi/selfreport.json`
  (read before `user_data`, so a boot that never gets config can still report),
  the `PAV_SELFREPORT_JSON` env var, or the `self_report` object in the enclave
  config (`config.example.json`). Missing ⇒ reporting is simply off.
- **Scope the credential to `PutObject` on that prefix** (RAM user, not the
  deploy AK). It is a guest-visible secret like the rest of the config.
- **Trap found by the live test**: OSS signs `Content-Type`. Sending the header
  without canonicalizing it returns a bare **403** with no explanation —
  `string_to_sign()` takes the content type, and the PUT path passes
  `application/json` while GET passes `""`.
- **Verify it yourself against the real bucket** (inert without the env var):
  `PAV_SELFREPORT_LIVE_SINK='{"bucket":…,"endpoint":…,"access_key_id":…,"access_key_secret":…}' cargo test live_roundtrip`
  — it performs a real signed PUT + GET through the production path. Manual
  check from the operator host: presign a GET for `{prefix}/latest.json` on
  the HK bucket.
- **Limitation**: after `egress_lockdown()` only 443 to the PayPal pins is
  allowed, so a halt *after* lockdown cannot publish. Every current halt site
  (network, config, probe, ACME) runs before lockdown; keep it that way or add
  the sink host to the lockdown rule deliberately.

### Boot diagnosis order for a dark instance (use this, in this order)

0. **Re-list the instances first.** Ids in this file go stale: the Round-1 id
   `i-2ze0sd65q6qhot55aerq` no longer exists, and every call against it answers
   `InvalidParameter "The instanceId provided is not valid"` — which is easy
   to misread as an API quirk while you keep polling a dead id (2026-10-23).
   `DescribeInstances` (no filter, or plural `InstanceIds`) is the source of
   truth for id → name → image → EIP.
1. `DescribeInstances` → `Status`; `EipAddress.AllocationId` == the reserved
   EIP? (No ⇒ stop here, that alone explains "no TLS ever".)
2. `DescribeUserData` (not `DescribeInstanceAttribute`) → config present and
   contains `domain`, `dns_zone`, `dns01_secret`?
3. `GetInstanceConsoleOutput` **while Running** → check the in-capture
   timestamps match this boot; look for `ACME certificate obtained` vs
   `ACME certificate failed: Cloudflare zone not found` vs
   `FAIL-CLOSED:` / `BOOT QUOTE PROBE`.
4. Only if 1–3 are inconclusive: snapshot the system disk, attach it to the
   relay, read `/boot/efi/boot-probe.log` off the raw device (recipe above).
5. Only then form an opinion about the image; and if you compare two images,
   give both the EIP for the whole comparison window.

### Alibaba-Specific Provisions Required
- Provisioning relies on downloading a versioned asset (`aliyun-cli`) and extracting it manually to bypass GPG restrictions
- Requires proprietary utility installation via `.deb` packaging
- Relies on Intel PCK certificates from Intel PKI as primary hardware root of trust
- TDX policy reads may be available via sysfs paths like `sysfs/firmware/intel/tdx/policy`

### 🚫 OSS data APIs are blocked from outside mainland China (since 2025-03-20)
`PutObject`/`GetObject`/`SetObjectAcl` from a non-ECS host return
`403 AccessDenied "must be addressed using the specified endpoint"` or
`400 PublicEndpointForbidden "please use CNAME instead"`, regardless of
region/endpoint. Bucket control-plane calls (`ls`, `stat`, `bucket-cname`)
still work, so the failure looks like a bucket misconfiguration — it is not.
**The exception is a bucket that itself lives outside the mainland**: the
Hong Kong bucket `paypal-tdx-relay-1792227992` (`oss-cn-hongkong`) is fully
readable and writable from the operator host *and* from a mainland ECS guest
(verified 2026-10-23) — it is the project's chosen evidence-transfer sink.
Workaround used by `import-alibaba-image.sh`: push the bytes to a **same-region
ECS instance** and PUT them there over the **intranet** endpoint, addressed in
virtual-host style (`$BUCKET.oss-cn-beijing-internal.aliyuncs.com`, path-style
returns `SecondLevelDomainForbidden`). Verified: 46 MB in 0.5 s, ETag == local
MD5. A custom CNAME domain is the other sanctioned route.
- **Working recipe (v179 cycle, verified twice 2026-10-23)**: a **V1 presigned
  PUT/GET URL via plain curl** is NOT geo-blocked — `aliyun oss cp` and any
  CLI-authenticated data-plane call are. So local→Beijing is: (1) presigned
  `curl -T <file>` → HK bucket (ETag == local MD5 = landed); (2) a **stock
  Debian instance + cloud-init user_data** pulls from HK (presigned GET), PUTs
  to the Beijing bucket over the intranet endpoint, reads back + compares MD5,
  then `shutdown -h now` — reaching **Stopped is the success signal**, every
  FAIL path must `while true; do sleep 3600; done` (**Running = failed**);
  (3) `ImportImage` (flat `DiskDeviceMapping.1.Format=raw`). The custom relay
  image (`Dockerfile.relay`) is **less reliable** than this (its runner stops
  itself seconds after boot with no artifact — several cycles 2026-10-23);
  prefer the stock cloud-init instance, fresh **per transfer** or re-armed via
  `ReplaceSystemDisk` (cloud-init is once-per-disk).
- **OSS V1 presigned URLs SIGN the Content-Type** (empty slot in the
  string-to-sign). A marker written with `curl --data` sends **POST** (→ 405
  on a PUT-signed URL) and with `-X PUT -H 'Content-Type: text/plain'` sends
  a header the signature never covered (→ `SignatureDoesNotMatch`). Marker
  writes must be `-X PUT -H 'Content-Type:'` — this bug made every relay
  marker silently vanish and cost hours of "did the script even run?" triage.
The standard path cannot be avoided: `CreateImage` refuses a data-disk
snapshot (`does not contain system disk snapshot`), so an image can only be
made from an OSS object via `ImportImage`.

### API traps (all hit live, all still present upstream)
- `ImportImage` takes `--DiskDeviceMapping.n.Format`, **not** `.ImageFormat`
- `ModifyImageAttribute --Features` must be sent in **flat** wire format
  (`Features.NvmeSupport=supported`). The `aliyun` CLI serializes its JSON
  struct form and the server rejects it; `--Features.NvmeSupport` is not a
  valid flag either. Bypass with a hand-signed RPC call (`SignatureMethod=HMAC-SHA1`,
  `SignatureNonce`, `Timestamp`) — see `/tmp/ecs-call.mjs` pattern
- `RunInstances` returns `InstanceIdSets.InstanceIdSet` (capital D) — reading
  `.InstanceidSet` silently yields an empty instance id
- `DescribeInstanceAttribute` does NOT populate `UserData` (returns empty) —
  use `DescribeUserData` for the instance config
- **New instances are NOT how images are rolled out** — see "🖥️ Instance &
  Disk Policy" above: rewrite the existing VM's disk with
  `ReplaceSystemDisk` (Confidential VM and Relay VM alike, whatever the
  disk size — the relay stays 40 GiB because downsizing is refused). Do
  not `RunInstances` a replacement and do not release the old box.
- `RunInstances` with `InstanceChargeType=Spot` →
  `InvalidInstanceChargeType.NotFound` (2026-10-21). Spot =
  `InstanceChargeType=PostPaid` + `SpotStrategy=SpotAsPriceGo`.
  `OperationDenied.NoStock` on a launch → pick another instance type via
  `DescribeAvailableResource --DestinationResource instanceType
  --SpotStrategy SpotAsPriceGo` rather than another zone/region.
- **Serial console output is lost once an instance stops**
  (`GetInstanceConsoleOutput` returns 0 bytes after `Stopped`) — and the
  relay runner powers itself off. Poll the console *while the instance is
  Running*, or design the `user_data` test to leave a verifiable artifact
  (e.g. PUT a result object to OSS) instead of relying on console logs.
- **STS tokens in `~/.aliyun/config.json` expire on the hour boundary**
  (`sts_expiration`); presigned OSS URLs embed the STS token and die with
  it, so a transfer started near expiry fails even if the URL's own
  `Expires` is later. Any `aliyun` CLI call after expiry rotates the
  token automatically — re-generate presigned URLs AFTER that call.
  Symptom from hand-signed callers (`/tmp/ecs-call.mjs`):
  `InvalidSecurityToken.Expired` — run `aliyun sts GetCallerIdentity` once
  and retry; the profile (mode `OAuth`) self-refreshes.
- **The `aliyun oss` subcommand cannot be aimed at another region from the
  operator host** (verified 2026-10-23). `aliyun oss ls --help` lists
  `--region`/`--profile` but **not** `--endpoint`, and in practice object
  operations always target `oss-cn-hongkong.aliyuncs.com` (the CLI's built-in
  default), returning the very misleading
  `403 AccessDenied "The bucket you are attempting to access must be
  addressed using the specified endpoint"` — it names your bucket, so it
  reads like an ACL/region misconfiguration. `--region cn-beijing` is
  ignored. Passing a bucket-prefixed `--endpoint` instead builds a doubled
  host (`$BUCKET.$BUCKET.oss-cn-beijing.aliyuncs.com`) and fails TLS.
  **Bucket listing (`aliyun oss ls`, no path) is fine** and shows each
  bucket's region. For object I/O use presigned vhost URLs generated by
  `/tmp/oss-puturl.mjs` / `/tmp/oss-geturl.mjs` against the HK bucket.
- **Cloud assistant / `RunCommand` is not guaranteed either**: the relay runs
  Alibaba's `OthersLinux_64` image. `DescribeCloudAssistantStatus` with
  `InstanceIds` returned an **empty set** for the relay (it does execute
  `user_data` at boot, so an init path exists, but do not assume a command
  agent). Confirm `InstanceCloudAssistantStatusSet` is non-empty **before**
  designing a diagnostic that needs `RunCommand`.
- `DeleteDisk` takes lowercase `--force`; `StopInstance` takes `--ForceStop`
- **EIP bind/unbind is VPC-side and rejects `InstanceType`**: ECS
  `DisassociateEipAddress` and `UnassociatePublicIpAddress` do not exist
  (`InvalidAction.NotFound`). Use `vpc UnassociateEipAddress` /
  `vpc AssociateEipAddress` with `AllocationId` + `InstanceId` and **no
  `InstanceType`** — both `Ecs` and `ecs` are rejected
  (`InvalidInstanceType.ValueNotSupported` /
  `InvalidParameter.InstanceTypeNotSupport`)
- **An instance's auto-assigned public IP blocks EIP binding**
  (`EIP_CAN_NOT_ASSOCIATE_WITH_PUBLIC_IP` — even while Stopped). Release it
  first: `ecs ReleasePublicIpAddress` (the `PublicIpAddress=<exact ip>`
  parameter is required); there is no "keep public IP" escape hatch
- **`/tmp/ali-rpc.mjs` args are `Key=Value`, never `--Key value`** — a
  bash-style `--RegionId cn-beijing` misparses into a garbage key and the call
  silently runs in the profile's default region (`cn-hangzhou` → empty
  result sets that look like "no instances exist")
- **STS creds expire (~3 h)**: `~/.aliyun/config.json` is OAuth mode. On
  `InvalidSecurityToken.Expired`, run any harmless `aliyun <product> <Action>`
  once — the CLI auto-refreshes STS and rewrites the profile, after which the
  `/tmp/*-rpc.mjs` helpers work again (`sts_expiration` shows remaining life)
- **`DescribeInstances` ignores a singular `InstanceId` param** — it silently
  returns every instance in the region (bit me: polled the WRONG instance
  after an EIP swap, watching "Running" on the new box while the old one had
  already stopped). List all + filter client-side, or pass the plural
  `InstanceIds` form
- **`RunCommand` targets instances with the INDEXED flag `--InstanceId.1 <id>`**
  (2026-10-25) — bare `--InstanceId` is accepted syntactically then fails
  server-side with `MissingParam.InstanceId`, and `--InstanceIds '[…]'` is
  rejected as an unknown flag (the help's "Did you mean: InstanceId" suggestion
  is misleading). Poll with `describe-invocation-results --biz-region-id
  cn-beijing --invoke-id <id>`; the result JSON is
  `Invocation.InvocationResults.InvocationResult[0]`, `Output` is base64
- **Both image buckets refuse the OSS PUBLIC endpoint entirely** (2026-10-25):
  `PublicEndpointForbidden … please use CNAME instead` from anywhere, and
  path-style addressing on the regional endpoint additionally returns
  `SecondLevelDomainForbidden` — so even presigned PUTs need **virtual-hosted**
  style. Working upload path: presigned vhost PUT → HK bucket → relay ECS →
  **Beijing intranet endpoint** PUT (ETag==MD5 on both hops), then
  `ALI_OSS_BUCKET=paypal-tdx-image-1792145409 SKIP_OSS_UPLOAD=1 bash
  import-alibaba-image.sh`

### TCG event-log & RTMR traps (hit live 2026-10-22)

- **The CCEL log IS readable in-guest on Alibaba TDX** (`read_ccel_log()`
  finds it at `data/CCEL`, a fixed 65536-byte area), so the boot-time replay
  gate is live there — and it found two parser issues on first contact:
- **The trailing padding of a fixed-size firmware log area is NOT part of the
  log**: Alibaba's real CCEL holds 1626 bytes of real events followed by
  0xFF/0x00 padding to 65536 bytes; parsing past the events reads
  `digestCount = 0xFFFFFFFF` (real failure:
  `implausible digestCount 4294967295 @1626`). Both parsers treat tails of
  only 0x00/0xFF bytes (any mix) as end-of-log — and since the replay must reproduce
  the quote EXACTLY, truncating there can never widen what is accepted.
- **The FIRST event of a crypto-agile TCG log uses the legacy `TCG_PCR_EVENT`
  fixed layout** (pcr u32 | type u32 | **digest[20]** | eventSize u32 @28 |
  event @32), not `TCG_PCR_EVENT2` (TCG PC Client PFP). Both parsers handle
  it; it is the EV_NO_ACTION "Spec ID Event03" header carrying the
  algorithm-size table.
- **RTMR reset convention: ZERO** ("The RTMR array is initialized to zero on
  build", Intel TDX Module Base Arch spec). Settled empirically 2026-10-22:
  the unextended RTMR3 in a live quote reads all-zeros. An earlier assumption
  here used SHA-384(1024×0x00); `ccel_replay_vs_quote` still accepts EITHER
  reset convention (recording which matched) so a future platform that
  differs cannot brick the boot.
- **Parse failure ≠ mismatch**: a log we cannot parse is noted + hex-dumped
  (first 2 KiB) and boot continues (enforcement deferred to the quote's RTMR
  pins); only a parsed log that REPLAYS to values ≠ the quote halts via
  `poweroff()` (the plan mandates the halt for inconsistent measurements).
- **Shared golden vectors** live in `/tmp/gen-vectors.mjs` and are asserted
  identically by `security_tests::ccel_replay_selftest_v168` (Rust) and
  `node scripts/calculate-golden-rtmr.mjs --selftest` (JS) — regenerate and
  update BOTH literals in the same commit when parser semantics change.
- **Host test env (NixOS)**: `cargo test` needs pkg-config + OpenSSL headers
  from the store or openssl-sys build fails:
  `export PATH=/nix/store/*pkg-config-wrapper*/bin:$PATH` and
  `PKG_CONFIG_PATH=/nix/store/*openssl-3*-dev/lib/pkgconfig`. (A disk-full
  incident truncated the cached build and surfaced this.)

### Cloudflare DNS-01 token is IP-pinned to the reserved EIP (proven live 2026-10-20)

The `dns01_secret` Cloudflare API token in the enclave config **only authorizes
API calls that egress from the reserved EIP** (`eip-2zet05jbat6wr6rp7elrc`,
101.200.178.251). From any other address — operator host, relay instance, or
an ECS instance using its auto-assigned public IP — Cloudflare returns
`Invalid API Token` (codes 1000/9109), which the enclave surfaces at boot as
`zone 'airma.de' not found for this API token` and then falls back to HTTP-01
(carrier-intercepted on mainland IPs ⇒ no TLS ever). Operational consequence
for any instance swap: the EIP must be moved **and** the instance must egress
through it *before* its first ACME attempt — release the auto public IP, bind
the EIP (recipes in the API-traps list above), then boot/reboot. The enclave
only orders ACME at boot, so a reboot after the EIP is in place is required.
The EIP also pins `login.airma.de` DNS (A record = the EIP), so moving it
moves all production traffic.

### Aliyun CLI Workflow (this branch's core tooling)

The provisioning stack depends on the official `aliyun` CLI, shipped as a locally built `.deb` (no apt repo, no GPG — the tarball is checksum-verified instead):

1. **Package** — `bash build-scripts/create-alien-deb.sh`
   - Downloads the official release tarball from `github.com/aliyun/aliyun-cli` (default `3.3.14`; `ALIYUN_CLI_VERSION=auto` resolves the latest tag, `ARCHITECTURE=arm64` for arm)
   - Verifies the asset against the release's `SHASUMS256.txt` (cached in `build-scripts/work/`) and **fails closed on mismatch**
   - Installs the ELF binary to `/opt/alibabacloud-cli/bin` plus `/etc/profile.d` PATH injection
   - Output: `build-scripts/packages/aliyun-cli-{VERSION}_{VERSION}-1_{ARCH}.deb` (override dir with `ALIYUN_DEB_OUT`)
   - Host tools required: `dpkg-deb curl sha256sum readelf file tar awk grep`
2. **Install** — `sudo dpkg -i build-scripts/packages/aliyun-cli-*.deb`
3. **Authenticate** — export `ALI_ACCESS_KEY_ID` + `ALI_ACCESS_KEY_SECRET`; `deploy-alibaba.sh` re-exports them as `ALIBABA_ACCESS_KEY_ID` / `ALIBABA_ACCESS_KEY_SECRET` (the CLI's native env names). `aliyun configure` also works.
4. **Build image** — `bash build-alibaba-docker.sh` → `initramfs-alibaba.img` (Debian Trixie, snapshot-pinned via `Dockerfile.alibaba`; apt package pins in `packages-alibaba.txt`, incl. `tpm2-tools 5.7-1`)
5. **Import image** — `bash import-alibaba-image.sh` (requires the aliyun CLI's built-in `oss` subcommand — **no ossutil** — plus `ALI_OSS_BUCKET`; uploads the ESP disk `output-alibaba/disk-alibaba.raw` to OSS, imports it via `ImportImage` using the flat `--DiskDeviceMapping.1.Format raw` flag — the CLI rejects `--DiskDeviceMapping.1.ImageFormat` — then polls the image `Status` until `Available` → yields `ALI_IMAGE_ID`; note `DescribeTasks` polling does NOT work with the current CLI: `--TaskId` is rejected and `--TaskIds '[...]'` returns an empty TaskSet)
6. **Deploy** — `bash deploy-alibaba.sh` (target `ecs.c9i.large` — cheapest TDX shape, live-verified 2026-10-23; `ALI_REGION=cn-beijing` default, spot strategy `SpotAsPriceGo` with `SpotDuration=0` (no protection period / no minimum time), `SecurityOptions.ConfidentialComputingMode=TDX`; enclave config delivered to `/etc/paypal-auth/config.json`)

The enclave image itself never contains the aliyun CLI — the CLI runs on the operator host; only the checksum-verified provisioning flow touches ECS.

---

## Cryptographic Chain of Trust

```
GitHub Provenance
    └─► PCR 15 (disk_manifest SHA-256 measured into TPM at boot)
            └─► PCR Composite Hash (SHA-256 of all quoted PCRs 0,4,8,9,15)
                    └─► TPMS_ATTEST binary (signed by Session AK over PCR composite + session nonce)
                            └─► Session Nonce (SEC-02 5-component: SHA-256 over
                                     │        [paypal_hash ∥ pubkey_SPKI_hash ∥ custom_info_hash
                                     │         ∥ binary_sha256 ∥ canonical-manifest_hash] — 160 bytes)
                                     │                │
                                     │                └── inputs: enclave pubkey SPKI DER, custom_info
                                     │                     ("NONE" if absent/empty), binary_sha256 (/init),
                                     │                     SHA-256 of sorted [path, sha256] manifest JSON
                                     └── PayPal OAuth userinfo JSON (compact sorted)

Google EK Certificate (NVRAM 0x01c00002)
    └─► Issued by: Google LLC / EK/AK CA Intermediate
            └─► Proves: this TPM is inside a real GCP Confidential VM (AMD SEV-SNP)
                    └─► Verified by: auditor checking Google CA issuer chain
```

Note: The EK Certificate and the TPM Quote signing key (Session AK) are separate keys. This is the **correct** TPM 2.0 attestation model.

---

## Unified Synthesis Pipeline (Reproducible Build System)

To ensure 100% bitwise reproducibility regardless of host environment, the project uses a multi-stage Docker synthesis engine (`Dockerfile.repro`):

1. **Phase 0: EAB Rotation**: Deployment script rotates ACME credentials before build
2. **Stage 1 — Rust Builder**: Compiles `paypal-auth-vm` for `x86_64-unknown-linux-gnu` using stable Rust toolchains on Debian Trixie
3. **Stage 2 — Image Builder**: Uses fixed Debian snapshot to bundle kernel, bootloaders, and initramfs
4. **Verification Stage**: Compares local synthesis hashes against the GitHub provenance ledger
5. **Aliyun CLI Packaging Stage**: Downloads official release tarball, verifies sha256, builds .deb

### ⚠️ Only the Docker pipeline build is the ATTESTED build (2026-10-23)

A plain **host build** (`cargo build --release`, e.g.
under Nix) is **not** bit-identical to the Docker/CI pipeline build — different
rustc/sysroot, different binary digest. Observed live for identical source:
host build `9ef6b729…` vs Docker/CI build `ba1a3bfe…`.

Consequences (each one bit us):

- GitHub attestations only ever cover **pipeline** digests, so a host-built
  binary can never resolve in `verify.html`'s provenance row —
  `githubCheck` stays red against the real API no matter how correct the code
  is. Deploy only Docker-built disks.
- `EXPECTED_ENCLAVE_SHA256` in `verify.html` tracks the **Docker/CI** binary
  digest, never a host-build digest.
- `bash build-alibaba-docker.sh` (rootless podman works) reproduces CI
  bit-for-bit from the same commit — that is the only supported way to obtain
  locally the exact bytes CI attests. `verify.html` is deliberately NOT
  embedded in the binary or the initramfs (no `include_str!`), so auditor/pin
  edits never perturb the measured boot chain or the attested binary digest.

### Single Build Target — Alibaba Cloud Intel TDX (v180, unconditional)

| Target Platform | Attestation Root | Network Driver |
|---|---|---|
| Alibaba ECS `ecs.c9i.large` (cn-beijing-i) | Intel TDX quote (PCK chain → Intel SGX/TDX Root CA) | virtio_net |

The `alibabacloud` cargo feature was **removed** in v180 (audit.md §3.1):
Intel TDX is compiled unconditionally, and the GCP (AMD SEV-SNP / vTPM) and
Oracle paths are permanently deleted from the source, the CI workflow and the
initramfs module list. Build command:
```bash
cargo build --release --target x86_64-unknown-linux-gnu
```

The former GCP/AMD material (dual-build matrix, `google_ca.pem`, GCP
metadata IP in nftables, `Dockerfile.repro`, GCP scripts/docs) is gone from
this branch; recover it from the `oraclecloud` archive branch only.

---

## Security Architecture

### Hardware-Anchored Trust Layer

#### Legacy GCP (AMD SEV-SNP) Path — REMOVED in v180
Kept here only as context for auditing OLD saved reports; the enclave and the
auditor no longer accept this evidence class (Intel-TDX-only gate).
- **Google EK Certificate** (NVRAM `0x01c00002`): DER X.509 cert issued by `EK/AK CA Intermediate` under Google's CA chain. Proves instance runs on real GCP Confidential VM silicon.
- **Session Signing AK**: Created fresh per-attestation via `tpm2_createprimary`. Signs TPM Quote containing PCR values + session nonce. Never reused.
- **Measured Boot**: PCRs 0, 4, 8, 9, 15 provide full-stack coverage verified by TPM quote.
- **Embedded TLS Pinning**: `paypal.pem` is compiled directly into the binary via `include_bytes!`, preventing filesystem-level tampering. **v179 fix (live-proven)**: `paypal.pem` was never a root — it was an EXPIRED LEAF (`CN=api-m.paypal.com`, notAfter 2026-09-13) that only *appeared* to pin while the rustls default roots were still trusted. Since plan Phase 2 disables system roots in `hardened_client()`, the pin must be the endpoint's real anchor: **DigiCert Global Root G2** (`cb3ccbb7…ab1cb5f`, fingerprint pinned by test `paypal_api_root_is_digicert_g2_v179`). Both `api-m.paypal.com` and `api-m.sandbox.paypal.com` chain to it (2026-10-23).

#### Alibaba Cloud (Intel TDX / AMD Rome) Path
- **Platform Certificate Key (PCK)**: Retrieved from Intel Online Certification Service (OCS) OR TPM NV endorsement hierarchy
- **Standard TPM 2.0**: Uses regular `tpm2` command suite without `/dev/sev-guest` dependency
- **Dynamic feature-flagged loader**: Conditional `insmod` / `modprobe` calls based on `alibabacloud` cfg attribute at compile time

### Resource Isolation
- Connection dropping and bandwidth throttling at entry points protect native Rust state (25 MB/hour per-IP limit, 512 MB/hour global limit)
- PID 1 isolation: no shell, no userspace utilities except specifically whitelisted binaries
- HTTP request concurrency capped at 50 concurrent active connections

### Network Enforcement

#### Native DHCP (PID 1)
Bootstraps networking in environments with zero OS-level init. Constructs raw BOOTP frames via `socket2` and processes DHCPOFFER/DHCPACK responses directly from UDP byte buffers, bypassing `dhclient` and `udhcpc`. Critical fix: pins socket device via `SO_BINDTODEVICE` before binding port 68, enabling broadcast UDP on unconfigured NICs.

#### nftables Egress Firewall
Loaded during `enclave_init` to enforce strict output traffic rules: only ports 53 (DNS/TCP+UDP), 80, 443 allowed on configured interfaces. Loopback always permitted. Default DROP on INPUT, FORWARD, OUTPUT chains. Only established/related inbound connections accepted.

#### DNS egress hardening
Production hardened client locks specific domains (`api-m.paypal.com`, `api-m.sandbox.paypal.com`) to known IPs via `reqwest::Client::builder().resolve(...)`, eliminating reliance on whatever nameserver config the cloud provider hands out.

#### Symmetrical Fallbacks
Both PayPal credential configurations include hardcoded defaults if Secret Manager is unreachable, preventing dead-starts while maintaining auth enforcement at token exchange step.

---

## Verification Workflow (Auditor Flow)

The system presents a signed **Remote Attestation Report** on the OAuth callback page after successful user login:

1. **Local air-gap verification**: Users download the JSON report and `verify.html` for deterministic offline auditing — eliminates web-vector trust completely
2. **GitHub Sigstore provenance**: Automatically fetches and verifies atomic run metadata across all components (binary, kernel, initramfs, bootloader)
3. **Silicon Audit**: Reads `google_ak_cert_pem` from report body and confirms:
   - Issuer chain contains `EK/AK CA Intermediate` or `Google Cloud Confidential Computing OS Root CA`
   - Encoded subject identity displays correctly (instance, zone, project)
   - Does **not** compare EK cert public key to session AK public key
4. **Disk Manifest Audit**: Live SHA-256 of every file mounted under `boot/efi` compared against signed CI baseline. Verifies expected PCR 15 extension value against hardware state.
5. **TPM Quote Validity Proof**: Binary-parses `TPMS_ATTEST` structure from `tpe_quote_msg` field (magic `0xFF544347`, type `0x8018`) to extract `extraData` (the combined nonce) and `pcrDigest`. Verifies session AK RSA-2048 signature over raw quote message through WebCrypto API.

---

## End-to-End Debugging Playbook

How to debug this system end-to-end when a login, audit or deploy misbehaves —
the order that finds bugs fastest (validated live 2026-10-23).

### 1. Static checks first (minutes, before any live system)
- `node scripts/test-verify-security.mjs` must be 0-failed;
  `REAL_REPORT=<envelope.json> node scripts/test-verify-security.mjs` adds
  Test 22 against a real captured report. Test 28 (README digest) is the
  canary for "you edited verify.html and forgot to republish".
- `cargo test --release --target x86_64-unknown-linux-gnu`
  (on NixOS the host build needs `PKG_CONFIG_PATH` pointing at a nix-store
  `openssl.pc`).

### 2. Capture live evidence (no browser needed)
- `curl -sk https://<enclave>/debug/envelope > envelope.json` — the full
  attestation envelope. Extract/rotate pins with
  `node scripts/calculate-golden-rtmr.mjs --report envelope.json` (`--update`
  rewrites verify.html deliberately).
- The OSS self-report sink (`boot/<env>/latest.json`) still carries boot-stage
  markers when TLS/ACME is down — the lifeline for dark instances.
- ECS calls are hand-signed (HMAC-SHA1 RPC). `InvalidSecurityToken.Expired`
  ⇒ run `aliyun sts GetCallerIdentity` once to refresh. The live API traps
  (flat `Features.NvmeSupport`, `Format` not `ImageFormat`, capital-D
  `InstanceIdSet`) are listed in the Alibaba section above.

### 3. Browser end-to-end — the only way to test login/handoff/download
- Playwright + `CHROMIUM_PATH=<nix chromium>` on NixOS (the bundled playwright
  chromium dies on missing distro libs, e.g. libglib).
- Load `file:///<repo>/verify.html` — never the enclave-served copy (key
  generation is refused there by design). Fill `#localEnclaveHost`
  (`https://<enclave>`), click **Log in with PayPal (Verified account only)**,
  drive the PayPal sandbox popup (test user `sb-fuobx47090577@personal.example.com`),
  land on `/callback`, then press **2. Claim Encrypted Report** on the local
  page. Success = the ✅ status line AND a `download` event carrying
  `attestation-report-*.json`.
- `scripts/e2e-login-download.mjs` automates exactly this (preflight → popup
  → consent → claim → download assertion, exits non-zero if the file never
  arrives, saves the claimed report to /tmp for gate triage);
  `scripts/e2e-sandbox.mjs` is the report-capture variant.
- Triage rule: the download is suppressed whenever ANY audit row is red —
  find the first ❌ / the thrown error in the browser console rather than
  suspecting the download logic. (That is how the v178 IDENTITY PREIMAGE bug
  was found: the download worked, the audit gate failed.)

### 4. Deploy loop for boot-chain changes
1. `bash build-alibaba-docker.sh` (rootless podman works) — the only build CI
   attests. Compare its digests with the CI run's annotations AND the
   attestation lookups (`api.github.com/repos/<o>/<r>/attestations/sha256:<hex>`)
   before deploying anything.
2. Presigned PUT to the HK bucket → relay `user_data` transfer (HK GET →
   Beijing intranet PUT; success powers the relay OFF) → `ImportImage`
   (`BootMode=UEFI`, flat `DiskDeviceMapping.1.Format=raw`) →
   `Features.NvmeSupport=supported` → Stop/`ReplaceSystemDisk`/Start on the
   enclave instance (the user_data config survives).
3. Capture `/debug/envelope` after boot, rotate pins from that capture,
   republish the README digest, roll `verify.html` onto the ESP (mtools on the
   extracted FAT partition). Then run
   `node scripts/check-manifest-parity.mjs https://<enclave> <deployed-disk>.raw`
   — the report's self-reported `disk_manifest` must match the deployed ESP
   byte-for-byte (NvVars excluded: the firmware rewrites it every boot).
   `verify.html` is in neither the binary nor the
   initrd and lives on the UNMEASURED ESP — editing it never moves RTMR2, so
   pin edits never feed a re-rotation loop.

## Known Constraints & Notes

- **EK Certificate ≠ Session AK** (by design): Never compare them during any verification pass. This mismatch is expected.
- **No persistent AK handles on GCP**: `tpm2 getcap handles-persistent` always returns empty on GCP Confidential VMs — the enclave creates a session signing AK via `tpm2_createprimary` each boot.
- **NVRAM buffer must be unbounded**: `tpm2 nvread -s <size>` truncates large certs. Always use `tpm2 nvread` without a size argument to retrieve the complete 1560-byte EC certificate blob.
- **Nonce binding formula (SEC-02 / verify.html v160 — the 5-component form)**: `nonce = SHA-256` over the 160-byte concatenation `[0..32] sha256(compact sorted PayPal userinfo JSON)` ∥ `[32..64] sha256(enclave signing pubkey SPKI DER)` ∥ `[64..96] sha256(custom_info string — `"NONE"` when absent or empty)` ∥ `[96..128] boot_measurements.binary_sha256 (self-measure of /init)` ∥ `[128..160] sha256(canonical compact JSON of sorted [path, sha256] disk-manifest pairs)`. The TPM quote's `extraData` and the TDX quote's `report_data[0..32]` MUST contain exactly this 32-byte digest or the entire attestation fails validation. (The old 2-component formula — `SHA-256(SHA-256(user JSON) ∥ SHA-256(key DER))` — was pre-SEC-02 and produced `binding=false` against every current verify.html build; the enclave was fixed 2026-10-19.)
- **Pre-flight REPORTDATA binding (v168 — 6-component form)**: `report_data[0..32] = SHA-256` over `P_enc SPKI DER ∥ code_challenge ∥ P_client SPKI DER ∥ client_nonce ∥ custom_info ("NONE" when absent) ∥ PayPal_Client_ID`, `[32..64]` zero. The PayPal APP id is the SIXTH element (plan Phase 3.1) so an over-scoped app swap changes the hardware-quoted bytes; verify.html enforces `EXPECTED_APPS` against the signed fields AND the report's `paypal_client_id` (login reports), both fail-closed. Mirrors: `compute_preflight_binding()` (Rust) ↔ `preflightBindingHex()` (verify.html) ↔ `security_tests::preflight_binding_parity_v168` + harness Test 6c — **update all four together**. (The callback/login report keeps the SEC-02 5-component nonce above — unchanged.)
- **`tpm2` standalone binary vs wrapper**: In the minimal initramfs filesystem, the unified `tpm2` binary should always be invoked directly — wrapper aliases like `tpm2_getcap` often don't exist, causing silent failures. Use pattern `tpm2 getcap` instead of `tpm2-getcap`.
- **DHCP timeout**: NATIVE implementation waits up to 30 seconds for DHCPAC before rejecting. If the cloud metadata service is slow responding, increase the socket timeout in PID-1 init (currently set to 30 seconds in the socket setup path).
- **PCIe slot exhaustion**: Each module loaded via `insmod` occupies PCI space on bare-metal virtualized infrastructures; batch loads where possible in `insmod_all()` function.
- **ACME DNS-01 is bound to the reserved EIP** (Cloudflare token IP
  restriction) — no reserved IP on the VM ⇒ `Cloudflare zone not found`,
  forever. See "ACME DNS-01 ONLY works from the reserved EIP".
- **"Running + dark" ≠ wedged host** — fail-closed halts sleep forever by
  design and the ACME retry loop serves nothing; diagnose via the ESP
  `boot-probe.log` transcript, not the (frozen, 64 KiB) serial console.
- **Mainland OSS buckets are write-only from the operator host** — presigned
  or not, `GetObject` is refused; only the **Hong Kong** relay bucket
  (`paypal-tdx-relay-1792227992`) is readable. Send guest evidence there.
- **Serial console is wiped when the instance stops**, so a `user_data` script
  that powers off before printing its result destroys the result. Print, then
  hold the instance in `Running`; only power off for a pure pass/fail signal.

---

## Security Audit Status (2026-10-20)

- **Round 1 complete & deployed**: independent audit under the threat model
  *the cloud provider and the owner of login.airma.de are untrusted and may
  collude* — fixes in `6a99f0e` (enclave OAuth: CSRF cookie + PKCE binding on
  `state = <flow>.<nonce>`; verify.html: MRTD/RTMR pins, app pins
  (full=`ARDDr…` / verified=`AZXkz…`), code/preflight pins, boot-chain
  provenance for shim/grub; CI: attests shim+grub and gates on the 83-test
  harness). CI run 283 green; attestations resolve unauthenticated via
  `api.github.com/repos/<o>/<r>/attestations/sha256:<hex>`; local disk
  `00963ad5…`, binary `ebe9fa31…`, initrd `ab97b8ed…` are byte-identical to
  CI's attested digests.
- **Live deployment (historical — ids below are GONE)**: Round 1 ran on
  `i-2ze0sd65q6qhot55aerq` with rollback `i-2zefwa6bdimeg1rbcfsg`; both were
  replaced and calls against them now return `InvalidParameter "The
  instanceId provided is not valid"`. Round-1 **E2E passed live** on both
  flows (CSRF cookie + PKCE against real PayPal), live harness 90/90,
  console-PII 0 — details in HANDOVER.md §3.
- **Actual instance inventory (cn-beijing, 2026-10-23 00:05Z)** — always
  re-verify with `DescribeInstances` before acting:
  | InstanceId | Name | Image | EIP | Status |
  |---|---|---|---|---|
  | `i-2ze686o40uawcau9vt9v` | paypal-auth-vm-1g | `m-2zed3wq8aubcqq0nofx2` | **101.200.178.251** | Running, ports 80/443 **closed** |
  | `i-2ze7b9txw6v7c7gtrqwt` | paypal-auth-vm-2 | `m-2zei3anvjitmgflr61kj` | — | Running, no EIP (cannot obtain a cert) |
  | `i-2ze19752fjlhw6rf4mpl` | oss-relay-tmp2 | `m-2zeaptkfw533l239al3z` | — | Stopped (economic) |
- **State of play + remaining task list live in `HANDOVER.md`** (repo root) —
  read it before continuing the audit cycle.

## Security Audit Status — Round 2 (2026-10-22, v168)

Independent end-to-end audit against the pasted audit plan
(*Hardware Verification of Running Code — Intel TDX on Alibaba Cloud*), same
threat model (cloud provider + owner of `login.airma.de` untrusted, may
collude). What changed:

1. **Self-measurement fallacy closed (plan 1.2)** — `boot.binary_sha256` is
   computed by the binary under suspicion, so it no longer decides pass/fail.
   The verdict is now decided EXCLUSIVELY by the silicon gates (`EXPECTED_MRTD`
   + `EXPECTED_RTMR0..3` over the Intel-signed quote). The digest stays as a
   LOUD informational warning (staleness/consistency signal) — see the
   `EXPECTED_ENCLAVE_SHA256` comment in verify.html. Harness Test 21d asserts
   the new semantics.
2. **Auditor isolation (plan 3.3)** — key generation / login / decryption run
   ONLY in a trusted auditor context (`file://` copy or the pinned GitHub Pages
   copy). The copy served by the enclave's own origin REFUSES all
   key-generating flows (Web Auditor Tampering: the owner can rewrite that
   script at will); paste-report auditing still works there. Harness Test 24.
3. **Malicious-App defense (plan 3.1)** — PayPal client id is hardware-bound
   into pre-flight `REPORTDATA` (6-component formula above) and carried in the
   signed login report (`paypal_client_id`); `EXPECTED_APPS` gates both,
   fail-closed. Harness Test 21g + 6c.
4. **Fail-closed report minting (plan 2.2)** — no silicon-signed TD Quote →
   the enclave returns **HTTP 503** and never emits a report
   (`unavailable_no_guest_device` reports are impossible on alibabacloud
   builds). The v165 boot probe still halts the box before serving if the
   platform cannot attest at all.
5. **Post-boot egress lockdown (plan 4.1)** — after config + ACME complete,
   `enclave_init::egress_lockdown()` flushes the output chain and allows ONLY
   loopback + established + `443 → {104.16.124.74, 146.75.123.1}` (the
   `hardened_client()` PayPal pins). IMDS `100.100.100.200`, GCP metadata,
   DNS and port 80 are dropped — they are boot-only needs (user_data, DNS-01
   ACME, HTTPS time sync) and afterwards pure exfil surface. If per-request
   quote generation ever proves to need the Alibaba PCCS endpoint, allow
   THAT IP explicitly (resolved before lockdown) — never re-open DNS/:80.
6. **Kernel hardening (plan 4.2)** — `harden_kernel()`: `swapoff` everything
   (TDX encrypts RAM, NOT swap — swapped pages would hit the host disk in
   plaintext; fail-closed if swap survives), `kexec_load_disabled=1` (an
   unmeasured kernel must never load past the RTMR pins), `suid_dumpable=0`.
7. **Cmdline injection gate (plan 1.1)** — `enclave_init::verify_cmdline()`
   halts unless `/proc/cmdline` equals `EXPECTED_CMDLINE` (pinned constant,
   drift-guarded against build-alibaba-image.sh by
   `cmdline_pin_matches_build_script`).   the grub.cfg string itself is already
   deterministic + SOURCE_DATE_EPOCH-pinned; the RTMR pins cover the measured
   boot chain remotely.
8. **Golden-RTMR tooling (plan 5)** — `scripts/calculate-golden-rtmr.mjs`:
   offline CCEL replay (byte-compatible with `intel_tdx::replay_ccel`, with a
   per-event coverage breakdown), pin extraction from live quotes
   (`--report`), log↔quote cross-check, and `--update` pin rotation for
   verify.html. `--selftest` shares one golden vector with
   `security_tests::ccel_replay_selftest_v168` (Rust ↔ JS replay parity).

Tests: harness **115 checks** (was 99) + Rust **6** incl. three
cross-implementation parity vectors. Rotation procedure for boot-chain
changes: rebuild → in-place disk rewrite (Instance & Disk Policy) →
`node scripts/calculate-golden-rtmr.mjs --report <live /debug/envelope> --update`
→ commit verify.html in the same reviewed commit.

## Security Audit Status — Round 3 (2026-10-23, v169)

Third independent pass over the live report + `verify.html` flow, same threat
model (cloud provider + owner of `login.airma.de` collude; the Intel TDX
silicon and the pinned trust anchors — Intel root CA, AMD ARKs, golden
MRTD/RTMR — are honest). Baseline before the pass: harness 115/115, Rust 6
tests. Everything below is fixed and covered by a regression test.

**Fixed (each with a regression test)**

1. **IDENTITY PREIMAGE BINDING (critical).** `verify.html` built the hardware
   nonce from the report's *self-asserted* `paypal_user_info_raw_hash` and
   never hashed the identity it displayed. A quote could attest hash H while
   the envelope showed a DIFFERENT user's record — and because the pinned
   RTMRs cover code+disk but NOT the IMDS config that drives behaviour, this
   was reachable without touching a measured byte. The auditor now recomputes
   `SHA-256(JSON.stringify(paypal_user_info))` and fails closed on mismatch;
   envelopes with no identity MUST carry the `PRELOGIN_NO_USER` placeholder
   hash. Parity is pinned on both sides by
   `security_tests::paypal_identity_json_layout_pinned` +
   `prelogin_placeholder_hash_pinned` (Rust) and harness Test 26.
2. **SANDBOX ENVIRONMENT BINDING (high).** A sandbox login is a *genuine*
   hardware attestation of a **synthetic** identity — `verified_account:true`
   there belongs to any account the owner creates. Every pin could be green
   while the "verified PayPal user" on screen was the operator's own. The
   signed reports now carry `paypal_environment` (`production`/`sandbox`, also
   in the pre-flight signed fields), and the auditor refuses anything that is
   not `production`, including an undeclared (pre-v169) value. Test 27.
3. **UNVERIFIED-ACCOUNT CHECK (medium).** The page displayed a "verified"
   identity without checking `paypal_user_info.verified_account === "true"`
   (the enclave enforced it server-side only). Now checked in the signed
   report, fail-closed. Test 27.
4. **AUDITOR DEPENDENCY INTEGRITY (high).** `verify.html` loaded node-forge
   from cdnjs with **no SRI**; forge parses the X.509 chains that anchor both
   TDX and AMD trust, so a substituted build could make `x509SignedBy()`
   accept anything. The tag is now `integrity="sha384-…"` +
   `crossorigin="anonymous"`, pinned to the exact bytes the harness evaluates
   (drift-guarded in Test 1), and the page fails closed with an actionable
   alert when forge is absent instead of silently skipping chain checks.
5. **RESPONSE HARDENING (medium).** All attestation/session responses now send
   `Cache-Control: no-store`, `Referrer-Policy: no-referrer`,
   `X-Content-Type-Options: nosniff`; HTML responses add
   `Content-Security-Policy: frame-ancestors 'none'` (clickjacking). The
   callback URL carries a one-time PayPal grant and the sealed report — it
   must never be cached or leak through `Referer`.
6. **BOUNDED SESSION TABLES (low).** `pending_oauth` and
   `pending_e2ee_blobs` are capped (`MAX_PENDING_OAUTH` /
   `MAX_PENDING_E2EE_BLOBS`, 4096 each) with TTL eviction instead of
   unbounded growth from an unauthenticated caller.

**Deliberately NOT changed (justified, not overlooked)**

- **The provenance row stays advisory, never a gate.** Every digest it checks
  (`binary_sha256`, `disk_manifest`) is *self-reported* by the enclave, so
  gating on it would resurrect exactly the self-measurement fallacy v168
  removed; a hard gate would also brick air-gapped audits whenever GitHub is
  unreachable. Code identity is decided only by the MRTD/RTMR silicon pins.
  (Comment in `verify.html` at the row.)
- **TLS-certificate binding stays advisory.** It only runs when the user
  pastes a certificate, and it cannot be security-relevant while the report
  itself is sealed to a client-generated ECDH key: a TLS-terminating owner
  sees ciphertext either way.
- **The static `/debug/envelope` pre-flight is a convenience, not the gate.**
  It has no client nonce (replayable), which is why the secure flow uses
  `POST /attest/preflight` with a fresh browser nonce; a replayed *login*
  report is impossible because it is encrypted to the fresh client key and
  pinned to the pre-flight `P_enc`.
- **`GET /e2ee-blob?state=…` is a bearer one-time token.** It returns only
  ciphertext whose key never leaves the browser; knowing `state` buys a DoS
  (claiming it first), not disclosure.
- **The auditor's own provenance cannot be fixed in-band.**
  `verify.html` is fetched from GitHub Pages / a saved file, and the owner
  controls that repository. **Mitigated, not eliminated**: `README.md` now
  publishes the auditor's SHA-256 **and byte size** in the "Verify the auditor
  itself first" table, and harness **Test 28** fails the suite if that value
  drifts from the file — so the digest can never silently go stale (a stale
  digest is worse than none: it teaches users to ignore mismatches).
  **Rotation rule: any commit touching `verify.html` MUST update the README
  digest/size in the same reviewed commit** (Test 28 enforces it). Users are
  still told to compare against a second independent source (release note,
  mirror, another checkout) — the README lives in the repository the threat
  model distrusts. The enclave-served copy refuses every key-generating flow,
  so a tampered ESP copy cannot steal keys.

**Deviations from the pasted plan (justified)**:
- Cmdline text: `quiet` omitted (it would hide the TDX probe transcript on the
  serial console — the project's primary diagnosis channel), `selinux=0`
  omitted (it disables MAC if ever enabled), `panic=1` omitted (no security
  gain — a panicked kernel serves nothing; rebooting only destroys evidence).
  The injection defense is determinism + `verify_cmdline()` + RTMR pins.
- UKI monolithic boot (plan.md repo variant) NOT adopted: live evidence
  (2026-10-21) shows GRUB 2.12's EFI CC measurement protocol extends
  kernel/initrd/cmdline into RTMR0–2 on this platform, and the pins enforce
  exactly those registers; `calculate-golden-rtmr.mjs --ccel` prints the
  per-event coverage to re-verify on demand.
- `verify.html` served from the unmeasured ESP stays (pins must not live in
  the measured initrd — self-reference), but it is now fenced by item 2.
