# AGENTS.md - Status Guidelines for PayPal Auth Confidential VM

## Branch Layout (updated 2026-10-16)

| Branch | Status | Contents |
|---|---|---|
| **`alibabacloud`** (default branch) | ✅ Active line of work | Alibaba Cloud / **aliyun CLI** stack: `Dockerfile.alibaba`, `build-alibaba{,-docker,-disk,-simple}.sh`, `deploy-alibaba.sh`, `import-alibaba-image.sh`, `build-scripts/create-alien-deb.sh` |
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
| **Alibaba Cloud** (ECS.r9i.xlarge) | Intel TDX / AMD Rome | PCK Certificate + Standard TPM | Custom provisioning stack |

Supported build target: **feature flag `alibabacloud`** (see `[features]` in `Cargo.toml`; default = GCP SEV-SNP).

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

- **Multi-Cloud Platform Support**: Dual-provider runtime — the single source tree supports seamless switching between GCP Confidential VMs (SEV-SNP) and Alibaba Cloud (`ecs.r9i.xlarge`) via the `--features alibabacloud` compile-time flag.
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

### Target Instance Type: ecs.c9i.xlarge (4 vCPU / 8 GiB, Intel TDX) in cn-beijing-i
- Live-proven 2026-10-16: spot `ecs.c9i.xlarge` (SpotAsPriceGo, no protection period) boots the ESP image end-to-end — DHCP, IMDS, `user_data` config load, NVMe ESP measurement (6 files), HTTP:80 + HTTPS:443, all green
- Cheapest TDX shape available: Beijing quotes **$0.024/h** spot vs $0.040/h for Hangzhou's minimum (Hangzhou only offers TDX on `r9i.xlarge` and up, i.e. 32 GiB). Everything (bucket, image, instance) must live in one region
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
Workaround used by `import-alibaba-image.sh`: push the bytes to a **same-region
ECS instance** and PUT them there over the **intranet** endpoint, addressed in
virtual-host style (`$BUCKET.oss-cn-beijing-internal.aliyuncs.com`, path-style
returns `SecondLevelDomainForbidden`). Verified: 46 MB in 0.5 s, ETag == local
MD5. A custom CNAME domain is the other sanctioned route.
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
6. **Deploy** — `bash deploy-alibaba.sh` (target `ecs.c9i.xlarge`, `ALI_REGION=cn-beijing` default, spot strategy `SpotAsPriceGo`, `SecurityOptions.ConfidentialComputingMode=TDX`; enclave config delivered to `/etc/paypal-auth/config.json`)

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

### Dual-Build Matrix

| Feature Flag | Target Platform | Attestation Root | Network Driver |
|---|---|---|---|
| *(none / default)* | GCP Confidential VM | Google EK Cert + Session AK | virtio_net / gve |
| `alibabacloud` | Alibaba ECS.r9i.xlarge | PCK Cert (Intel) or VCEK (AMD) | virtio_net / aliyun-net |

Build commands:
```bash
# GCP (default)
cargo build --release --target x86_64-unknown-linux-gnu

# Alibaba Cloud
cargo build --release --features alibabacloud --target x86_64-unknown-linux-gnu
```

---

## Security Architecture

### Hardware-Anchored Trust Layer

#### GCP (AMD SEV-SNP) Path
- **Google EK Certificate** (NVRAM `0x01c00002`): DER X.509 cert issued by `EK/AK CA Intermediate` under Google's CA chain. Proves instance runs on real GCP Confidential VM silicon.
- **Session Signing AK**: Created fresh per-attestation via `tpm2_createprimary`. Signs TPM Quote containing PCR values + session nonce. Never reused.
- **Measured Boot**: PCRs 0, 4, 8, 9, 15 provide full-stack coverage verified by TPM quote.
- **Embedded TLS Pinning**: `google_ca.pem` and `paypal.pem` compiled directly into binary via `include_bytes!`, preventing filesystem-level tampering.

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

## Known Constraints & Notes

- **EK Certificate ≠ Session AK** (by design): Never compare them during any verification pass. This mismatch is expected.
- **No persistent AK handles on GCP**: `tpm2 getcap handles-persistent` always returns empty on GCP Confidential VMs — the enclave creates a session signing AK via `tpm2_createprimary` each boot.
- **NVRAM buffer must be unbounded**: `tpm2 nvread -s <size>` truncates large certs. Always use `tpm2 nvread` without a size argument to retrieve the complete 1560-byte EC certificate blob.
- **Nonce binding formula (SEC-02 / verify.html v160 — the 5-component form)**: `nonce = SHA-256` over the 160-byte concatenation `[0..32] sha256(compact sorted PayPal userinfo JSON)` ∥ `[32..64] sha256(enclave signing pubkey SPKI DER)` ∥ `[64..96] sha256(custom_info string — `"NONE"` when absent or empty)` ∥ `[96..128] boot_measurements.binary_sha256 (self-measure of /init)` ∥ `[128..160] sha256(canonical compact JSON of sorted [path, sha256] disk-manifest pairs)`. The TPM quote's `extraData` and the TDX quote's `report_data[0..32]` MUST contain exactly this 32-byte digest or the entire attestation fails validation. (The old 2-component formula — `SHA-256(SHA-256(user JSON) ∥ SHA-256(key DER))` — was pre-SEC-02 and produced `binding=false` against every current verify.html build; the enclave was fixed 2026-10-19.)
- **`tpm2` standalone binary vs wrapper**: In the minimal initramfs filesystem, the unified `tpm2` binary should always be invoked directly — wrapper aliases like `tpm2_getcap` often don't exist, causing silent failures. Use pattern `tpm2 getcap` instead of `tpm2-getcap`.
- **DHCP timeout**: NATIVE implementation waits up to 30 seconds for DHCPAC before rejecting. If the cloud metadata service is slow responding, increase the socket timeout in PID-1 init (currently set to 30 seconds in the socket setup path).
- **PCIe slot exhaustion**: Each module loaded via `insmod` occupies PCI space on bare-metal virtualized infrastructures; batch loads where possible in `insmod_all()` function.

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
- **Live deployment**: new TDX instance `i-2ze0sd65q6qhot55aerq` holds the
  reserved EIP and serves TLS; old `i-2zefwa6bdimeg1rbcfsg` is the rollback
  (**Stopped** once live E2E went green; restart + re-attach EIP to roll
  back). Round-1 **E2E passed live** on both flows (CSRF cookie + PKCE
  against real PayPal), live harness 90/90, console-PII 0 — details in
  HANDOVER.md §3.
- **State of play + remaining task list live in `HANDOVER.md`** (repo root) —
  read it before continuing the audit cycle.
