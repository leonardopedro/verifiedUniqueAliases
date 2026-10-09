# AGENTS.md - Status Guidelines for PayPal Auth Confidential VM

## Project Overview

`paypal-auth-vm` (crate name: `paypal-auth-vm`) is a hardware-attested Rust service that provides a secure bridge for PayPal OAuth tokens across **multi-cloud confidential compute**:

| Cloud Provider | Architecture | Root-of-Trust | Key Driver |
|---|---|---|---|
| **GCP** (Confidential VM) | AMD SEV-SNP via vTPM | Google EK Cert + Session AK | Standard TPM 2.0 |
| **Oracle Cloud** (VM.Standard.E5.Flex) | AMD SEV-SNP (`/dev/sev-guest`) | VCEK (AMD KDS) + SNP report | Custom provisioning stack (OCI CLI) |

Supported build target: **feature flag `oci`** (see `[features]` in `Cargo.toml`; default = GCP SEV-SNP).

### Hardware Roots of Trust Compared

| Component | GCP AMD SEV-SNP | Oracle Cloud AMD SEV-SNP (E5/E6) |
|---|---|---|
| **Hardware Key** | Google-provisioned EK/AK (NVRAM) | VCEK from AMD KDS (per-chip, TCB-versioned) |
| **Key Source** | NVRAM index `0x01c00002` | AMD KDS `kdsintf.amd.com/vcek/v1/{family}/{chip_id}` |
| **Quote Mechanism** | TPM quote via `tpm2_quote` (session-bound) | SNP report via `/dev/sev-guest` ioctl (`SNP_GET_REPORT`), report_data = session nonce |
| `/dev/sev-guest` | **Not available** on GCP vTPM | **Primary root** (sev-guest driver); fallback ConfigFS TSM |
| ConfigFS TSM | Times out / unavailable | Optional fallback (PATH 3) |
| **TPM / vTPM** | Present (session AK, PCRs) | **Absent** — OCI has no vTPM; TPM evidence fields are empty by design |
| Persistent AK handle | `tpm2_getcap handles-persistent` → empty | N/A (no TPM) |
| Kernel module path | N/A (uses unified TPM path) | `sev_guest`, `amd_sev`, `amd_tsm`, `tsm`, virtio stack |

The project uses a **single codebase** with conditional compilation to support both platforms.

---

### 🏆 Current Accomplishments

- **Multi-Cloud Platform Support**: Dual-provider runtime — the single source tree supports seamless switching between GCP Confidential VMs (SEV-SNP) and Oracle Cloud (`VM.Standard.E5.Flex`) via the `--features oci` compile-time flag.
- **Correct GCP vTPM Attenuation Model** (v145): Resolved fundamental misunderstanding about two-key attestation. The enclave uses the correct model: Google EK Certificate (NVRAM `0x01c00002`, static silicon proof) is separate from the Session Signing AK (created fresh per-attestation via `tpm2_createprimary`, dynamic quote signer). Keys intentionally do not match.
- **Full EK Certificate Retrieval**: The 1560-byte Google EK/AK CA Certificate is retrieved from NVRAM index `0x01c00002` without truncation using unbounded `tpm2 nvread`. Systematic scanning across indices `0x01c00002`, `0x01c00001`, `0x01400001`, and more.
- **Hardened TPM Quote Verification**: Full binary parsing of `TPMS_ATTEST` in audit flow verifies the hardware-signed nonce from raw TPM quote message, neutralizing session replay and forgery attacks.
- **PCR 15 Software Binding**: Strict verification of `disk_manifest` hash against hardware PCR 15, ensuring running code matches GitHub provenance.
- **PCR Composite Digest**: Auditor manually reconstructs expected SHA-256 hash of all quoted PCRs (0, 4, 8, 9, 15) and verifies against signed `TPMS_ATTEST`.
- **Native DHCP Implementation**: Complete rewrite of network acquisition from shell scripts into pure Rust. Uses `socket2` with `SO_BINDTODEVICE` for reliable broadcast UDP on interfaces lacking IP bindings, including full BOOTP packet construction, lease parsing, and route application (with GCP-specific `/32` MTU handling).
- **Four-Path AMD Hardware Root Acquisition**: Automatic fallback strategy when acquiring SNP reports — PATH 0: native `/dev/sev-guest` ioctl (`SNP_GET_REPORT`, report_data = session nonce, OCI primary), PATH 1: NVRAM scan (systematic NV index discovery), PATH 2: TPM quote auxblob inspection, PATH 3: ConfigFS TSM interface. Includes automatic VCEK fetch from AMD Key Distribution Service (KDS) based on extracted chip ID with CPUID family-aware product naming (Milan/Genoa/Turin) and TCB layout selection (AMD KDS spec Tables 3/4).
- **OCI SEV-SNP Adapter** (`oci_snp.rs`): Replaces the retired Intel TDX module — sev-guest ioctl structs, CPUID family detection (`__cpuid(1)`), report parsing (report_data/chip_id/reported_tcb/signature at documented offsets), TCB byte-layout selection (Layout A vs B), AMD KDS VCEK/chain fetch, and OCI instance metadata access (`/opc/v2` with v1 fallback, `Authorization: Bearer Oracle`) including `user_data` config delivery.
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

## Oracle Cloud Platform Notes

### Target Instance Type: VM.Standard.E5.Flex (confidential)
- Processor: AMD EPYC Genoa (CPUID family 19h model 11h); E6 = Turin (family 1Ah)
- Confidential Computing enabled at launch via `platformConfig: {"type": "AMD_VM", "isMemoryEncryptionEnabled": true}` — SEV-SNP memory encryption (must be set at launch; cannot be toggled later)
- On-demand by default — OCI forbids preemptible capacity together with confidential computing (docs: "Confidential computing" is not available with preemptible instances); `OCI_PREEMPTIBLE=true` attempts spot and the script falls back to on-demand after the rejection ("not supported for VM preemptible")
- **SNP-only root of trust**: OCI provides **no vTPM and no TPM**. There is no Google-style EK cert and no PCR 15. The session is bound through the SNP report `report_data` field (first 32 bytes = session nonce), and the silicon root is the AMD VCEK certificate chain
- `/dev/sev-guest` is the primary hardware root (sev-guest driver); ConfigFS TSM is the fallback. Whether Debian's `linux-image-cloud-amd64` exposes `/dev/sev-guest` on OCI is runtime-unverified — verify at first boot and adjust module list if needed
- Supported OS list for confidential E5 includes Oracle Linux 9/10 and Ubuntu 24.04; **custom image launch on confidential shapes is runtime-unverified** — validate `import-oci-image.sh` + `deploy-oci.sh` end-to-end before relying on it

### OCI-Specific Delivery Mechanisms
- **Image import**: OCI accepts **QCOW2 only** (raw rejected). `build-oci-image.sh` produces a deterministic bootable QCOW2 (GPT + ESP with shim/grub/vmlinuz/initrd); `import-oci-image.sh` uploads to Object Storage and imports via `oci compute image import from-object --source-image-type QCOW2 --launch-mode PARAVIRTUALIZED`, polling the image until AVAILABLE
- **Config delivery**: `deploy-oci.sh` injects the enclave **config JSON directly as instance `user_data`** (base64-encoded by the OCI CLI). The enclave reads it from `http://169.254.169.254/opc/v2/instance/metadata/user_data` (IMDSv2 with `Authorization: Bearer Oracle`, v1 fallback) — **no cloud-init, no bash user-data**. Path is `instance/metadata/user_data`, NOT `virtualDevices/instance/user_data`
- **Instance metadata**: used for boot preview logging (`instance/`) and `user_data`; region/AD discovery and all provisioning go through the operator's `oci` CLI (pre-installed, no deb packaging — the old aliyun CLI packaging stack was deleted with the Alibaba target)

---

## Cryptographic Chain of Trust

```
GitHub Provenance
    └─► PCR 15 (disk_manifest SHA-256 measured into TPM at boot)
            └─► PCR Composite Hash (SHA-256 of all quoted PCRs 0,4,8,9,15)
                    └─► TPMS_ATTEST binary (signed by Session AK over PCR composite + session nonce)
                            └─► Session Nonce (SHA-256[PayPal User Hash ∥ Enclave PubKey Hash])
                                     │                │
                                     │                └── Enclave Asymmetric RSA signing key DER
                                     └── PayPal OAuth userinfo JSON (compact sorted)

Google EK Certificate (NVRAM 0x01c00002)
    └─► Issued by: Google LLC / EK/AK CA Intermediate
            └─► Proves: this TPM is inside a real GCP Confidential VM (AMD SEV-SNP)
                    └─► Verified by: auditor checking Google CA issuer chain
```

Note: The EK Certificate and the TPM Quote signing key (Session AK) are separate keys. This is the **correct** TPM 2.0 attestation model.

### OCI (TPM-less) Chain of Trust

```
GitHub Provenance ──► disk_manifest SHA-256 (measured at boot; no PCR 15 — bound via report instead)
Session Nonce (SHA-256[paypal hash ∥ SHA-256(enclave pubkey DER)])
    └─► SNP report_data[0..32] = raw 32-byte nonce (rest zero)   ← binds report to THIS session
AMD VCEK (from kdsintf.amd.com, TCB-versioned by bl/tee/snp/ucode SPLs)
    └─► ECDSA P-384/SHA-384 signature over SNP report bytes [0..672)
            └─► VCEK → ASK → ARK chain (ARK pinned by SHA-256 of raw DER in verify.html)
                    └─► ARK pin set: Genoa / Turin / Milan (KDS) — family selected by CPUID
```

---

## Unified Synthesis Pipeline (Reproducible Build System)

To ensure 100% bitwise reproducibility regardless of host environment, the project uses a multi-stage Docker synthesis engine (`Dockerfile.repro`):

1. **Phase 0: EAB Rotation**: Deployment script rotates ACME credentials before build
2. **Stage 1 — Rust Builder**: Compiles `paypal-auth-vm` for `x86_64-unknown-linux-gnu` using stable Rust toolchains on Debian Trixie
3. **Stage 2 — Image Builder**: Uses fixed Debian snapshot to bundle kernel, bootloaders, and initramfs
4. **Verification Stage**: Compares local synthesis hashes against the GitHub provenance ledger
5. **OCI Image Stage** (`Dockerfile.oci` / `build-oci-image.sh`): Assembles the deterministic GPT+ESP disk and converts it to QCOW2 for OCI image import

### Dual-Build Matrix

| Feature Flag | Target Platform | Attestation Root | Network Driver |
|---|---|---|---|
| *(none / default)* | GCP Confidential VM | Google EK Cert + Session AK | virtio_net / gve |
| `oci` | Oracle Cloud VM.Standard.E5.Flex | VCEK (AMD KDS) + SNP report | virtio_net / virtio_blk |

Build commands:
```bash
# GCP (default)
cargo build --release --target x86_64-unknown-linux-gnu

# Oracle Cloud
cargo build --release --features oci --target x86_64-unknown-linux-gnu

# Full reproducible OCI image (binary + initramfs + QCOW2), uses docker or rootless podman
bash build-oci-docker.sh
```

### OCI Image Build Details (OL10 / UEK8)

The deliverable is a **bootable QCOW2 VM image** — the container is only a build sandbox. Rootless podman works (no root/docker daemon needed; needs `/etc/subuid`+`/etc/subgid` entries, setuid `newuidmap`/`newgidmap`, `~/.config/containers/policy.json` with `insecureAcceptAnything`, and `registries.conf` with `unqualified-search-registries=["docker.io"]` for the short-name `debian@sha256:…` ref).

1. **`ol10-builder` stage** (`FROM oraclelinux:10@sha256:…` digest-pinned): `extract-ol10-binaries.sh` dnf-installs pinned NEVRAs (`kernel-uek-* 6.12.0-207.111.5.1.el10uek` from a written UEKR8 repo, `shim-x64`, `grub2-efi-x64`, `--setopt=tsflags=noscripts`), stages `ol10/{vmlinuz,modules/<ver>,BOOTX64.EFI,grubx64.efi,VERSIONS.txt}` with a sha256 manifest
2. **rust-builder stage**: Debian + pinned `RUST_VERSION`, builds `--features oci` for `x86_64-unknown-linux-gnu`
3. **initramfs** (`build-initramfs-tools.sh` OL10 branch): self-assembled staging (skips Debian `mkinitramfs`), curated `MODULES_OVERRIDE` injection with **dependency closure** — boot-proven required sets: `virtio_pci`→`virtio_pci_modern_dev`+`virtio_pci_legacy_dev`, `virtio_net`→`net_failover`→`failover`, `sr_mod`→`cdrom`, `sev_guest`→`tsm`, `sev_guest` probe crypto prereqs `gcm`+`ghash_generic`→`gf128mul` (probe runs `crypto_alloc_aead("gcm(aes)")`; missing gcm/ghash ⇒ `-EIO`, no `/dev/sev-guest`), `nvme`→`nvme-core`→`nvme-auth`+`nvme-keyring`, `nft_ct`→`nf_conntrack`; `modules.builtin*`/`modules.order` must be copied into staging or depmod warns and builtin lookups fail
4. **`build-oci-image.sh`**: deterministic GPT+ESP → QCOW2. Kernel cmdline uses `mem_encryption=on` only — `sev=on` is invalid for this kernel

Reproducibility (proven repeatedly): `podman build` vs `podman build --no-cache` → bitwise-identical qcow2/initramfs/grub.cfg. QE smoke test: `qemu-system-x86_64 -machine q35 -enable-kvm -m 2048` + OVMF pflash pair (`OVMF.fd` → `FV/{OVMF_CODE.fd,OVMF_VARS.fd}`, copy VARS to a writable file and `chmod 644` — nix store files are read-only) + virtio-blk qcow2 + user-mode net. Expected in qemu: all modules load, DHCP handshake completes, then the config fetch fails (no OCI IMDS in qemu) → `panic=1` reboot loop.

---

## Security Architecture

### Hardware-Anchored Trust Layer

#### GCP (AMD SEV-SNP) Path
- **Google EK Certificate** (NVRAM `0x01c00002`): DER X.509 cert issued by `EK/AK CA Intermediate` under Google's CA chain. Proves instance runs on real GCP Confidential VM silicon.
- **Session Signing AK**: Created fresh per-attestation via `tpm2_createprimary`. Signs TPM Quote containing PCR values + session nonce. Never reused.
- **Measured Boot**: PCRs 0, 4, 8, 9, 15 provide full-stack coverage verified by TPM quote.
- **Embedded TLS Pinning**: `google_ca.pem` and `paypal.pem` compiled directly into binary via `include_bytes!`, preventing filesystem-level tampering.

#### Oracle Cloud (AMD SEV-SNP) Path
- **SNP Report** (`/dev/sev-guest`, `SNP_GET_REPORT` ioctl): `report_data[0..32]` carries the raw session nonce; signed by the chip's report key
- **AMD VCEK**: Fetched from `kdsintf.amd.com` using chip_id + TCB SPLs (bl/tee/snp/ucode byte positions depend on TCB layout A vs B); ASK/ARK chain pinned by SHA-256 in `verify.html`
- **No TPM**: `quote()` skips all TPM operations when `/dev/tpmrm0`/`/dev/tpm0` are absent (GCP behavior unchanged when a TPM exists); `ak_pub_pem`, `tpm_quote_msg`, `pcr_values` serialize empty
- **Dynamic feature-flagged loader**: Conditional `insmod` / `modprobe` calls based on `oci` cfg attribute at compile time (AMD sev modules, virtio stack)

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
4. **Disk Manifest Audit**: Live SHA-256 of every file mounted under `boot/efi` compared against signed CI baseline. Verifies expected PCR 15 extension value against hardware state — **PCR 15 check only runs when the report contains TPM evidence** (GCP); TPM-less OCI reports skip it (GitHub provenance checks still apply)
5. **TPM Quote Validity Proof**: Binary-parses `TPMS_ATTEST` structure from `tpe_quote_msg` field (magic `0xFF544347`, type `0x8018`) to extract `extraData` (the combined nonce) and `pcrDigest`. Verifies session AK RSA-2048 signature over raw quote message through WebCrypto API. Skipped entirely when `ak_pub_pem`/`tpm_quote_msg` are empty (OCI reports)
6. **AMD SEV-SNP Silicon Proof** (OCI reports): Decodes `snp_report_b64` — checks `report_data[0..32] === expectedNonce` (rest zero), verifies the ECDSA P-384/SHA-384 signature over report bytes `[0..672)` (r/s are 72-byte little-endian fields at 0x2A0/0x2E8), then verifies VCEK → ASK → ARK with the ARK pinned by SHA-256 of its raw DER (Genoa/Turin/Milan pins embedded in `verify.html`)

---

## Known Constraints & Notes

- **EK Certificate ≠ Session AK** (by design): Never compare them during any verification pass. This mismatch is expected.
- **No persistent AK handles on GCP**: `tpm2 getcap handles-persistent` always returns empty on GCP Confidential VMs — the enclave creates a session signing AK via `tpm2_createprimary` each boot.
- **NVRAM buffer must be unbounded**: `tpm2 nvread -s <size>` truncates large certs. Always use `tpm2 nvread` without a size argument to retrieve the complete 1560-byte EC certificate blob.
- **Nonce binding formula**: `SHA-256(SHA-256(PayPal user JSON compacted) ∥ SHA-256(enclave asymmetric signing key DER bytes))`. The TPM quote's `extraData` MUST contain exactly this 32-byte digest or the entire attestation fails validation.
- **`tpm2` standalone binary vs wrapper**: In the minimal initramfs filesystem, the unified `tpm2` binary should always be invoked directly — wrapper aliases like `tpm2_getcap` often don't exist, causing silent failures. Use pattern `tpm2 getcap` instead of `tpm2-getcap`.
- **DHCP timeout**: NATIVE implementation waits up to 30 seconds for DHCPAC before rejecting. If the cloud metadata service is slow responding, increase the socket timeout in PID-1 init (currently set to 30 seconds in the socket setup path).
- **PCIe slot exhaustion**: Each module loaded via `insmod` occupies PCI space on bare-metal virtualized infrastructures; batch loads where possible in `insmod_all()` function.
- **No TPM on OCI**: Never hard-fail on missing TPM artifacts in the `oci` build — `quote()` probes `/dev/tpmrm0`/`/dev/tpm0` first. Empty `ak_pub_pem`/`tpm_quote_msg`/`pcr_values` in a report means "TPM-less platform", not "forgery"; GCP reports always carry TPM evidence and stay strict.
- **SNP report_data binding**: `report_data[0..32]` = raw 32-byte session nonce (`SHA-256(paypal_hash ∥ SHA-256(pubkey DER))`), `[32..64]` zero. The legacy formula `SHA-256(ak_pem ∥ nonce)` was removed — auditors must compare against `expectedNonce` directly.
- **SNP report layout (fixed offsets)**: report_data @ 0x50 (64B), measurement @ 0x90, reported_tcb @ 0x180, chip_id @ 0x1A0 (64B), signature @ 0x2A0 (r @ 0x2A0, s @ 0x2E8, each 72B little-endian), signed region = first **672 bytes**, total report = **1184 bytes**.
- **AMD KDS product naming**: family 19h → `Milan` (base model 0x) / `Genoa` (base model 0x1/0xA); family 1Ah → `Turin` (or `Venice` for models 0x50-0x5F). TCB byte layout: Layout A (bl=b0, tee=b1, snp=b6, ucode=b7) for Milan/Genoa/standard Turin; Layout B (bl=b1, tee=b2, snp=b3, ucode=b7) for Turin-Dense (1Ah model ≥ 0x60). Override with env `AMD_VCEK_FAMILY` during bring-up.
- **OCI user_data path**: `http://169.254.169.254/opc/v2/instance/metadata/user_data` (header `Authorization: Bearer Oracle`), v1 fallback at `/opc/v1/...`. The config arrives base64-encoded (OCI CLI encodes `--user-data-file` automatically).
- **`modprobe sev-guest` fails with ENODEV on non-SNP machines (expected)**: v6.12 `sev_guest_probe()` returns `-ENODEV` when `!cc_platform_has(CC_ATTR_GUEST_SEV_SNP)` and `module_platform_driver_probe()` propagates it through finit → kmod logs `could not insert 'sev_guest': No such device`. This is **normal in qemu/dev builds** — not an initramfs defect. On real OCI E5 with SNP it must load and create `/dev/sev-guest` (still runtime-unverified).
- **PID-1 `modprobe()` captures kmod output** (`src/main.rs`): failures log exit code + captured stdout/stderr to kmsg (the old `-q` invocation swallowed even finit errors). Use the boot log's `ALL PATHS FAILED (rc=… err=…)` lines as the authoritative module-load diagnosis; kmod `-q` hides errors that `.status()` alone would never show.
