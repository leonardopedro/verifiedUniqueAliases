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
| **Quote Mechanism** | TPM quote via `tpm2_quote` (session-bound) | SNP report via `/dev/sev-guest` ioctl (`SNP_GET_REPORT`), report_data = SHA-256(P_enc ∥ nonce) |
| `/dev/sev-guest` | **Not available** on GCP vTPM | **Primary root** (sev-guest driver); fallback ConfigFS TSM |
| ConfigFS TSM | Times out / unavailable | Optional fallback (PATH 3) |
| **TPM / vTPM** | Present (session AK, PCRs) | **Absent** — OCI has no vTPM; TPM evidence fields are empty by design |
| Persistent AK handle | `tpm2_getcap handles-persistent` → empty | N/A (no TPM) |
| Kernel module path | N/A (uses unified TPM path) | `sev_guest`, `amd_sev`, `amd_tsm`, `tsm`, virtio stack |

The project uses a **single codebase** with conditional compilation to support both platforms.

---

### 🏆 Current Accomplishments

- **Pillar 2–4 Security Hardening (v160)**: report-signing key bound into silicon `report_data` (`SHA-256(P_enc ∥ nonce)`), strict PKCE code exchange (RFC 7636), pre-flight audit of the live report via `/debug/envelope`, and dual-profile launch-digests (CI-computed, Sigstore-attested direct-boot profile + live-captured fleet profile pinned in verify.html).
- **Multi-Cloud Platform Support**: Dual-provider runtime — the single source tree supports seamless switching between GCP Confidential VMs (SEV-SNP) and Oracle Cloud (`VM.Standard.E5.Flex`) via the `--features oci` compile-time flag.
- **Correct GCP vTPM Attenuation Model** (v145): Resolved fundamental misunderstanding about two-key attestation. The enclave uses the correct model: Google EK Certificate (NVRAM `0x01c00002`, static silicon proof) is separate from the Session Signing AK (created fresh per-attestation via `tpm2_createprimary`, dynamic quote signer). Keys intentionally do not match.
- **Full EK Certificate Retrieval**: The 1560-byte Google EK/AK CA Certificate is retrieved from NVRAM index `0x01c00002` without truncation using unbounded `tpm2 nvread`. Systematic scanning across indices `0x01c00002`, `0x01c00001`, `0x01400001`, and more.
- **Hardened TPM Quote Verification**: Full binary parsing of `TPMS_ATTEST` in audit flow verifies the hardware-signed nonce from raw TPM quote message, neutralizing session replay and forgery attacks.
- **PCR 15 Software Binding**: Strict verification of `disk_manifest` hash against hardware PCR 15, ensuring running code matches GitHub provenance.
- **PCR Composite Digest**: Auditor manually reconstructs expected SHA-256 hash of all quoted PCRs (0, 4, 8, 9, 15) and verifies against signed `TPMS_ATTEST`.
- **Native DHCP Implementation**: Complete rewrite of network acquisition from shell scripts into pure Rust. Uses `socket2` with `SO_BINDTODEVICE` for reliable broadcast UDP on interfaces lacking IP bindings, including full BOOTP packet construction, lease parsing, and route application (with GCP-specific `/32` MTU handling).
- **Four-Path AMD Hardware Root Acquisition**: Automatic fallback strategy when acquiring SNP reports — PATH 0: native `/dev/sev-guest` ioctl (`SNP_GET_EXT_REPORT` first, which returns the PSP's own VCEK/VLEK+ASK+ARK cert table in one call, then plain `SNP_GET_REPORT`), PATH 1: NVRAM scan (systematic NV index discovery), PATH 2: TPM quote auxblob inspection, PATH 3: ConfigFS TSM interface. The PSP cert table is authoritative — the enclave verifies chain + report signature against each offered leaf (VCEK, then VLEK) and publishes the one that verifies; AMD KDS remains the fallback for legacy kernels. Includes automatic VCEK fetch from AMD Key Distribution Service (KDS) based on extracted chip ID with CPUID family-aware product naming (Milan/Genoa/Turin) and TCB layout selection (AMD KDS spec Tables 3/4).
- **OCI SEV-SNP Adapter** (`oci_snp.rs`): Replaces the retired Intel TDX module — sev-guest ioctl structs, CPUID family detection (`__cpuid(1)`), report parsing (report_data/chip_id/reported_tcb/signature at documented offsets), TCB byte-layout selection (Layout A vs B), AMD KDS VCEK/chain fetch, and OCI instance metadata access (`/opc/v2` with v1 fallback, `Authorization: Bearer Oracle`) including `user_data` config delivery.
- **PID 1 Hardened Init Pipeline**: All filesystem lifecycle logic lives in `enclave_init` module within PID 1 before Tokio runtime starts. Handles mount ordering (`/dev` first so kmsg works), aggressive driver discovery via recursive `insmod` scanning of `/lib/modules`, and EFI partition measurement (dynamic device scanning).
- **Egress Hardening & Firewalling**: nftables ruleset enforcing strict TCP/UDP port filtering. TLS pinning enforced at transport layer via embedded `google_ca.pem` and `paypal.pem` compiled into binary via `include_bytes!`. DNS resolution hardcoded via `reqwest::resolver::resolve` to prevent hijacking. Bandwidth throttled per-IP (the old global 512 MB/h cap was removed in v153 — audit SEC-05: it was a self-inflicted service-wide DoS).
- **Secure Time Synchronization**: RTC pre-seeded to epoch 2026 prevents TLS cert validation failure on cold-boot machines. HTTPS-based time fetch serves as clock source after initial boot; timezone stripped from Date header.
- **Stable Build OS**: Build system, kernel image, initramfs pinned to Debian 13 (Trixie) using snapshot.debian.org. Reproducible via multi-stage Docker synthesis engine.
- **v160 Live on login.airma.de (2026-10-14)**: the attested v160 image (commit 713da7d, binary `db57929d…`, provenance gate ON) replaced the pre-v160 `sec02` fleet; E5/AD-3 relaunch landed a KDS-verifiable host on the first attempt (`vcek_source=kds`, VCEK 1796 B). Real `runAudit()`/`runPreflight()` driven from `verify.html` against the live `/debug/envelope` (CORS `*`) pass green: report signature, session binding, v160 `report_data` = SHA-256(P_enc ∥ nonce), ECDSA P-384, VCEK→ASK→ARK (ARK pin), launch-digest pin, Sigstore provenance (binary + image atomicity). PKCE `S256` visible on live `/login`.

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
- **SNP-only root of trust**: OCI provides **no vTPM and no TPM**. There is no Google-style EK cert and no PCR 15. The session and the report-signing key are bound through the SNP report `report_data` field (first 32 bytes = `SHA-256(P_enc DER ∥ session nonce)`, v160), and the silicon root is the AMD VCEK certificate chain
- `/dev/sev-guest` is the primary hardware root (sev-guest driver); ConfigFS TSM is the fallback. Whether Debian's `linux-image-cloud-amd64` exposes `/dev/sev-guest` on OCI is runtime-unverified — verify at first boot and adjust module list if needed
- Supported OS list for confidential E5 includes Oracle Linux 9/10 and Ubuntu 24.04; **custom image launch on confidential shapes is LIVE-PROVEN** — the production fleet boots our imported QCOW2 on `VM.Standard.E5.Flex` with `platformConfig AMD_VM` (v160 binding live-verified 2026-10-14; single-UKI ESP live 2026-10-15). Still validate every NEW image end-to-end with `import-oci-image.sh` + `deploy-oci.sh` before relying on it

### OCI-Specific Delivery Mechanisms
- **Image import**: OCI accepts **QCOW2 only** (raw rejected). `build-oci-image.sh` produces a deterministic bootable QCOW2 (GPT + ESP whose ENTIRE boot payload is the monolithic UKI at `EFI/BOOT/BOOTX64.EFI` since v161 — no shim/grub loose files); `import-oci-image.sh` uploads to Object Storage and imports via `oci compute image import from-object --source-image-type QCOW2 --launch-mode PARAVIRTUALIZED`, polling the image until AVAILABLE
- **Config delivery**: `deploy-oci.sh` injects the enclave **config JSON directly as instance `user_data`** (base64-encoded by the OCI CLI). The enclave reads it from `http://169.254.169.254/opc/v2/instance/metadata/user_data` (IMDSv2 with `Authorization: Bearer Oracle`, v1 fallback) — **no cloud-init, no bash user-data**. Path is `instance/metadata/user_data`, NOT `virtualDevices/instance/user_data`
- **Instance metadata**: used for boot preview logging (`instance/`) and `user_data`; region/AD discovery and all provisioning go through the operator's `oci` CLI (pre-installed, no deb packaging — the old aliyun CLI packaging stack was deleted with the Alibaba target)

---

## Cryptographic Chain of Trust

```
GitHub Provenance
    └─► PCR 15 (disk_manifest SHA-256 measured into TPM at boot)
            └─► PCR Composite Hash (SHA-256 of all quoted PCRs 0,4,8,9,15)
                    └─► TPMS_ATTEST binary (signed by Session AK over PCR composite + session nonce)
                            └─► Session Nonce (SHA-256[PayPal User Hash ∥ Enclave PubKey Hash ∥ SHA-256(custom_info)])
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
GitHub Provenance ──► disk_manifest SHA-256 (measured at boot; no PCR 15 — carried in the enclave-signed report only, see the scope warning below)
Session Nonce (SHA-256[paypal hash ∥ SHA-256(enclave pubkey DER) ∥ SHA-256(custom_info)])
    └─► SNP report_data[0..32] = SHA-256(P_enc DER ∥ session nonce) (rest zero)   ← (v160) binds report to THIS session AND the signing key
AMD VCEK (from kdsintf.amd.com, TCB-versioned by bl/tee/snp/ucode SPLs)
    └─► ECDSA P-384/SHA-384 signature over SNP report bytes [0..672)
            └─► VCEK → ASK → ARK chain (ARK pinned by SHA-256 of raw DER in verify.html)
                    └─► ARK pin set: Genoa / Turin / Milan (KDS) — family selected by CPUID
```

> **⚠️ OCI measurement-scope truth (audit SEC-02, 2026-10-13)**: on OCI the
> AMD SEV-SNP `LAUNCH_DIGEST` (report bytes 144..192) measures only Oracle's
> OVMF launch firmware — the virtual disk (the UKI: EFI stub + cmdline +
> kernel + initramfs in one PE/COFF, plus the enclave binary inside it)
> is attached via virtio and read AFTER the launch measurement, so it is
> **not** hardware-measured. The pinned digest pins *Oracle's standard
> confidential OVMF*, not our code. What hardware proves on OCI: genuine AMD
> silicon, memory encryption, and a session-bound nonce. Code integrity rests
> on the GitHub provenance of the self-reported `disk_manifest` /
> `binary_sha256` against the bitwise-reproducible build — NOT on the SNP
> digest. `verify.html` states this inline on every OCI report. If OCI ever
> ships a vTPM for E5/E6, migrate measured boot back to PCRs.
>
> **Deploy only attested builds (audit follow-up)**: `verify.html` queries
> `api.github.com/repos/…/attestations/sha256:<hash>` for exactly the hashes a
> report carries, and CI attests artifacts built **from pushed commits**
> (`.github/workflows/build-attest.yml`). A binary/disk built from a dirty or
> uncommitted tree has a hash no attestation will ever cover — every report
> from such a deployment shows `❌ Binary / ❌ Image Atomicity`. Workflow:
> commit → push → CI attests → build from the clean checkout
> (bitwise-reproducible) → deploy. `build-oci-docker.sh` now warns when a
> freshly built hash has no GitHub attestation.
>
> **Local ≠ CI kernel trap (fixed 2026-10-13)**: `Dockerfile.oci` used to
> prefer a gitignored host-side `ol10/` staging dir over the in-container
> pinned-NEVRA extraction. That dir (kernel `6.12.0-206.104.4.4`) silently
> overrode the committed pin (`6.12.0-207.111.5.1.el10uek`) in EVERY local
> build, so local images and CI artifacts never shared a kernel hash — and
> provenance could never pass no matter what was deployed. The pinned
> extraction is now the default (identical to CI); the host shortcut is
> opt-in via `--build-arg USE_HOST_OL10=1` (bring-up only — it forfeits
> attestation parity).

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

Build commands (local builds need `pkg-config` + OpenSSL headers, which the
`nix-shell -p pkg-config openssl` wrapper supplies — a bare `cargo build`
stops at `openssl-sys`; the Docker/podman path installs its own):
```bash
# GCP (default)
nix-shell -p pkg-config openssl --run 'cargo build --release --target x86_64-unknown-linux-gnu'

# Oracle Cloud
nix-shell -p pkg-config openssl --run 'cargo build --release --features oci --target x86_64-unknown-linux-gnu'

# Local verification: the tree has no #[test], so the gate is "both feature sets compile"
nix-shell -p pkg-config openssl --run 'cargo test --locked && cargo check --locked --all-targets --features oci'

# Relative markdown links (CI: linkcheck.yml)
nix-shell -p python3 --run "python3 scripts/check-links"

# Full reproducible OCI image (binary + initramfs + QCOW2), uses docker or rootless podman
bash build-oci-docker.sh
```

### OCI Image Build Details (OL10 / UEK8)

The deliverable is a **bootable QCOW2 VM image** — the container is only a build sandbox. Rootless podman works (no root/docker daemon needed; needs `/etc/subuid`+`/etc/subgid` entries, setuid `newuidmap`/`newgidmap`, `~/.config/containers/policy.json` with `insecureAcceptAnything`, and `registries.conf` with `unqualified-search-registries=["docker.io"]` for the short-name `debian@sha256:…` ref).

1. **`ol10-builder` stage** (`FROM oraclelinux:10@sha256:…` digest-pinned): `extract-ol10-binaries.sh` dnf-installs pinned NEVRAs (`kernel-uek-* 6.12.0-207.111.5.1.el10uek` from a written UEKR8 repo, `shim-x64`, `grub2-efi-x64`, `--setopt=tsflags=noscripts`), stages `ol10/{vmlinuz,modules/<ver>,BOOTX64.EFI,grubx64.efi,VERSIONS.txt}` with a sha256 manifest
2. **rust-builder stage**: Debian + pinned `RUST_VERSION`, builds `--features oci` for `x86_64-unknown-linux-gnu`
3. **initramfs** (`build-initramfs-tools.sh` OL10 branch): self-assembled staging (skips Debian `mkinitramfs`), curated `MODULES_OVERRIDE` injection with **dependency closure** — boot-proven required sets: `virtio_pci`→`virtio_pci_modern_dev`+`virtio_pci_legacy_dev`, `virtio_net`→`net_failover`→`failover`, `sr_mod`→`cdrom`, `sev_guest`→`tsm`, `sev_guest` probe crypto prereqs `gcm`+`ghash_generic`→`gf128mul` (probe runs `crypto_alloc_aead("gcm(aes)")`; missing gcm/ghash ⇒ `-EIO`, no `/dev/sev-guest`), `nvme`→`nvme-core`→`nvme-auth`+`nvme-keyring`, `nft_ct`→`nf_conntrack`; `modules.builtin*`/`modules.order` must be copied into staging or depmod warns and builtin lookups fail
4. **`build-oci-image.sh`**: deterministic GPT+ESP → QCOW2. Kernel cmdline uses `mem_encryption=on` only — `sev=on` is invalid for this kernel

Reproducibility (proven repeatedly): `podman build` vs `podman build --no-cache` → bitwise-identical qcow2/initramfs/grub.cfg. **Cross-environment proof (2026-10-14)**: the rootless-podman synthesis on the dev host produced byte-identical enclave binary / initramfs / qcow2 (sha256 `db57929d16e6…`, `d7ccdc082ca9…`, `1e1f3abf7e25…`) to the GitHub Actions build of the same commit (`713da7d`) — all three return HTTP 200 on the public attestations API. QE smoke test: `qemu-system-x86_64 -machine q35 -enable-kvm -m 2048` + OVMF pflash pair (`OVMF.fd` → `FV/{OVMF_CODE.fd,OVMF_VARS.fd}`, copy VARS to a writable file and `chmod 644` — nix store files are read-only) + virtio-blk qcow2 + user-mode net. Expected in qemu: all modules load, DHCP handshake completes, then the config fetch fails (no OCI IMDS in qemu) → `panic=1` reboot loop.

---

## Security Architecture

### Hardware-Anchored Trust Layer

#### GCP (AMD SEV-SNP) Path
- **Google EK Certificate** (NVRAM `0x01c00002`): DER X.509 cert issued by `EK/AK CA Intermediate` under Google's CA chain. Proves instance runs on real GCP Confidential VM silicon.
- **Session Signing AK**: Created fresh per-attestation via `tpm2_createprimary`. Signs TPM Quote containing PCR values + session nonce. Never reused.
- **Measured Boot**: PCRs 0, 4, 8, 9, 15 provide full-stack coverage verified by TPM quote.
- **Embedded TLS Pinning**: `google_ca.pem` and `paypal.pem` compiled directly into binary via `include_bytes!`, preventing filesystem-level tampering.

#### Oracle Cloud (AMD SEV-SNP) Path
- **SNP Report** (`/dev/sev-guest`, `SNP_GET_REPORT` ioctl): `report_data[0..32]` = `SHA-256(P_enc DER ∥ session nonce)` (v160 — commits the silicon quote to the report-signing key); signed by the chip's report key
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

#### Credential Loading (fail-closed)
Credentials (both PayPal flows) are loaded from environment variables, `CONFIG_FILE`, or instance `user_data` and **validated at startup** — empty or `MISSING_*` placeholder values abort boot. Hardcoded fallback secrets were removed in v152: the OCI image is reproducible from a public repo, so any compiled-in credential is world-readable.

---

## Verification Workflow (Auditor Flow)

> **Pre-flight audit (v160, Pillar 4)**: `verify.html` audits the LIVE hardware report *before* any PayPal redirect — `runPreflight()` fetches `GET /debug/envelope` (CORS `*`) and pins the enclave's `enclave_signing_public_key`; binding, measurement pin, and silicon root must pass first, and the final post-login report must be signed by the SAME pinned key (else the audit throws `PRE-FLIGHT VIOLATION`).

The system presents a signed **Remote Attestation Report** on the OAuth callback page after successful user login:

1. **Local air-gap verification**: Users download the JSON report and `verify.html` for deterministic offline auditing — eliminates web-vector trust completely
2. **GitHub Sigstore provenance**: Automatically fetches and verifies atomic run metadata across all components (binary, kernel, initramfs, bootloader)
3. **Silicon Audit**: Reads `google_ak_cert_pem` from report body and confirms:
   - Issuer chain contains `EK/AK CA Intermediate` or `Google Cloud Confidential Computing OS Root CA`
   - **A fully-verified TPM quote accompanies the cert** (signature + nonce + PCR digest) — a pasted public certificate alone is rejected (v152)
   - Encoded subject identity displays correctly (instance, zone, project)
   - Does **not** compare EK cert public key to session AK public key
4. **Disk Manifest Audit**: Live SHA-256 of every file mounted under `boot/efi` compared against signed CI baseline. Verifies expected PCR 15 extension value against hardware state — **PCR 15 check only runs when the report contains TPM evidence** (GCP); TPM-less OCI reports skip it (GitHub provenance checks still apply)
5. **TPM Quote Validity Proof**: Binary-parses `TPMS_ATTEST` structure from `tpe_quote_msg` field (magic `0xFF544347`, type `0x8018`) to extract `extraData` (the combined nonce) and `pcrDigest`. Verifies session AK RSA-2048 signature over raw quote message through WebCrypto API. Skipped entirely when `ak_pub_pem`/`tpm_quote_msg` are empty (OCI reports)
6. **AMD SEV-SNP Silicon Proof** (OCI reports): Decodes `snp_report_b64` — checks `report_data[0..32] === SHA-256(enclave_signing_public_key DER ∥ expectedNonce)` (rest zero; v160 binding — pre-v160 reports fail by design), verifies the ECDSA P-384/SHA-384 signature over report bytes `[0..672)` (r/s are 72-byte little-endian fields at 0x2A0/0x2E8), then verifies VCEK → ASK → ARK with the ARK pinned by SHA-256 of its raw DER (Genoa/Turin/Milan pins embedded in `verify.html`), **and requires the MEASUREMENT (bytes 144..192) to match `EXPECTED_SNP_MEASUREMENTS`** — the pinned launch digest of the reproducible OCI image stack

---

## Known Constraints & Notes

- **EK Certificate ≠ Session AK** (by design): Never compare them during any verification pass. This mismatch is expected.
- **No persistent AK handles on GCP**: `tpm2 getcap handles-persistent` always returns empty on GCP Confidential VMs — the enclave creates a session signing AK via `tpm2_createprimary` each boot.
- **NVRAM buffer must be unbounded**: `tpm2 nvread -s <size>` truncates large certs. Always use `tpm2 nvread` without a size argument to retrieve the complete 1560-byte EC certificate blob.
- **Nonce binding formula**: `SHA-256(SHA-256(PayPal user JSON compacted) ∥ SHA-256(enclave asymmetric signing key DER bytes) ∥ SHA-256(custom_info))`. The TPM quote's `extraData` MUST contain exactly this 32-byte digest or the entire attestation fails validation. Since v160 the SNP form differs: `report_data[0..32]` MUST contain `SHA-256(enclave signing key DER ∥ this digest)` — the report is signed by that key (P_enc), so the silicon quote commits to it; both forms fail closed on mismatch.
- **`tpm2` standalone binary vs wrapper**: In the minimal initramfs filesystem, the unified `tpm2` binary should always be invoked directly — wrapper aliases like `tpm2_getcap` often don't exist, causing silent failures. Use pattern `tpm2 getcap` instead of `tpm2-getcap`.
- **DHCP timeout**: NATIVE implementation waits up to 30 seconds for DHCPAC before rejecting. If the cloud metadata service is slow responding, increase the socket timeout in PID-1 init (currently set to 30 seconds in the socket setup path).
- **PCIe slot exhaustion**: Each module loaded via `insmod` occupies PCI space on bare-metal virtualized infrastructures; batch loads where possible in `insmod_all()` function.
- **No TPM on OCI**: Never hard-fail on missing TPM artifacts in the `oci` build — `quote()` probes `/dev/tpmrm0`/`/dev/tpm0` first. Empty `ak_pub_pem`/`tpm_quote_msg`/`pcr_values` in a report means "TPM-less platform", not "forgery"; GCP reports always carry TPM evidence and stay strict.
- **SNP report_data binding (SEC-02, v155 → v160)**: `report_data[0..32]` = `SHA-256(P_enc DER ∥ session_nonce)`, `[32..64]` zero — P_enc is the per-boot RAM-only RSA-4096 `EphemeralEnclaveIdentity` published as `enclave_signing_public_key`, so the silicon quote now commits to the exact key that signs the final report (a rogue binary holding official hashes still cannot produce a report signed by the audited P_enc). `session_nonce` itself = `SHA-256(paypal_hash ∥ SHA-256(pubkey DER) ∥ SHA-256(custom_info) ∥ binary_sha256 ∥ SHA-256(canonical_manifest_json))` — a 160-byte 5-element pre-image. `canonical_manifest_json` = sorted `[[path, sha256], …]` compact JSON (byte-identical between Rust `canonical_manifest_json()` and the auditor's `JSON.stringify(sorted pairs)`). The OCI SEV-SNP launch digest is fleet-constant (covers only Oracle's OVMF), so this fusion is what makes the silicon quote commit to the exact running code; the auditor's Sigstore lookup of the same hashes closes the loop. Parity pins: Rust `security_tests::session_nonce_binds_custom_info` + `security_tests::snp_report_data_binding_parity_v160` ↔ node Test 4 (`398c2c1b…`) + Test 8 (binding parity pin + pre-flight key pinning) ↔ verify.html — update all together. Reports from pre-v155 enclaves FAIL the nonce-composition checks; reports from pre-v160 enclaves FAIL the binding check, by design. The legacy formula `SHA-256(ak_pem ∥ nonce)` was removed — auditors must compare against `expectedNonce` directly. **Live-verified 2026-10-14 (real Firefox via Selenium on the deployed fleet envelope)**: a pre-v160 report fails ONLY this binding check while `sig=true`, `chain=true` (Genoa ARK pin `4c6598d1…`) and the measurement pin both pass — exactly the by-design rejection; every check turns green only after the v160 image is deployed (`deploy-oci.sh`).
- **Pre-flight client-bound binding (v161 → v161.2)**: for pre-flight (E2EE) sessions the SNP `report_data[0..32]` instead carries `SHA-256(P_enc_SPKI_DER ∥ code_challenge ∥ P_client_SPKI_DER ∥ client_nonce[32] ∥ custom_info_utf8)` — five-element since v161.2, where `custom_info` is the user's optional input from the verify.html field (public key / wallet / nonce), canonicalized once in the pre-flight handler (trimmed, empty→`NONE`, 512-byte cap) and echoed in `signed_fields.custom_info`, `session_context.preflight.custom_info` AND `report.custom_info` (all three must be identical — the browser aborts on any echo mismatch before redirecting to PayPal, and the auditor recomputes the binding from the echoed value). The same custom string is also hashed into the session nonce, so the silicon quote commits directly to the user's entropy. `[32..64]` zero. Parity pins: Rust `security_tests::preflight_binding_parity_v161` (`c459f5fa…` for the test vector with custom_info, `52bc1e5b…` for the canonical `NONE` form) ↔ node Test 9 (mirror + drift guard executing the SHIPPED `preflightBindingHex` from verify.html) ↔ `tpm::preflight_report_data_binding()` — update all together. Pre-v161.2 pre-flight reports FAIL the binding check by design (same discipline as v160→v161).
- **SNP MEASUREMENT pinning (ghost-enclave guard)**: `verify.html` requires the report's launch digest (bytes 144..192, SHA-384 of the initial guest image) to match `EXPECTED_SNP_MEASUREMENTS` — the pinned digest of the reproducible OCI image stack. A valid VCEK signature only proves *some* AMD SEV-SNP VM produced the report; the pin proves it is *our* image. **Re-pin after any image change**: capture `snp.slice(144,192)` hex from a freshly deployed, independently audited instance and add it to the list in `verify.html`. Since v160, `build-attest.yml` also computes the *direct-boot* profile digest (staged OVMF = pinned Debian `ovmf-amdsev_2026.08+ds-2` extracted in the image-builder stage — the only Debian OVMF carrying the `SNP_KERNEL_HASHES` section that `sev-snp-measure --kernel` requires: every generic `OVMF_CODE*.fd` variant from `apt install ovmf` errors with "doesn't include SNP_KERNEL_HASHES section" — plus UKI inputs, cmdline single-sourced from the built `grub-<platform>.cfg`, 1/2 vCPUs, EPYC-Genoa, `sev-snp-measure==0.0.13`), publishes it as `EXPECTED_SNP_MEASUREMENT_<PLATFORM>_<N>VCPU` (job env) + `snp-measure-<platform>.txt` + job summary, and Sigstore-attests that file via `actions/attest-build-provenance@v2` — an unstaged input is an explicit `[gap]`, never a silent pass. The live-captured fleet array `EXPECTED_SNP_MEASUREMENTS` remains verify.html's authority (harness Test 1 asserts the live digest is pinned there); refresh the fleet pin after any image change. **Direct-boot digest MEASURED (Pillar 1 finished, 2026-10-15)**: CI run `38633354282` (commit `32d5111` — step 5 `Compute SEV-SNP expected launch measurement` = success AND step 6 `Attest SEV-SNP expected launch measurements` = success, which is only possible when `snp-measure-oci.txt` was actually written, i.e. NOT the `[gap]` path) computed the UKI-profile digests, and they were **reproduced locally with the identical tool + inputs** (`sev-snp-measure==0.0.13`, inputs docker-cp'd from the build image; local UKI `f5c76c22…`, initramfs `cd668c62…`, grub.cfg `00aef1c0…` each carry Sigstore attestations from that very run — byte-identical in, byte-identical out): **1 vCPU `6019f67a7380b8b17a5e070e6e5342eee1920c1731a7dfdd295911b76df03d6e03dd049f7e29c840a9d3c418f9b63a89`**, **2 vCPU `03db06441639121c65aa233aa6ab342b2b0d54c4d300cda089a51c76f8ee71fb48f19a7ce867508eca3ae69f207e6807`** (EPYC-Genoa, staged `ovmf-amdsev` profile). These are the expected digests for a platform that measures the UKI (QEMU `kernel-hashes=on`, plan §3.3) — NOT the OCI fleet digest, which stays OVMF-only (SEC-02 scope warning above). CI job logs require admin rights (403 anonymously), so the cross-check is byte-identity of inputs + step conclusions, not log diffing.
- **PKCE (RFC 7636, v160)**: `/login` generates a 32-random-byte `code_verifier` (base64url; RAM-only, single-use 10-min TTL keyed by the OAuth `state`, never logged or serialized — the report JSON carries no PKCE fields) and sends `code_challenge = BASE64URL(SHA-256(verifier))` + `code_challenge_method=S256` in the authorization URL. `/callback` looks up the single-use `(state, pkce)` entry (403 on unknown/expired — replay safe) and redeems the code itself, presenting the in-RAM verifier: an intercepted authorization code cannot be exchanged by any other party because PayPal's S256 check rejects it (exchange failure is logged enclave-side; the browser only sees a generic error, per v156). Enforced by Rust `security_tests::pkce_session_matches_rfc7636` — no PKCE material crosses the report boundary, so verify.html has no PKCE logic to mirror.
- **UKI + dual-profile measurement (v160, Pillar 1)**: `build-oci-image.sh` single-sources the kernel cmdline (`KERNEL_CMDLINE`) into grub.cfg, the monolithic UKI (`output/enclave-uki.efi` = stub + `.cmdline`/`.linux`/`.initrd` via objcopy with fixed non-overlapping VMAs derived from the stub's `.text` — never an absolute `0x30000`, which would land inside the stub and corrupt its PE headers), and the `sev-snp-measure` inputs; CI stages OVMF (as `OVMF-<platform>.fd`), computes the direct-boot digest (1/2 vCPUs, EPYC-Genoa) and publishes it to the job env + step summary alongside a Sigstore-attested `snp-measure-<platform>.txt`. The OCI ESP boot chain is the **UKI directly since v161** (`EFI/BOOT/BOOTX64.EFI` = `output/enclave-uki.efi`, no shim/grub loose files) — **live-proven on real OCI E5 hardware**: the deployed `login.airma.de` envelope captured 2026-10-15T01:57Z has `disk_manifest = {EFI/BOOT/BOOTX64.EFI, NvVars}` (single-payload ESP), its UKI hash `b3559f12…` is Sigstore-attested by run 38624597877, and its fleet launch digest still equals the pinned OVMF-only value `8f58e1cc…`. OCI's launch digest therefore remains OVMF-only (SEC-02 scope warning above): the UKI boots under an UNMEASURED firmware handoff by construction; the *direct-boot measurement profile* (UKI-input digests above) is computed in CI for QEMU CC platforms and a future OCI boot-mode change that OCI's current launch API cannot express.
- **Google AK certificate is not a silicon root by itself**: the cert is public data (checked-in copies existed in git history until v152). `verify.html` only accepts it when accompanied by a fully-verified TPM quote (signature + session nonce + PCR digest) — i.e. on real GCP hardware. TPM-less (OCI) reports must pass the AMD SEV-SNP path instead.
- **OAuth CSRF state**: `/login` issues a random 32-byte `state` (single-use, 10-min TTL, server-side map) mirrored into an `HttpOnly; Secure; SameSite=Lax` cookie; `/callback` rejects unless the query token matches the cookie and is found unexpired in the map. The old static `state` (flow label) allowed Login CSRF.
- **Fail-closed firewall**: any `nft` spawn error **or non-zero exit** during `setup_firewall()` poweroffs the enclave — running without egress filtering violates the threat model.
- **No self-signed TLS fallback**: ACME failures retry with capped backoff (2 min → 1 h) instead of serving a self-signed certificate (removed in v152 with its `rcgen` dependency) — a fallback cert breaks production and trains users to accept warnings (MITM prompt-fatigue).
- **No private key logging**: the ephemeral attestation RSA key PEM is never written to `info!()` — on OCI, GRUB's `console=ttyS0` lands every log line in Instance Console History (readable with console permissions).
- **SNP report layout (fixed offsets)**: report_data @ 0x50 (64B), measurement @ 0x90, reported_tcb @ 0x180, chip_id @ 0x1A0 (64B), signature @ 0x2A0 (r @ 0x2A0, s @ 0x2E8, each 72B little-endian), signed region = first **672 bytes**, total report = **1184 bytes**.
- **OCI PSP/KDS key mismatch (v153)**: some OCI E5 hosts' PSP signs reports with a key that matches NEITHER the KDS entry for its chip_id/TCB NOR the PSP's own cert table (verified with Google go-sev-guest: report format valid, well-formed P-384 scalars, every cert/encoding fails; sibling instance on a different host/chip verifies fine). The enclave therefore uses `SNP_GET_EXT_REPORT` (0xC0205302) to pull the PSP's own GHCB cert table (`{GUID[16], offset u32, length u32}` entries, zero-terminated, GUIDs VCEK `63da758d-…`, VLEK `a8074bc2-…`, ASK `4ab7b379-…`, ARK `c0b406a4-…`), validates chain+signature per leaf, and publishes whichever verifies; a report whose signature verifies against NO available cert is a defective host — relaunch on different hardware (AD-2 landed on a good chip where all 19 verify.html checks pass).
- **AMD KDS product naming**: family 19h → `Milan` (base model 0x) / `Genoa` (base model 0x1/0xA); family 1Ah → `Turin` (or `Venice` for models 0x50-0x5F). TCB byte layout: Layout A (bl=b0, tee=b1, snp=b6, ucode=b7) for Milan/Genoa/standard Turin; Layout B (bl=b1, tee=b2, snp=b3, ucode=b7) for Turin-Dense (1Ah model ≥ 0x60). Override with env `AMD_VCEK_FAMILY` during bring-up.
- **OCI user_data path**: `http://169.254.169.254/opc/v2/instance/metadata/user_data` (header `Authorization: Bearer Oracle`), v1 fallback at `/opc/v1/...`. The config arrives base64-encoded (OCI CLI encodes `--user-data-file` automatically).
- **Verified flow fetches verification info only (v154)**: the `verified` scope is only `paypalattributes`, and the enclave additionally projects the userinfo down to `{user_id, payer_id, verified_account}` via `PayPalUserInfo::into_verification_only()` immediately after the fetch — before the verified_account gate, the session store, the completion page, the nonce hash, or the signed report. Even an over-scoped token or extra PayPal fields cannot leak profile data on this flow; the `full` flow (which explicitly grants profile scope) is unchanged.
- **OCI E5 PSP/KDS endorsement-key mismatch (fixed v154, live-proven)**: the OCI E5 fleet is **MIXED**. On some hosts the PSP signs SNP reports with the chip's KDS-published VCEK (third-party verifiable); on others it signs with a **vendor-loaded (VLEK-style) key that is NOT in AMD KDS** — proven exhaustively on chip `e17153f7…`: 561 distinct KDS certs across the whole TCB neighborhood, zero verify the live report, while a genuine control report+VCEK pair verifies sigOk=true in the same JS code (ruling out an auditor bug). Those hosts also reject `SNP_GET_EXT_REPORT` (`fw_error=0xff` — the PSP cert table is hypervisor-provisioned via `SNP_SET_EXT_CONFIG` and OCI doesn't provision it), so the guest cannot obtain the signing cert at all. Consequences: (a) the enclave publishes a VCEK/VLEK **iff it verifies the live report's signature** (PSP table first; chain completed from the table or KDS issuer certs); the KDS fallback is verify-before-publish and a non-verifying KDS cert is NEVER shipped (the old code shipped it → auditors saw `chain=true, sig=false`); (b) the report carries `vcek_source` (provenance: `psp-table:VCEK|VLEK`, `psp-table+kds-chain:…`, `kds`) which verify.html displays; (c) a report with `snp_report_b64` but no `vcek_der_b64` means NO obtainable key signs it — verify.html fails closed with that exact message; (d) the boot log's `v154: PSP diag:` lines (zero-nonce probe, never evidence) show the cert table contents, per-leaf sig/chain results, AND the KDS verdict (`KDS VCEK sig_ok=true/false`) — this is the per-host oracle; (e) **operations: run `bash check-host-verifiable.sh <instance-ocid>` after every deploy — it drives the serial console across a SOFTRESET and reports `KDS_SIG_OK` / `KDS_SIG_BAD`; on a BAD host, terminate + relaunch (deploy-oci.sh = fresh host lottery; spread across AD-1/2/3 via `OCI_AVAILABILITY_DOMAIN`, the `paypal-subnet` is regional). Known-good host: chip `d2fd32a8…` (AD-3, TCB 12002988).
- **SEC-02 (OCI code↔silicon binding) — defense-in-depth, v155**: four layers: (1) AMD SEV-SNP hardware anchor; (2) the 160-byte nonce pre-image above binds code identity into REPORT_DATA; (3) GitHub Sigstore attestation of the exact binary/initramfs/qcow2/grub.cfg hashes in the report; (4) guest lockdown — `lockdown=confidentiality` is on the **OCI** kernel cmdline only (`build-oci-image.sh`; OL10 UEK modules are Oracle-signed and load under lockdown — proven in the qemu smoke test; the GCP/Debian build deliberately does NOT get it: Debian modules are unsigned). **Deploy gate**: `build-oci-docker.sh` writes `.build-provenance` (commit + 3 artifact hashes) and `deploy-oci.sh` refuses to launch unless every hash answers HTTP 200 on the attestation API (`PROVENANCE_GATE=off` escape hatch for dev/qemu). **Not implemented**: OCI UEFI Secure Boot for imported custom images — the installed OCI CLI exposes no launch option or image-capability-schema path for it (`oci compute instance launch --help` has no secure-boot flag); the shim/grub/UEK components are signed, so this is a tooling gap, not an architectural one.
- **`modprobe sev-guest` fails with ENODEV on non-SNP machines (expected)**: v6.12 `sev_guest_probe()` returns `-ENODEV` when `!cc_platform_has(CC_ATTR_GUEST_SEV_SNP)` and `module_platform_driver_probe()` propagates it through finit → kmod logs `could not insert 'sev_guest': No such device`. This is **normal in qemu/dev builds** — not an initramfs defect. On real OCI E5 with SNP it must load and create `/dev/sev-guest` — **live-proven**: every deployed-fleet envelope (E5, captured 2026-10-14/15) carries an SNP report read through `/dev/sev-guest`.
- **PID-1 `modprobe()` captures kmod output** (`src/main.rs`): failures log exit code + captured stdout/stderr to kmsg (the old `-q` invocation swallowed even finit errors). Use the boot log's `ALL PATHS FAILED (rc=… err=…)` lines as the authoritative module-load diagnosis; kmod `-q` hides errors that `.status()` alone would never show.
- **v162 audit hardenings (see README table)**: `verify.html` has (a) an `EXPECTED_APPS` pin — the audited (flow, client_id, authorize_base, scope) allow-list checked on both pre-flight paths before any PayPal redirect; rotate only via a deliberate reviewed commit; (b) `GOLDEN_PCRS` — per-PCR pins for 0/4/8/9 captured with `scripts/capture-golden-pcrs.mjs <host> --update` from a provenance-gated deployment (v163 tri-state: an unset or partially-pinned set renders the amber ⚠️ DEGRADED state — never a green pass; a set pin that mismatches throws `GOLDEN PCR PIN VIOLATION` ❌ before anything else can report success; all four set + matching ⇒ green ✅); (c) a local-auditor mode — run the page from `file://`, claim the ciphertext from `GET /e2ee-blob?state=…` (single-use, 10-min TTL, CORS `*`) so no key ever exists on the enclave origin. Server-side, `pending_attestations` is gone: `/attest/preflight` is the only `pending_oauth_states` writer and `/callback` fails closed (500) on anything else; identity is only ever delivered inside the E2EE envelope (vaulted + rendered).
- **VULN-01 residual (known, not fixable on OCI)**: the SNP launch digest covers Oracle's fleet OVMF only — disk content is unmeasured by hardware on OCI custom-image launches, and OCI's launch API offers no direct-measured-boot (`SNP_KERNEL_HASHES`) path. Code integrity there rests on the deploy-time GitHub provenance gate in `deploy-oci.sh` + pinned `EXPECTED_SNP_MEASUREMENTS` + reproducible public source. Never claim hardware disk measurement for the OCI path.
- **OCI E6 (Turin) hosts are VLEK-style and NOT third-party verifiable (v156, live-proven)**: a `VM.Standard.E6.Flex` probe (AD-1) produced a well-formed 1184-byte SNP report (version 5; CPUID family 1Ah model 02h visible in the report bytes at 0x188) whose `chip_id` is **8 bytes + 56 zero bytes** — unlike Genoa's full 64-byte chip ID. AMD KDS returns **404 for every query form** (no-TCB-params = base TCB, Layout A SPLs `01/03/00/117`, Layout B `03/03/07/117`, other permutations, left-padded chip id, and Venice/Genoa/Milan family names), while the same KDS serves a Genoa chip's VCEK both with and without TCB params — the calibration that proves the chip is simply absent from KDS, not a naming/layout bug on our side (`Bogus/cert_chain` 404s vs `Turin|Venice/cert_chain` 200 confirms product names are validated). `SNP_GET_EXT_REPORT` fails with `fw_error=0xff` (no `SNP_SET_EXT_CONFIG` table) as on E5. Net: the signing key of an E6 report is unobtainable from both the PSP and KDS → the enclave fails closed and `firmwareCheck` cannot pass. E6 boots the custom image fine (same PV-SCSI path, same `platformConfig AMD_VM`) and is **priced identically to E5** ($0.03/OCPU-h, $0.002/GB-h), so it is worth sampling, but the known-good path remains the **E5 fleet lottery with AD spread** — 2026-10-13: E5/AD-3 landed a KDS-verifiable host on the first relaunch (`vcek_source=kds`) and verify.html passed 5/5 on live `login.airma.de`.
- **AMD KDS cache (v152)**: the VCEK and the ASK+ARK cert chain are fetched once and persisted — directory order `$AMD_VCEK_CACHE_DIR` → `/persistent/.enclave/amd-kds` (survives reboot) → `/tmp/amd-kds-cache` (tmpfs fallback for read-only/volatile roots). The VCEK cache name embeds `chip_id` + reported TCB SPLs, so a TCB update is the only thing that forces a re-download (plus a 7-day expiry margin). Chains shorter than ASK+ARK are never cached or published — `verify.html` anchors silicon trust solely on the pinned ARK, so a partial chain can never validate. `tpm::warm_kds_cache()` (cfg `oci`) pre-fetches both at boot from a zero-nonce SNP report (chip/TCB only, never presented as evidence).

- **vfat iocharset trap (empty `disk_manifest`, fixed v153)**: UEK8's vfat defaults to `iocharset=utf8` and `nls_utf8` is a *module* that was never staged in the OL10 initramfs — every plain vfat mount failed with EIO, so `measure_boot_components()` shipped `disk_manifest: {}` and `verify.html` showed `❌ Image Atomicity` on every OCI report. Three-layer mitigation: `nls_utf8`+`nls_iso8859-1` are now staged (`build-initramfs-tools.sh`); `measure_boot_components()` retries mounts with `iocharset=ascii`/`cp437` (kernel builtins on both UEK8 and Debian) and reuses an already-mounted `/boot/efi`; the boot log's `vfat mount of … failed:` / `Disk manifest: N files measured` kmsg lines are the diagnosis. A live report with `enclave_debug.manifest_size: 0` means the enclave predates the fix.
- **OCI E5 boot volume is PV-SCSI, not virtio-blk (fixed v153b, live-proven)**: on real `VM.Standard.E5.Flex` the boot disk attaches as a paravirtualized SCSI LUN (`ORACLE BlockVolume` behind `virtio_scsi`) whose async SCSI scan + `sd` probe completes *after* PID-1's single-shot measurement — and `sd_mod`, though staged, was never modprobe'd, so no `/dev/sda*` node could ever appear. qemu masks both problems by attaching the disk as virtio-blk (`vda`). Fixes: `load_drivers()` modprobes `sd_mod`+`sr_mod`; `measure_boot_components()` scans `/sys/class/block` in retry rounds (20×500 ms) and logs the candidate list (rounds 0/4/12). Boot serial proof on real E5: `block devices (round 0): ["sda", "sda1"]` → `Successfully mounted /dev/sda1 -> /tmp/esp` → `Disk manifest: 6 files measured` (the 6th file is OVMF's `System Volume Information` — harmless; verify.html checks only the four known ESP keys). **Never trust a manifest fix validated only in qemu for OCI — the PV device model differs; verify on a live E5 via the serial console (RSA key required; ed25519 is rejected, and the session must be attached across a SOFTRESET to catch the ~3-second boot window).**
- **Platform-enforced silicon root (audit SEC-04)**: `verify.html` derives the required silicon root from the report's own evidence class — SNP evidence present → the AMD SEV-SNP path MUST verify; Google cert/TPM evidence → the Google+TPM path; mixed evidence → BOTH. The old `googleVerified || snpVerified` OR let a TPM-less OCI-claiming report be "validated" with a locally forged (self-consistent) TPM quote + the public Google cert. Residual documented risk: a self-consistent TPM quote can still anchor a report that CLAIMS GCP — inherent to the two-key model where EK and session AK are intentionally unlinked; closing it needs GCP-side AK certification against the EK.
- **PayPal edge IP pins need refreshing (audit SEC-06)**: `hardened_client()` pins multiple Cloudflare/Fastly addresses per PayPal host via `resolve_to_addrs` (the v151 single pin `104.16.124.74` stopped appearing in live DNS answers by 2026-10). TLS hostname validation against the embedded roots still gates identity — a stale pin is an *availability* risk, not a trust risk. Refresh with `dig api-m.paypal.com` when token exchanges start failing.
- **No operator identity in the public repo (audit SEC-07)**: the GCP project id is no longer hard-coded anywhere — scripts read `GCP_PROJECT_ID`, the enclave bakes it in via `option_env!("GCP_PROJECT_ID")` at compile time for GCP builds. The legacy GCP troubleshooting docs (`DEBUG_CHECKLIST.md`, `README_GCP_ATTESTATION_FIX.md`, `FINAL_SUMMARY.md`, `gcp-config-check.sh`, `google-archive/`) and scratch files were removed; git HISTORY still contains them — a `git filter-repo`/BFG scrub is an owner decision.

## Security Regression Tests

- `cargo test` — v152 suite: credential validation (no hardcoded fallbacks, placeholders rejected), session-nonce formula + cross-implementation parity vector (must match `expectedNonce` in `verify.html`; update both together), source scan for reintroduced secrets.
- `npm install --no-save node-forge && node scripts/test-verify-security.mjs` — drives the REAL `runAudit()` from `verify.html` (DOM stubbed) against: the Google-cert-paste spoof (must fail), a tampered SEV-SNP launch digest (must fail), nonce parity, a legitimate GCP report (must still pass), an OCI-claiming report with a forged local TPM quote + pasted Google cert (SEC-04 bypass, must fail), and the provenance-failure diagnostics (empty manifest + unattested hash must render explanations, not bare ❌s). Set `GENUINE_REPORT=/path/to/capture.json` to also exercise the pinned-digest checks against a live capture.
