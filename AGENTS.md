# AGENTS.md - Status Guidelines for PayPal Auth Confidential VM

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

### Target Instance Type: ECS.r9i.xlarge
- Processor: Intel Xeon Platinum 8475L (Sapphire Rapids) with Intel TDX or AMD Rome with SEV-SNP depending on allocation
- Alibaba Cloud does **not** expose `/dev/sev-guest` or ConfigFS TSM interfaces out of the box for Spot instances

### Alibaba-Specific Provisions Required
- Provisioning relies on downloading a versioned asset (`aliyun-cli`) and extracting it manually to bypass GPG restrictions
- Requires proprietary utility installation via `.deb` packaging
- Relies on Intel PCK certificates from Intel PKI as primary hardware root of trust
- TDX policy reads may be available via sysfs paths like `sysfs/firmware/intel/tdx/policy`

### Alibaba CLI Packaging Script
```
build-scripts/create-alien-deb.sh
```
- Downloads official release tarball from GitHub releases
- Verifies SHA-256 against SHASUMS256.txt
- Builds a proper .deb package with profile.d PATH injection
- Supports auto-version resolution (`ALIYUN_CLI_VERSION=auto`)
- Output format: `packages/aliyun-cli-{VERSION}_{VERSION}-1_{ARCH}.deb`

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
- **Nonce binding formula**: `SHA-256(SHA-256(PayPal user JSON compacted) ∥ SHA-256(enclave asymmetric signing key DER bytes))`. The TPM quote's `extraData` MUST contain exactly this 32-byte digest or the entire attestation fails validation.
- **`tpm2` standalone binary vs wrapper**: In the minimal initramfs filesystem, the unified `tpm2` binary should always be invoked directly — wrapper aliases like `tpm2_getcap` often don't exist, causing silent failures. Use pattern `tpm2 getcap` instead of `tpm2-getcap`.
- **DHCP timeout**: NATIVE implementation waits up to 30 seconds for DHCPAC before rejecting. If the cloud metadata service is slow responding, increase the socket timeout in PID-1 init (currently set to 30 seconds in the socket setup path).
- **PCIe slot exhaustion**: Each module loaded via `insmod` occupies PCI space on bare-metal virtualized infrastructures; batch loads where possible in `insmod_all()` function.
