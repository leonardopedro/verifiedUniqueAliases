# Implementation Plan: Pure-Play Alibaba Cloud Intel TDX Confidential Auth Enclave

## 1. Executive Summary & Branch Mandate

This implementation plan refocuses the `alibabacloud` branch **exclusively on Alibaba Cloud ECS Intel TDX** (instance shapes `ecs.c9i.xlarge` / `ecs.g8i` / `ecs.r9i` in `cn-beijing-i`). All multi-cloud abstractions, legacy Google Cloud Confidential VM (AMD SEV-SNP via vTPM) code, and Oracle Cloud (OCI SEV-SNP) paths are permanently de-scoped and purged.

### 1.1 Architectural Pillars
1. **Exclusive Platform Target**: Alibaba Cloud ECS Intel TDX with Linux kernel $\ge 6.7$ (Debian 13 Trixie, Linux 6.12 cloud kernel) using ConfigFS TSM (`/sys/kernel/config/tsm/report`) [1].
2. **Phase 3 (UKI) Documented Deferral Maintained**: The boot chain retains GRUB 2.12. Live empirical evidence confirms that GRUB 2.12’s EFI Confidential Computing (CC) Measurement Protocol directly extends `vmlinuz` + `initrd.img` (enclosing `/init`) + `/proc/cmdline` into **`RTMR2`**. Live rotations demonstrated that `RTMR2` moves deterministically with each new `/init` binary while `MRTD`, `RTMR0`, and `RTMR1` remain stable.
3. **Hardened Against Collusion**: Protection holds even when the webservice owner, Alibaba Cloud (the host hypervisor), and external cloud partners (such as Oracle Cloud) cooperate to steal user identities or access tokens. Plaintext data is never exposed outside TDX-encrypted RAM.

---

## 2. Threat Model & Collusion Boundary

```
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│                           COLLUSION ATTACK VECTORS & INVARIANTS                           │
├───────────────────────────────────────────────────────────────────────────────────────────┤
│ 1. Malicious Owner:     Controls PayPal Client Secrets, domain TLS certificates for       │
│                         login.airma.de, Cloudflare DNS-01 tokens, and GitHub repo push.   │
│ 2. Malicious Host:      Alibaba Cloud hypervisor controls virtual disk storage (ESP/GPT),  │
│                         virtual NIC, QGS (Quote Generation Service), and console.         │
│ 3. External Clouds:     Hostile external infrastructure (e.g. OCI) attempting cross-cloud │
│                         quote substitution or replay attacks.                             │
│ 4. Intel Silicon Root:  Intel CPU silicon, TDX SEAM module, and Intel DCAP PCK PKI are     │
│                         GENUINE and UNCOMPROMISED (hardware attacks are out of scope).    │
├───────────────────────────────────────────────────────────────────────────────────────────┤
│ CORE GUARANTEE: Even if the owner and cloud host tamper with the disk, terminate domain  │
│ TLS, or inject network traffic, the client auditor mathematically rejects the enclave     │
│ via TDX hardware quotes before credentials or user profile data can be compromised.       │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Codebase Pruning: Purging Multi-Cloud Technical Debt

To eliminate cross-cloud attestation confusion, reduce binary size, and simplify security auditing, all non-Alibaba/non-TDX code must be excised.

### 3.1 Cargo.toml & Rust Compilation
* **Remove Multi-Cloud Feature Toggles**:
  - Remove `[features] default = []` and `alibabacloud = []` from `Cargo.toml`.
  - Compile Intel TDX support unconditionally. Remove all `#[cfg(feature = "alibabacloud")]` conditional blocks in `src/main.rs` and `src/intel_tdx.rs`.
* **Prune Non-TDX Dependencies and Code**:
  - Delete `src/google_ca.pem` and remove `GOOGLE_CA_PEM` from `src/main.rs`. Retain only `src/paypal.pem` (pinned DigiCert Global Root G2).
  - Delete `src/bin/test_gcp_iam.rs` and `parse_chip_id.rs`.
  - Remove all GCP metadata IP addresses (`169.254.169.254`) from network routines and `nftables` firewall rules.

### 3.2 Purge Legacy Repository Artifacts
* **Delete GCP-Specific Scripts & Docs**:
  - Delete `google-archive/` directory.
  - Delete `Dockerfile.repro` (GCP Dockerfile), `build-vm-image.sh`, and `build-gcp-gpt-image.sh`.
  - Delete `gcp-config-check.sh`, `verify_enclave.sh`, `README_GCP_ATTESTATION_FIX.md`, and `FINAL_SUMMARY.md`.
* **Streamline `.github/workflows/build-attest.yml`**:
  - Remove the build matrix (`gcp` vs `alibabacloud`).
  - Run exclusively on a single job targeting `Dockerfile.alibaba` (target: `assembler`).
  - Attest only Alibaba Cloud artifacts: `paypal-auth-vm`, `vmlinuz`, `initramfs-paypal-auth.img`, and `disk-alibaba.raw`.

### 3.3 Hardware Module Selection (`build-initramfs-tools.sh`)
* Strip all AMD and GCP kernel modules from the initramfs build:
  ```bash
  # Pure-play Alibaba Cloud Intel TDX module set:
  PLATFORM_MODULES="tdx-guest tsm virtio_net virtio_scsi virtio_blk virtio_pci nvme nvme_core vfat nls_cp437 nls_ascii nf_tables nft_chain_filter nft_reject_ipv4 nft_limit nf_conntrack nft_ct configfs"
  ```
  *(Removed: `sev_guest`, `amd_tsm`, `gve`, `coco`, `virt_anchor`)*.

---

## 4. Hardware Verification Architecture (Intel TDX on Alibaba Cloud)

```
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│                        ALIBABA CLOUD INTEL TDX HARDWARE REGISTERS                         │
├───────────────────────────────────────────────────────────────────────────────────────────┤
│  Intel Hardware Root (Intel SGX/TDX PCK Root CA -> Quoting Enclave)                       │
│    └─► Signed TD Quote (ECDSA P-256 over SHA-384 TDREPORT)                                │
│          ├─► MRTD  (TDVF Firmware Initial Build Measurement) == PINNED_MRTD               │
│          ├─► RTMR0 (Firmware Environment & ACPI Configuration) == PINNED_RTMR0            │
│          ├─► RTMR1 (EFI Bootloader: Shim + GRUB 2.12 Binaries) == PINNED_RTMR1            │
│          ├─► RTMR2 (OS Kernel + Initramfs + /init + Cmdline) == PINNED_RTMR2  <-- CODE PIN │
│          ├─► RTMR3 (Enclave Application Custom Measurement) == 0x00...00                   │
│          │                                                                                │
│          ├─► REPORTDATA[0..32]  == SHA-256(P_enc ∥ code_challenge ∥ P_cli ∥ Nonce ∥ App) │
│          └─► REPORTDATA[32..64] == SHA-256(P_cli ∥ Nonce_cli)                             │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

### 4.1 Register Partitioning under GRUB 2.12
1. **`MRTD` (Build-Time Measurement)**:
   - Measures the initial TD private memory populated by Alibaba Cloud ECS host hypervisor before `TDH.MR.FINALIZE` (the TDVF firmware).
   - Invariant across enclave binary updates. Pinned in `verify.html` (`EXPECTED_MRTD`).
2. **`RTMR0` (Firmware Environment)**:
   - Extended by TDVF during early boot. Measures platform configuration and ACPI tables.
   - Pinned in `verify.html` (`EXPECTED_RTMR0`).
3. **`RTMR1` (Bootloader)**:
   - Extended by TDVF when loading `/EFI/BOOT/BOOTX64.EFI` (shim) and `grubx64.efi`.
   - Invariant as long as Debian’s signed shim and GRUB binaries are untouched. Pinned in `verify.html` (`EXPECTED_RTMR1`).
4. **`RTMR2` (OS Kernel, Initramfs, and Execution Core)**:
   - **The Anchor of Running Code**: Extended by GRUB 2.12 via `EFI_CC_MEASUREMENT_PROTOCOL` before executing `vmlinuz`.
   - Covers:
     * Kernel image (`vmlinuz`)
     * Complete initramfs (`initramfs-paypal-auth.img` enclosing the statically linked Rust `/init`)
     * Immutable kernel command line:
       ```text
       console=tty0 console=ttyS0,115200n8 net.ifnames=0 biosdevname=0 swiotlb=524288
       ```
   - Pinned in `verify.html` (`EXPECTED_RTMR2`).
   - **Why this defeats the host collusion**: Any host modification to `/init` on the virtual disk alters the initramfs SHA-384 hash, resulting in a different `RTMR2` value in the hardware quote.
5. **`RTMR3` (Runtime Extensions)**:
   - Pinned strictly to all zeros ($0^{48}$).

---

## 5. Pure-Play Verification Engine (`verify.html`)

All legacy multi-cloud verification branches (`claimsOci`, `claimsGcp`) are completely removed from `verify.html`. The auditor becomes a dedicated Intel TDX verifier.

### 5.1 De-Scoping Foreign Evidence in `verify.html`
* Delete all node-forge code paths handling AMD VCEK, ASK, ARK, Milan/Genoa/Turin keys, and Google NVRAM EK certificates.
* Enforce that any report missing an Intel TDX Quote v4/v5 is rejected outright:
  ```javascript
  if (!hw.tdx_quote_b64) {
      throw new Error("REJECTED: Report contains no hardware-signed Intel TDX Quote. This service exclusively supports Alibaba Cloud Intel TDX.");
  }
  ```

### 5.2 Intel DCAP Quote Verification Flow
1. **Header Validation**:
   - `version`: 4 or 5.
   - `tee_type`: `0x00000081` (Intel TDX).
   - `vendor_id`: `939a7233f79c4ca9940a0db3957f0607` (Intel Quoting Enclave).
   - `att_key_type`: `2` (ECDSA P-256).
2. **Signature & Attestation Key Binding**:
   - Verify quote signature over `signed_length` (header + TDREPORT body) using the quote's embedded ephemeral attestation public key.
   - Verify QE Report: Assert $\text{SHA-256}(\text{att\_key} \parallel \text{qe\_auth\_data}) == \text{QE\_Report.report\_data}[0..32]$.
   - Verify QE Report signature using the PCK Leaf Certificate.
3. **PCK Chain to Intel Root**:
   - Walk the X.509 certificate chain from PCK Leaf $\rightarrow$ PCK Platform CA $\rightarrow$ Intel SGX/TDX Root CA.
   - Assert the root certificate matches the pinned digest:
     `44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3`.
4. **Hardware Register Matching**:
   - Extract `MRTD` and `RTMR0..3` from `TDREPORT10` (body offsets `136..184` and `328..520`).
   - Assert exact match against `EXPECTED_MRTD`, `EXPECTED_RTMR0`, `EXPECTED_RTMR1`, `EXPECTED_RTMR2`, and `EXPECTED_RTMR3`.
   - Failure on any register immediately halts the audit.

---

## 6. Anti-Collusion Protocol & Cryptographic Flow

```
Client (verify.html on file:// or GitHub Pages)   Enclave (Alibaba Cloud ECS Intel TDX)
─────────────────────────────────────────────   ─────────────────────────────────────
Generate Ephemeral ECDH (P_cli, S_cli)
Generate Random Nonce_cli (32 bytes)
Send P_cli, Nonce_cli, flow, custom_info ──────► Ingest client session parameters
                                                Generate Enclave ECDH (P_enc, S_enc)
                                                Generate PKCE code_challenge / verifier
                                                Compute REPORTDATA[0..32]:
                                                  SHA256(P_enc ∥ challenge ∥ P_cli ∥ Nonce ∥ custom ∥ App_ID)
                                                REPORTDATA[32..64] = 0
                                                TDCALL [TDG.MR.REPORT] -> Fetch Quote via ConfigFS TSM
                      ◄──────────────────────── Return Signed Fields + Pre-flight Quote
Verify Pre-flight Quote:
  1. Intel PCK Chain -> Intel Root CA
  2. MRTD & RTMR0..3 == Golden Pins
  3. REPORTDATA[0..32] == Client Session Hash
Store P_enc, client keys in local memory
Redirect user to PayPal with PKCE challenge
                      (User Authenticates at PayPal)
PayPal redirects with code to /callback ───────► Ingest code & state token
                                                Exchange code with PayPal using code_verifier
                                                Fetch userinfo (api-m.paypal.com)
                                                Filter to verified-only; zeroize tokens
                                                Compute REPORTDATA[0..32]:
                                                  sec02_nonce(paypal_hash, P_enc, custom, manifest)
                                                Compute REPORTDATA[32..64]:
                                                  SHA256(P_cli ∥ Nonce_cli)
                                                TDCALL [TDG.MR.REPORT] -> Fetch Callback Quote
                                                Derive K = HKDF(ECDH(S_enc, P_cli), Nonce_cli)
                                                Encrypt report with AES-256-GCM_K
                      ◄──────────────────────── Return Ciphertext Blob (No Plaintext)
Fetch blob via GET /e2ee-blob?state=...
Decrypt using S_cli and Nonce_cli
Verify Callback Quote:
  1. Intel PCK Chain -> Intel Root CA
  2. MRTD & RTMR0..3 == Golden Pins
  3. REPORTDATA[0..32] == Identity Nonce
  4. REPORTDATA[32..64] == Client Session Hash
Output: Verified Identity Decrypted Locally
```

### 6.1 Auditor Isolation (Eliminating Hostile Origin Script Injection)
* Under the threat model, the domain `login.airma.de` is controlled by the malicious owner and host.
* `verify.html` must **never** execute key generation or decryption when loaded from `https://login.airma.de/`.
* `trustedAuditorContext()` in `verify.html` enforces:
  ```javascript
  function trustedAuditorContext() {
      if (typeof location === 'undefined') return true; // Headless test harness
      if (location.protocol === 'file:') return true;   // Local air-gapped file
      return location.host === 'leonardopedro.github.io'; // Pinned GitHub Pages
  }
  ```
* If opened from the enclave origin, key generation is blocked, and the page displays an explicit security warning directing the user to run the auditor locally.

### 6.2 Dual-Slot Hardware Binding
1. **Pre-Flight Commitment**:
   `REPORTDATA[0..32]` binds the enclave public key, client public key, client nonce, PKCE code challenge, user custom info, and the approved PayPal App ID [2].
2. **Post-Login Commitment**:
   - `REPORTDATA[0..32]` binds the PayPal identity hash (`sec02_nonce`).
   - `REPORTDATA[32..64]` binds `SHA-256(P_client || Nonce_client)`.
   - **No Wildcard Verification**: Remove `tdxBindingLoose32` from `verify.html`. The auditor must verify both 32-byte slots against the local session parameters. Replaying a quote from a previous user's session fails closed.

---

## 7. Enclave Runtime Hardening (Alibaba Cloud Specifics)

### 7.1 Post-Boot Firewall Lockdown (`src/main.rs`)
At boot, egress is required for Alibaba Cloud IMDS (`100.100.100.200:80`) to fetch `user_data` and Cloudflare DNS-01 ACME to issue TLS certificates [2]. Once the certificate is in memory and serving begins:
```rust
pub fn egress_lockdown() {
    kmsg("POST-BOOT EGRESS LOCKDOWN: Restricting egress strictly to PayPal API on 443...");
    let commands = [
        "flush chain inet filter output",
        "add rule inet filter output oif lo accept",
        "add rule inet filter output ct state established,related accept",
        // Pinned PayPal API endpoints (api-m.paypal.com / api-m.sandbox.paypal.com)
        "add rule inet filter output ip daddr { 104.16.124.74, 146.75.123.1 } tcp dport 443 accept",
        // Drop all other outbound packets, including IMDS (100.100.100.200), DNS (53), and port 80
        "add rule inet filter output drop",
    ];
    for cmd in commands {
        let _ = std::process::Command::new("/usr/sbin/nft").arg(cmd).status();
    }
}
```

### 7.2 In-Guest Kernel Hardening (`enclave_init::harden_kernel`)
* **Permanent Swapoff**: `libc::swapoff()` ensures private TDX memory pages are never swapped to unencrypted host disks.
* **Kernel Execution Lockdown**: Set `/proc/sys/kernel/kexec_load_disabled = 1`.
* **Block Core Dumps**: Set `/proc/sys/fs/suid_dumpable = 0` and `setrlimit(RLIMIT_CORE, 0)`.
* **Memory Scrubbing**: All intermediate OAuth tokens, PayPal response strings, and derived symmetric keys are zeroized (`zeroize_str`) immediately after encryption.

### 7.3 Boot-Time CCEL Replay Gate (`src/intel_tdx.rs`)
Before accepting network traffic, `/init` reads `/sys/firmware/acpi/tables/data/CCEL` (Alibaba Cloud CC Event Log), replays the SHA-384 extend sequence, and compares the result against the live hardware quote's `RTMR0..3` [1]. Any discrepancy triggers `enclave_init::poweroff()`.

---

## 8. CI/CD, Tooling & Operational Workflow

### 8.1 Offline Measurement & Pin Tooling (`scripts/calculate-golden-rtmr.mjs`)
The golden pins in `verify.html` must be derived from verified hardware quotes:
```bash
# Capture live hardware quote from test enclave
curl -sk https://login.airma.de/debug/envelope > /tmp/envelope.json

# Extract MRTD and RTMR0..3, verify CCEL replay, and update verify.html pins
node scripts/calculate-golden-rtmr.mjs --report /tmp/envelope.json --update
```

### 8.2 Deployment Sequence for Binary Rotations
1. **Build Deterministic Disk**:
   ```bash
   bash build-alibaba-docker.sh
   ```
2. **Transfer via Minimal Economic Relay**:
   - Presigned upload to Hong Kong relay bucket (`oss-cn-hongkong`).
   - Relay pulls from HK and uploads to Beijing intranet bucket (`oss-cn-beijing-internal`).
   - Relay instance powers off immediately (`StopCharging` economy mode) [2].
3. **In-Place Disk Rewrite on ECS**:
   - Import image via `ImportImage` (flat `--DiskDeviceMapping.1.Format raw`).
   - Set NVMe support: `ModifyImageAttribute --Features.NvmeSupport supported`.
   - Rewrite system disk in place: `StopInstance` $\rightarrow$ `ReplaceSystemDisk --SystemDisk.Size 1 --SystemDisk.Category cloud_auto --ImageId <new_image>` $\rightarrow$ `StartInstance` [2].
   - **Preserves Reserved EIP**: Retains `101.200.178.251` (required for Cloudflare DNS-01 ACME authorization) [2].
4. **Update Golden Pins & Publish**:
   - Query `/debug/envelope`, run `calculate-golden-rtmr.mjs --update`.
   - Update `verify.html` SHA-256 digest and byte size in `README.md`.
   - Run security test suite:
     ```bash
     npm test
     ```
   - Commit `verify.html` and `README.md` together.

---

## 9. Threat Mitigation Matrix (Pure-Play TDX)

| Attack Scenario | Colluding Adversary Action | Defense Mechanism | Result |
| :--- | :--- | :--- | :--- |
| **Disk/Initramfs Injection** | Host alters `/init` inside `initrd.img` on virtual disk to log tokens. | GRUB 2.12 measures kernel + initrd into `RTMR2`. `verify.html` enforces `RTMR2 == EXPECTED_RTMR2`. | **Audit Fails Closed**: Quote carries altered `RTMR2`. Client halts before login. |
| **Cross-Cloud Quote Substitution** | Owner/Host presents an AMD SEV-SNP quote from an Oracle Cloud VM. | `verify.html` demands Intel TDX quote (`claimsTdx`) and rejects AMD/OCI evidence. | **Replay Blocked**: Non-TDX quote rejected immediately. |
| **TLS MITM by Owner** | Owner terminates TLS on load balancer using domain certificate. | Report is encrypted with $\text{AES-256-GCM}_K$ where $K = \text{HKDF}(\text{ECDH}(P_{client}, S_{enclave}))$. | **Data Unreadable**: Adversaries capture only high-entropy ciphertext. $S_{client}$ never left user's browser. |
| **Web Auditor Hijacking** | Host modifies `verify.html` on the ESP partition to suppress errors. | `trustedAuditorContext()` disables key generation on `login.airma.de`. User runs auditor on `file://` or GitHub Pages. | **Script Injection Defeated**: Untrusted host filesystem bypassed completely. |
| **Session Quote Replay** | Host replays an honest hardware quote from another user's session. | Callback quote binds $P_{client} \parallel Nonce_{client}$ into $\text{REPORTDATA}[32..64]$. Auditor enforces both slots. | **Substitution Blocked**: Replayed quote carries mismatched client session digest. |
| **Post-Boot Exfiltration** | Malicious dependency attempts to send tokens to external IP or IMDS. | `egress_lockdown()` drops all egress except port 443 to PayPal's pinned IPs. IMDS and DNS blocked post-boot. | **Exfiltration Blocked**: Outbound packets dropped at kernel netfilter boundary. |
