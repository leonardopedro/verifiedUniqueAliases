An implementation plan is detailed below to upgrade the hardware verification architecture on the `alibabacloud` branch (Intel TDX on Alibaba Cloud ECS) [1]. It addresses the threat model where **the webservice owner, Alibaba Cloud, and an external cloud (such as Oracle Cloud) collude** [2].

---

### 1. Threat Model & Collusion Vector Analysis

```
┌───────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   COLLUSION ATTACK VECTORS                                    │
├───────────────────────────────────────────────────────────────────────────────────────────────┤
│ 1. Malicious Owner: Controls PayPal Client Secret, domain TLS, DNS-01, and git push.          │
│ 2. Malicious Host:  Controls QEMU/KVM hypervisor, disk storage (ESP/GPT), and virtual NIC.   │
│ 3. Oracle Cloud:   Hostile external relay/infrastructure (shares keys/collusion channel).     │
│ 4. Intel Hardware: CPU, SEAM, and Intel DCAP PCK PKI are GENUINE and UNCOMPROMISED.          │
└───────────────────────────────────────────────────────────────────────────────────────────────┘
```

#### The Residual Flaws in the Current Implementation
1. **Unmeasured Shim/GRUB Chain**:
   `build-alibaba-image.sh` still packages separate files (`BOOTX64.EFI` shim, `grubx64.efi`, `vmlinuz`, `initrd.img`, and `grub.cfg`) on an unencrypted FAT32 ESP. While GRUB 2.12 extends measurements into `RTMR2`, GRUB’s internal runtime execution flow, modules, and secondary commands can be manipulated by an untrusted host unless packaged into a single cryptographically atomic, measured binary (Unified Kernel Image).
2. **Pre-flight vs. Post-Callback Quote Binding Discrepancy**:
   In `src/main.rs`:
   - At pre-flight (`/attest/preflight`), the quote binds the client session:
     $$\text{REPORTDATA}[0..32] = \text{SHA-256}(P_{enc} \parallel \text{code\_challenge} \parallel P_{client} \parallel Nonce_{client} \parallel \text{custom\_info} \parallel \text{PayPal\_Client\_ID})$$
   - At callback (`/callback`), the quote binds `sec02_nonce`:
     $$\text{sec02\_nonce} = \text{SHA-256}(\text{paypal\_hash} \parallel P_{enc} \parallel \text{custom\_info} \parallel \text{binary\_sha256} \parallel \text{manifest\_hash})$$
   **The Vulnerability**: The callback hardware quote does *not* directly bind $Nonce_{client}$ or $P_{client}$ in its hardware $\text{REPORTDATA}$. It relies on AES-256-GCM encryption with $K = \text{HKDF}(\text{ECDH}(S_{enc}, P_{client}), Nonce_{client})$. If a colluding host records or intercepts an old hardware quote from another session, the quote itself does not commit to the active client session key.
3. **IMDS Side-Channel & Late Firewall Lockdown**:
   Alibaba Cloud IMDS (`100.100.100.200:80`) is left accessible throughout initial boot and ACME negotiation [2]. If an attacker controls the DNS-01 ACME channel, they can induce delays, during which malicious runtime calls could interact with IMDS.
4. **Alibaba Cloud TDX PCCS Dependency**:
   When using Alibaba Cloud's VPC PCCS endpoint (`https://sgx-dcap-server-vpc.${region_id}.aliyuncs.com/sgx/certification/v4/`), network egress to this internal VPC endpoint must be whitelisted specifically, rather than relying on general network rules [1].

---

### 2. Architectural Solution Overview

```
┌───────────────────────────────────────────────────────────────────────────────────────────────┐
│                          COLLUSION-PROOF INTEL TDX ATTESTATION MODEL                          │
├───────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                               │
│  [1] BUILD TIME (Deterministic Multi-Stage Docker)                                            │
│      systemd-stub + vmlinuz + initrd (PID 1 /init) + locked cmdline                          │
│      └─► Monolithic UKI: output-alibaba/BOOTX64.EFI                                          │
│                                                                                               │
│  [2] BOOT TIME (Alibaba Cloud ECS TDX Instance)                                               │
│      TDVF (EDK2) measures BOOTX64.EFI via EFI CC Protocol ──► RTMR1                           │
│      Kernel /init mounts encrypted RAM, executes swapoff, and seals kexec                     │
│      Replays ACPI CCEL Event Log (/sys/firmware/acpi/tables/data/CCEL) ──► Replay == Quote    │
│      Drops all firewall egress except:                                                        │
│        - Boot: Cloudflare DNS-01 & ACME                                                       │
│        - Runtime: Port 443 to PayPal pinned IPs (104.16.124.74, 146.75.123.1) only           │
│                                                                                               │
│  [3] USER SESSION (file:// or GitHub Pages Local Auditor)                                     │
│      Client generates (P_cli, S_cli) and Nonce_cli (32 random bytes)                          │
│      Pre-flight Quote: REPORTDATA binds (P_enc, P_cli, Nonce_cli, PKCE, App_ID)               │
│      Callback Quote:   REPORTDATA binds (P_enc, P_cli, Nonce_cli, Paypal_Hash, App_ID)         │
│      Auditor verifies:                                                                        │
│        * Intel DCAP PCK Certificate Chain reaches Pinned Intel Root CA                        │
│        * MRTD  == PINNED_MRTD                                                                 │
│        * RTMR1 == PINNED_RTMR1 (Monolithic UKI Hash)                                          │
│        * RTMR2 == PINNED_RTMR2                                                                │
│        * REPORTDATA == Client-Expected 32-byte session digest                                 │
│        * Ciphertext payload decrypts with K = HKDF(ECDH(S_cli, P_enc), Nonce_cli)             │
│                                                                                               │
└───────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 3. Step-by-Step Implementation Plan

#### Phase 1: Direct Monolithic UKI Assembly (Eliminating GRUB)

Replace the multi-file GRUB boot chain with a single **Unified Kernel Image (UKI)** directly loaded by Alibaba Cloud's TDVF as `/EFI/BOOT/BOOTX64.EFI`.

1. **Update `Dockerfile.alibaba`**:
   Install `systemd-boot-efi` or `binutils` to provide `linuxx64.efi.stub`:
   ```dockerfile
   RUN apt-get update && apt-get install -y --no-install-recommends \
       systemd-boot-efi binutils dosfstools mtools parted fdisk coreutils
   ```

2. **Update `build-alibaba-image.sh` to Build the UKI**:
   Construct the monolithic UKI that embeds the kernel, initramfs, and immutable kernel command line into a single PE image:
   ```bash
   CMDLINE="console=tty0 console=ttyS0,115200n8 net.ifnames=0 biosdevname=0 swiotlb=524288 quiet panic=1"
   echo -n "$CMDLINE" > /tmp/cmdline.txt

   # Synthesize the Unified Kernel Image (UKI)
   objcopy \
       --add-section .osrel="/etc/os-release" --change-section-vma .osrel=0x20000 \
       --add-section .cmdline="/tmp/cmdline.txt" --change-section-vma .cmdline=0x30000 \
       --add-section .linux="$KERNEL" --change-section-vma .linux=0x40000 \
       --add-section .initrd="$INITRD" --change-section-vma .initrd=0x3000000 \
       /usr/lib/systemd/boot/efi/linuxx64.efi.stub \
       "$OUTPUT_DIR/BOOTX64.EFI"

   # Populate the FAT32 ESP partition with ONLY BOOTX64.EFI
   truncate -s 64M "$ESP_IMAGE"
   mkfs.vfat -F 32 -i 12345678 --invariant -n "EFI" "$ESP_IMAGE"
   mmd -i "$ESP_IMAGE" ::/EFI
   mmd -i "$ESP_IMAGE" ::/EFI/BOOT
   mcopy -i "$ESP_IMAGE" "$OUTPUT_DIR/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
   ```
   **Security Gain**: When Alibaba Cloud TDVF loads `BOOTX64.EFI`, the UEFI CC Measurement Protocol hashes the entire composite UKI into **`RTMR1`**. Any modification by the cloud provider to the kernel, initramfs, `/init`, or command line produces a mismatch in `RTMR1`.

---

#### Phase 2: Dual-Stage Hardware Quote Session Binding

Bind the client’s session parameters directly into the hardware quote's $\text{REPORTDATA}$ at **both** pre-flight and callback stages.

1. **Unify Pre-Flight and Post-Login Binding in `src/main.rs`**:
   At pre-flight:
   $$\text{REPORTDATA}_{\text{preflight}}[0..32] = \text{SHA-256}(P_{enc} \parallel \text{code\_challenge} \parallel P_{client} \parallel Nonce_{client} \parallel \text{custom\_info} \parallel \text{PayPal\_Client\_ID})$$

   At callback (post-login):
   Modify `callback()` in `src/main.rs` so the hardware quote directly binds $P_{client}$ and $Nonce_{client}$ alongside the user info hash:
   $$\text{REPORTDATA}_{\text{callback}}[0..32] = \text{SHA-256}(P_{enc} \parallel \text{paypal\_user\_info\_raw\_hash} \parallel P_{client} \parallel Nonce_{client} \parallel \text{custom\_info} \parallel \text{PayPal\_Client\_ID})$$

   ```rust
   // In src/main.rs inside callback():
   let mut callback_hasher = Sha256::new();
   callback_hasher.update(&state.enclave_identity.pubkey_der);
   callback_hasher.update(hex::decode(&paypal_user_raw_hash).unwrap_or_default());
   callback_hasher.update(&pkce.client_ecdh_pub);
   callback_hasher.update(&pkce.client_nonce);
   callback_hasher.update(custom_info.as_bytes());
   callback_hasher.update(cid.as_bytes());
   let callback_digest = callback_hasher.finalize();

   let mut report_data = [0u8; 64];
   report_data[0..32].copy_from_slice(&callback_digest);
   let quote_res = tpm::quote(&hex::encode(&callback_digest), Some(report_data));
   ```

2. **Fail-Closed Hardware Quote Verification in `src/main.rs`**:
   Remove any permissive fallback. If a valid hardware-signed TDX quote is not produced, reject the operation immediately:
   ```rust
   if quote_res.tdx_quote_b64.is_none() {
       error!("FAIL-CLOSED: TDX quote generation failed. Halting.");
       enclave_init::poweroff();
   }
   ```

---

#### Phase 3: Runtime Egress Lockdown & Memory Scrubbing

Prevent post-boot exfiltration of user data by a colluding cloud provider or host hypervisor.

1. **Firewall Lockdown Post-ACME in `src/main.rs`**:
   Immediately after obtaining the TLS certificate in RAM and before accepting incoming HTTP/HTTPS connections, drop all unnecessary egress rules:
   ```rust
   pub fn egress_lockdown() {
       kmsg("POST-BOOT EGRESS LOCKDOWN: Restricting egress to PayPal pinned IPs on 443 only...");
       let commands = [
           "flush chain inet filter output",
           "add rule inet filter output oif lo accept",
           "add rule inet filter output ct state established,related accept",
           // Allow ONLY PayPal Production & Sandbox API IPs on 443
           "add rule inet filter output ip daddr { 104.16.124.74, 146.75.123.1 } tcp dport 443 accept",
           // Explicitly drop all other egress
           "add rule inet filter output drop",
       ];
       for cmd in commands {
           let _ = std::process::Command::new("/usr/sbin/nft").arg(cmd).status();
       }
   }
   ```
   **Security Gain**: Any exfiltration attempt to external server addresses, DNS tunneling, or Alibaba Cloud IMDS (`100.100.100.200`) is dropped at the netfilter boundary.

2. **Explicit Memory Scrubbing**:
   In `src/main.rs`:
   - Zeroize OAuth tokens (`token_obj.access_token`), intermediate user info, and derived AES-GCM session keys immediately after use using `zeroize_str()` and `zeroize()`.
   - Ensure the process disables core dumps (`prctl(PR_SET_DUMPABLE, 0)`) and disables swap (`libc::swapoff`).

---

#### Phase 4: Local Client Auditor (`verify.html`) Updates

To eliminate the "Web Auditor Tampering" attack (where a malicious owner serves backdoored JavaScript from `login.airma.de`):

1. **Auditor Origin Isolation**:
   `verify.html` must refuse key-generation and pre-flight flows when loaded from the enclave’s origin (`https://login.airma.de`). It must mandate execution from:
   - `file:///path/to/verify.html`, or
   - `https://leonardopedro.github.io/verifiedUniqueAliases/verify.html`

2. **Update Hardware Pins in `verify.html`**:
   Update `EXPECTED_RTMR1` to match the golden monolithic UKI SHA-384 digest:
   ```javascript
   var EXPECTED_MRTD  = "<PINNED_TDVF_BUILD_MEASUREMENT>";
   var EXPECTED_RTMR0 = "<PINNED_TDVF_CONFIG_MEASUREMENT>";
   var EXPECTED_RTMR1 = "<PINNED_MONOLITHIC_UKI_MEASUREMENT>";
   var EXPECTED_RTMR2 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
   var EXPECTED_RTMR3 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
   ```

3. **Verify Callback Dual-Binding**:
   In `runAudit()` in `verify.html`, verify that the callback quote’s $\text{REPORTDATA}[0..32]$ matches:
   ```javascript
   const recomputedCallbackDigest = toHexLc(new Uint8Array(await crypto.subtle.digest(
       'SHA-256',
       concat(
           pubKeyBuffer,
           fromHex(recomputedPaypalHash),
           b64ToDer(pfCtx.client_pub_b64),
           fromHex(pfCtx.client_nonce_hex),
           new TextEncoder().encode(report.custom_info || 'NONE'),
           new TextEncoder().encode(report.paypal_client_id || '')
       )
   )));

   if (qReportDataHex.slice(0, 64) !== recomputedCallbackDigest) {
       throw new Error("CALLBACK HARDWARE QUOTE BINDING VIOLATION: Hardware quote does not match client session and PayPal identity!");
   }
   ```

---

#### Phase 5: Automated Golden Measurement Tooling & CI Integration

1. **Enhance `scripts/calculate-golden-rtmr.mjs`**:
   - Add direct UKI measurement calculation by hashing the PE sections of `BOOTX64.EFI` according to the UEFI CC Event Log specification:
     $$\text{RTMR1}_{\text{initial}} = \text{SHA-384}(0^{48} \parallel \text{SHA-384}(\text{BOOTX64.EFI}))$$
   - Add a command to verify live reports against the calculated golden pins:
     ```bash
     node scripts/calculate-golden-rtmr.mjs --report /tmp/report.json --check-pins
     ```

2. **Automate Sigstore Provenance in `.github/workflows/build-attest.yml`**:
   - Attest `output-alibaba/BOOTX64.EFI` and `output-alibaba/disk-alibaba.raw` in GitHub Actions Sigstore.
   - Verify that the CI-calculated `RTMR1` matches the constant in `verify.html` in an automated test step (`npm test`).

---

### 4. Security Verification Checklist

| Test Scenario | Attack Method | Expected Result |
| :--- | :--- | :--- |
| **Disk Injection** | Colluding host modifies `/init` on virtual disk to log tokens. | UKI hash changes $\rightarrow$ `RTMR1` changes $\rightarrow$ `verify.html` fails closed on `RTMR1` pin mismatch. |
| **TLS MITM** | Owner terminates TLS on load balancer / proxy. | Wire traffic is encrypted with $\text{AES-256-GCM}_K$, where $K = \text{HKDF}(\text{ECDH}(S_{client}, P_{enclave}))$. Owner sees only ciphertext; cannot decrypt without $S_{client}$. |
| **Session Swap** | Host tries to replay an old hardware quote from another user. | Hardware quote $\text{REPORTDATA}$ binds $Nonce_{client}$ and $P_{client}$. Stale quote has mismatched $\text{REPORTDATA} \rightarrow$ rejected. |
| **Over-Scoped App** | Owner injects malicious PayPal Client ID with PII scopes. | Hardware quote binds `PayPal_Client_ID`. `verify.html` verifies `EXPECTED_APPS` $\rightarrow$ fails closed. |
| **Egress Exfiltration** | Attacker tries to leak memory via IMDS (`100.100.100.200:80`) or outbound socket. | `egress_lockdown()` drops all traffic except port 443 to PayPal pinned IPs (`104.16.124.74`, `146.75.123.1`) $\rightarrow$ packets dropped. |
| **Auditor Spoofing** | Host serves modified `verify.html` from `https://login.airma.de/`. | `trustedAuditorContext()` detects origin $\ne$ `file://` / GitHub Pages $\rightarrow$ refuses key generation. |
