# AGENTS.md - Status Guidelines for GCP Confidential Auth VM

## Project Overview
`paypal-auth-vm` is a hardware-attested Rust service on **GCP Confidential VM** (AMD SEV-SNP). It provides a secure bridge for PayPal OAuth tokens, ensuring the integrity of the computing environment before secrets are accessible.

### 🏆 Current Accomplishments (v120)
- **Hardened TPM Quote Verification**: Full binary parsing of `TPMS_ATTEST` in the auditor verifies the hardware-signed nonce directly from the raw TPM quote message, neutralizing session replay and forgery attacks.
- **PCR 15 Software Binding**: Strict verification of the `disk_manifest` hash against hardware PCR 15, ensuring the code running on the silicon matches the GitHub provenance.
- **PCR Composite Digest**: The auditor manually reconstructs the expected SHA-256 hash of all quoted PCRs (0, 4, 8, 9, 15) and verifies it against the value in the signed `TPMS_ATTEST` structure.
- **Unified Hardware Anchor (Hybrid)**: The Silicon Root of Trust now correctly handles both native **AMD SEV-SNP binary reports** and **Google AK Certificates (DER-encoded X.509)**. Detection is based on ASN.1 magic bytes (`0x30 0x82`), and verification checks for Google's Private Enterprise Number OID (`d679` in DER) and ASCII "Google" strings embedded in the certificate.
- **Egress & Metadata Hardening**: Eliminated hypervisor-controlled environment injection and enforced TLS pinning (embedded `google_ca.pem` and `paypal.pem`) for all sensitive configuration and time synchronization fetches.
- **Secure Time Synchronization**: Pinned HTTPS-based time fetching with RTC pre-seeding to the build epoch (April 6, 2026) prevents TLS rollback and clock spoofing attacks.
- **Stable OS (Trixie)**: Build system, kernel, and initramfs pinned to **Debian 13 (Trixie)** using snapshot.debian.org.

## Unified Synthesis Pipeline (v120)
To ensure 100% bitwise reproducibility regardless of the host build environment, the project uses a multi-stage Docker synthesis engine (`Dockerfile.repro`).
1. **Phase 0: EAB Rotation**: `deploy-gcp.sh` rotates ACME credentials before the build.
2. **Stage 1: Rust Builder**: Compiles the source for `x86_64-unknown-linux-gnu` using stable Rust toolchains on Debian Trixie.
3. **Stage 2: Image Builder**: Uses a fixed Debian snapshot to bundle the kernel, bootloaders, and initramfs. Includes `tsm` and `amd_tsm` kernel modules for hardware attestation.
4. **Verification**: Compares local synthesis hashes against the GitHub provenance ledger.

## Security Architecture
- **Hardware-Anchored Trust**:
  - **SNP Launch Measurement / Google AK Cert**: Verified against physical hardware (AMD SEV-SNP report or Google-signed TPM EK/AK Certificate from NVRAM).
  - **Measured Boot**: PCRs 0, 4, 8, 9, 15 provide full-stack coverage verified by TPM quote.
  - **Embedded TLS Pinning**: `google_ca.pem` and `paypal.pem` are compiled directly into the binary via `include_bytes!`, preventing filesystem-level tampering.
- **Resource Isolation**: Connection dropping and bandwidth throttling at entry points protect the native Rust state.
- **PID 1 Isolation**: No shell, no userspace utilities except specifically whitelisted binaries.

## Cryptographic Chain of Trust
```
GitHub Provenance
    └─► PCR 15 (disk_manifest SHA-256 measured into TPM at boot)
            └─► PCR Composite Hash (SHA-256 of all quoted PCRs 0,4,8,9,15)
                    └─► TPMS_ATTEST binary (signed by AK over PCR composite + session nonce)
                            └─► Google AK Certificate (DER X.509, Google-issued, proves AK is GCP hardware-bound)
                                    └─► Session Nonce (SHA-256[PayPal User Hash ∥ Enclave PubKey Hash])
```

## Verification Workflow (v120 Auditor)
The system provides a signed **Remote Attestation Report** on the OAuth callback page.
1. **Local verification**: Users are encouraged to download the report and `verify.html` for local, air-gapped verification to eliminate web-vector trust.
2. **GitHub Audit**: Automatically fetches Sigstore provenance from GitHub and verifies the **Atomic Run ID** across all components (binary, kernel, initramfs, bootloader).
3. **Silicon Audit**: Detects hardware proof format (DER AK Cert vs. raw SNP report) by inspecting ASN.1 magic bytes. For Google AK Certs, verifies the Google PEN OID (`1.3.6.1.4.1.11129.*`) is present in DER and displays full decoded identity strings (issuer, subject, zone, project, instance name).
4. **Disk Audit**: Compares the live `disk_manifest` (SHA-256 of every EFI file) against signed CI hashes. Verifies the expected PCR 15 value matches hardware.
5. **TPM Proof**: Binary-parses `TPMS_ATTEST` (magic `0xFF544347`, type `0x8018`) to extract `extraData` (nonce) and `pcrDigest`. Verifies the AK RSA-2048 signature over the raw quote message using WebCrypto.

## Known Constraints & Notes
- **`/dev/sev-guest` is MISSING on current GCP Confidential VMs**: The kernel exposes the TSM ConfigFS interface instead. The enclave attempts `configfs` first, then falls back to TPM NVRAM indices for the hardware report.
- **EK Certificate ≠ Session AK**: The `snp_report_b64` field contains the Google-issued EK/AK CA certificate (for the hardware-bound TPM key), not the ephemeral session AK. The session AK is a fresh RSA-2048 key generated per attestation.
- **Nonce Binding**: The session nonce is `SHA-256(SHA-256(PayPal user JSON) ∥ SHA-256(enclave public key DER))`. The TPM quote's `extraData` field must contain this nonce for the audit to pass.
