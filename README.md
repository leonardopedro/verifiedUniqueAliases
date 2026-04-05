# GCP Confidential Auth VM — Reproducible & Attested

Hardware-attested PayPal OAuth service on **GCP Confidential Space** (AMD SEV-SNP).
Built for 100% bit-by-bit reproducibility and maximum security.

---

## 🚀 Current Status (v28+)

| Component | Status |
|---|---|
| Bitwise Reproducibility (`disk.raw`, `disk.tar.gz`, `qcow2`) | ✅ Achieved |
| Native PID 1 Rust Launcher & Boot Isolation | ✅ Achieved |
| Native Rust DHCP / Network Management | ✅ Achieved |
| GCP Secure Boot (signed Shim/GRUB) | ✅ Achieved |
| GCP UEFI Boot from custom image | ✅ Achieved |

### Architectural Breakthrough: Native PID 1 Rust Integration
The service takes complete control of the OS from the very first instruction. It runs perfectly isolated on GCP Confidential Space without any shell dependencies:
- **No `systemd` or standard `/init` scripts.**
- **Filesystem Setup**: Rust uses the `nix` crate to natively mount `/proc`, `/sys`, and `/dev` virtual filesystems.
- **Kernel Drivers**: Rust natively performs `modprobe` for the `gve` (GCP Virtual Ethernet) and `virtio_net` drivers.
- **Network Stack**: No shell or `klibc-utils`. Rust performs a complete DHCP exchange (`DISCOVER -> OFFER -> REQUEST -> ACK`) via raw UDP sockets, parsing and applying the lease using `iproute2`.
  - *Layer 3 Broadcast Bypass*: Implements `libc::setsockopt(SO_BINDTODEVICE)` to successfully broadcast UDP DHCP packets without an existing routing table.
  - *GCP /32 Subnet Routing*: Automatically injects device-bound host routes to circumvent Google Cloud's off-subnet gateway architecture.
- **Native Diagnostic Logging**: Bypasses `eprintln!` standard output restrictions by writing all PID 1 boot diagnostics directly to the kernel ring buffer (`/dev/kmsg`), guaranteeing persistent GCP Serial Console logs.

### Reproducibility Strategy
The full **extract → normalize → rebuild** pipeline ensures bitwise identity:

1. **ESP Build**: Create FAT32 image with `mkfs.vfat --invariant` (removes all time/random metadata)
2. **Initramfs Hook**: Copies the Rust binary + GLIBC shared objects deterministically using `copy_exec` directly to `/init`.
3. **Extraction**: Copy all EFI files out with normalized `SOURCE_DATE_EPOCH` timestamps
4. **Sorted Reinsertion**: Re-insert files into a fresh `--invariant` FAT image in deterministic order
5. **GPT Assembly**: `sfdisk` with fixed Disk/Partition UUIDs (`00000000-...`)

---

## 🏗️ Build Architecture & Workflow

To maintain exact EFI/Kernel Secure Boot signatures matching GCP infrastructure, the build process is split into two phases:

1. **Local Compilation**: The Rust binary is compiled locally.
2. **Remote Synthesis**: The native `mkinitramfs` and GPT disk assembly run on a dedicated Google Cloud build VM (`build-vm-paypal-n2d`) running the identical OS (`Ubuntu 25.10`) and kernel as the target.

```bash
# 1. Compile Rust Binary Locally targetting x86_64 Linux
cargo build --release --target x86_64-unknown-linux-gnu

# 2. Sync binary & scripts to the GCP Build VM
gcloud compute scp ./target/x86_64-unknown-linux-gnu/release/paypal-auth-vm build-vm-paypal-n2d:/tmp/paypal-auth-vm-bin
gcloud compute scp hooks/ build-initramfs-tools.sh build-gcp-gpt-image.sh build-vm-paypal-n2d:~ --recurse

# 3. Synthesize the Reproducible Disk on the Build VM
gcloud compute ssh build-vm-paypal-n2d \
  --command="sudo ./build-initramfs-tools.sh && ./build-gcp-gpt-image.sh"

# 4. Download final reproducible disk for deployment
gcloud compute scp build-vm-paypal-n2d:~/disk.tar.gz ./disk.tar.gz
```

## 🚢 Deployment

**Note**: Deployments should run from an environment with IAM privileges for `storage.objects.create`, `compute.instances.create`, and `compute.images.create`.

```bash
gsutil cp disk.tar.gz gs://[YOUR_PROJECT_BUCKET]/
sh deploy_final.sh
```

## ⏭️ Next Steps for Developers

Now that the lowest-level OS bootstrapping, driver loading, network routing, and Secure Boot attestation are perfectly solved, the task switches fully to higher-level service logic:

1. **Attestation & TLS**: Implement logic using the bundled `tpm2_...` tools. The hook copies them into the RAM disk. They must be used by the Rust environment to request ACME TLS certificates and handle caching.
2. **OAuth Flow**: Complete the PayPal OAuth user experience handled via `axum`. Manage redirect mechanisms properly.
3. **Secret Manager Hookup**: The service receives the GCP Secret Manager path via `tee-env-SECRET_NAME`. Retrieve the `PAYPAL_AUTH_CONFIG` payload correctly and deserialize it.

## 📂 Repository Structure

| File | Purpose |
|---|---|
| `src/main.rs` | Rust backend (Contains `enclave_init` PID 1 logic handler + Axum web logic) |
| `hooks/paypal-auth` | `initramfs-tools` hook that bundles the Rust app as `/init` alongside `tpm2_tools` |
| `Dockerfile` | Multi-stage builder with dependency caching |
| `build-gcp-gpt-image.sh` | Bitwise-reproducible GPT disk synthesis |
| `build-initramfs-tools.sh` | initramfs-tools based buildup (Ubuntu native) |
| `deploy_final.sh` | GCP image registration + VM launch |