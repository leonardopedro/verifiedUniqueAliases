# GCP Confidential Auth VM — Reproducible & Attested

Hardware-attested PayPal OAuth service on **GCP Confidential Space** (AMD SEV-SNP).
Built for 100% bit-by-bit reproducibility and maximum security.

---

## 🚀 Current Status (v28+)

| Component | Status |
|---|---|
| Bitwise Reproducibility (`disk.raw`, `disk.tar.gz`, `qcow2`) | ✅ Achieved |
| Systemd-Free Initramfs (no switch-root freeze) | ✅ Achieved |
| Incremental Docker Build Cache | ✅ Achieved |
| GCP Secure Boot (signed Shim/GRUB) | ✅ Configured |
| GCP UEFI Boot from custom image | ✅ Achieved |

### Reproducibility Strategy
The full **extract → normalize → rebuild** pipeline ensures bitwise identity:

1. **ESP Build**: Create FAT32 image with `mkfs.vfat --invariant` (removes all time/random metadata)
2. **Extraction**: Copy all EFI files out with normalized `SOURCE_DATE_EPOCH` timestamps
3. **Sorted Reinsertion**: Re-insert files into a fresh `--invariant` FAT image in deterministic order
4. **GPT Assembly**: `sfdisk` with fixed Disk/Partition UUIDs (`00000000-...`)
5. **Final Normalization**: `add-det` on the assembled raw, qcow2, and tar.gz


---

## 🏗️ Build & Reproduce

```bash
# 1. Build builder image (Rust deps cached — fast incremental rebuilds)
docker build -t paypal-builder-v28 .

# 2. Extract artifacts
docker create --name tmp paypal-builder-v28
docker cp tmp:/img/. ./output/
docker rm tmp

# 3. Synthesize the reproducible disk stack
./build-gcp-gpt-image.sh

# 4. Verify reproducibility (run twice, compare hashes)
./build-gcp-gpt-image.sh && sha256sum disk.raw disk.tar.gz paypal-auth-vm-gcp.qcow2
```

## 🚢 Deployment

```bash
gsutil cp disk.tar.gz gs://project-ae136ba1-3cc9-42cf-a48-images/
sh deploy_final.sh
```

## 📂 Repository Structure

| File | Purpose |
|---|---|
| `Dockerfile` | Multi-stage builder with dependency caching |
| `build-gcp-gpt-image.sh` | Bitwise-reproducible GPT disk synthesis |
| `build-initramfs-tools.sh` | initramfs-tools based buildup (Ubuntu native) |
| `deploy_final.sh` | GCP image registration + VM launch |
| `hooks/` / `scripts/` | initramfs-tools native hooks/pre-mount logic |
| `legacy/` | Deprecated OCI/Nix build scripts |

## 🔐 Security Architecture

- **Kernel**: `linux-image-gcp` (GVNIC + SEV-SNP support)
- **Secure Boot**: Pre-signed Canonical Shim (`shimx64.efi`) + GRUB binaries
- **Attestation**: PCR 15 measures the Rust binary at boot
- **Secrets**: Fetched from GCP Metadata Server via `tee-env-*` attributes (never on disk)
- **Confidential Compute**: AMD SEV-SNP on `n2d-highcpu-2`