# Native Build for Firebase Studio

This document explains how to build the initramfs and qcow2 image directly in firebase.studio without QEMU, Docker, or Podman.

## Prerequisites

The `dev.nix` file has been configured with all necessary packages:
- GRUB2 bootloader tools
- Disk partitioning utilities (parted)
- Filesystem tools (e2fsprogs, dosfstools)
- QEMU tools (for qemu-img)
- Dracut and kernel packages
- Rust toolchain and build dependencies

## Quick Start

Simply run the native build script:

```bash
./build-native.sh
```

This will:
1. Build the Rust binary with reproducibility flags
2. Prepare the dracut module
3. Build the initramfs image
4. Create a bootable qcow2 disk image
5. Generate checksums and build manifest

## Output Files

- `initramfs-paypal-auth.img` - The initramfs image
- `initramfs-paypal-auth.img.sha256` - SHA256 checksum
- `paypal-auth-vm.qcow2` - Bootable VM image
- `paypal-auth-vm.qcow2.sha256` - SHA256 checksum
- `build-manifest.json` - Build metadata for reproducibility

## Reproducibility

The build process is designed for reproducibility:
- Fixed `SOURCE_DATE_EPOCH` timestamp
- Consistent build flags (`RUSTFLAGS`, `CARGO_PROFILE_*`)
- Normalized timestamps on all files
- `add-determinism` tool for binary normalization
- Build manifest records exact package versions

### Checking Reproducibility

To verify builds are reproducible:

```bash
# First build
./build-native.sh
cp initramfs-paypal-auth.img.sha256 build1.sha256

# Clean and rebuild
rm -f initramfs-paypal-auth.img paypal-auth-vm.qcow2
./build-native.sh
cp initramfs-paypal-auth.img.sha256 build2.sha256

# Compare
diff build1.sha256 build2.sha256
```

If the SHA256 hashes match, the build is reproducible!

## Testing the Image

Boot the qcow2 image with QEMU:

```bash
qemu-system-x86_64 \
    -m 2G \
    -drive file=paypal-auth-vm.qcow2,format=qcow2 \
    -nographic
```

## Troubleshooting

### Sudo Access Required

The build script needs sudo access for:
- Installing dracut modules to `/usr/lib/dracut/modules.d/`
- Loop device operations (`losetup`)
- Filesystem mounting

If you don't have sudo access, you can modify the script to use user-space alternatives or request elevated privileges in firebase.studio.

### Kernel Not Found

If the script can't find a kernel, ensure the `pkgs.linux` package is installed in `dev.nix`.

### add-determinism Not Found

The `add-determinism` tool is installed via the onCreate hook in `dev.nix`. If it's missing:

```bash
cargo install add-determinism
```

## Comparison with QEMU/Docker Builds

The native build approach:
- ✅ **Faster**: No VM or container overhead
- ✅ **Simpler**: Runs directly in your workspace
- ✅ **Same output**: Produces identical images (verify with SHA256)
- ⚠️ **Requires sudo**: Needs elevated privileges for some operations

The QEMU/Docker approaches are still useful for:
- Environments without sudo access
- Testing in isolated VMs
- Cross-platform builds
