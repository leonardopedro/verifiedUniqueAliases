#!/bin/bash
set -exuo pipefail

echo "🏗️  Building robust reproducible initramfs for GCP Confidential VM..."

# Set reproducible build environment
export SOURCE_DATE_EPOCH=1712260800
export TZ=UTC
export LC_ALL=C.UTF-8

BUILD_TARGET="x86_64-unknown-linux-gnu"
OUTPUT_DIR="$(pwd)/output"
OUTPUT_FILE="${OUTPUT_DIR}/initramfs-paypal-auth.img"
STAGING_DIR="/tmp/initramfs_staging"
BIN_PATH="$(pwd)/paypal-auth-vm-bin"

echo "✅ Using pre-built binary: $BIN_PATH"

echo "✅ Using pre-built binary: $BIN_PATH"
chmod +x "$BIN_PATH"

# 2. Prepare build environment
mkdir -p "$OUTPUT_DIR"
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR"

# In Debian, the kernel is in /boot/vmlinuz-*-cloud-amd64
KERNEL_FILE=$(ls /boot/vmlinuz-*-cloud-amd64 | sort -V | tail -n 1)
# The modules are in /lib/modules/
KERNEL_VERSION=$(basename "$KERNEL_FILE" | sed 's/vmlinuz-//')
echo "🔍 Using kernel version: $KERNEL_VERSION"

# Workarounds for Ubuntu mkinitramfs hook warnings
touch /etc/iscsi/initiatorname.iscsi 2>/dev/null || true
chmod 644 /etc/iscsi/initiatorname.iscsi 2>/dev/null || true

# Force inclusion of GCP network modules in the base image
echo "gve" | tee -a /etc/initramfs-tools/modules >/dev/null
echo "virtio_net" | tee -a /etc/initramfs-tools/modules >/dev/null

echo "🔨 Generating base mkinitramfs..."
BASE_IMG="/tmp/base-initrd.img"
mkinitramfs -o "$BASE_IMG" "$KERNEL_VERSION"

# 4. Extract base initramfs
echo "📦 Extracting base image..."
cd "$STAGING_DIR"
# Detect compression format
FILE_TYPE=$(file -b "$BASE_IMG")
if echo "$FILE_TYPE" | grep -qi "gzip"; then
    zcat "$BASE_IMG" | cpio -idm --quiet 2>/dev/null || true
elif echo "$FILE_TYPE" | grep -qi "xz"; then
    xzcat "$BASE_IMG" | cpio -idm --quiet 2>/dev/null || true
elif echo "$FILE_TYPE" | grep -qi "zstd"; then
    zstdcat "$BASE_IMG" | cpio -idm --quiet 2>/dev/null || true
else
    # Uncompressed cpio archive
    cpio -idm --quiet < "$BASE_IMG" 2>/dev/null || true
fi

# 5. Overwrite the default init with our Rust binary
echo "🚀 Installing Enclave Init..."
rm -f ./init
cp "$BIN_PATH" ./init
chmod 755 ./init

# -----------------------------------------------------------------------------
# ROBUST DEPENDENCY RESOLVER FUNCTION
# This safely handles copying binaries, resolving their real paths,
# and meticulously recreating symlinks for shared libraries (crucial for glibc)
# -----------------------------------------------------------------------------
copy_bin_and_deps() {
    local bin_path
    bin_path=$(command -v "$1" 2>/dev/null || echo "$1")

    if [ ! -f "$bin_path" ]; then
        echo "  ⚠️  Warning: $1 not found, skipping."
        return
    fi

    # 1. Resolve and copy the binary itself
    local real_bin
    real_bin=$(readlink -f "$bin_path")
    mkdir -p ".$(dirname "$real_bin")"
    
    # Use --update=none on newer cp versions, fallback to -n
    if cp --help | grep -q "update=none"; then
        cp -p --update=none "$real_bin" ".${real_bin}"
    else
        cp -pn "$real_bin" ".${real_bin}"
    fi

    # If the binary was a symlink, recreate the symlink in staging
    if [ "$bin_path" != "$real_bin" ]; then
        mkdir -p ".$(dirname "$bin_path")"
        # Create RELATIVE symlink for stability
        (cd ".$(dirname "$bin_path")" && ln -sf "$(real_bin=$(readlink -f "$real_bin"); python3 -c "import os; print(os.path.relpath('$real_bin', '$(dirname "$bin_path")'))")" "$(basename "$bin_path")")
    fi

    # 2. Resolve and copy all shared libraries via ldd
    # If the binary is static, ldd will return 'not a dynamic executable' and the loop won't run.
    ldd "$real_bin" 2>/dev/null | awk '/=>/ {print $3} /ld-linux/ {print $1}' | grep '^/' | while read -r lib; do
        [ -f "$lib" ] || continue
        local real_lib
        real_lib=$(readlink -f "$lib")

        # Copy real library
        mkdir -p ".$(dirname "$real_lib")"
        if cp --help | grep -q "update=none"; then
            cp -p --update=none "$real_lib" ".${real_lib}" 2>/dev/null || true
        else
            cp -pn "$real_lib" ".${real_lib}" 2>/dev/null || true
        fi

        # Recreate symlink (e.g., libc.so.6 -> libc-2.31.so)
        if [ "$lib" != "$real_lib" ]; then
            mkdir -p ".$(dirname "$lib")"
            (cd ".$(dirname "$lib")" && ln -sf "$(real_lib=$(readlink -f "$real_lib"); python3 -c "import os; print(os.path.relpath('$real_lib', '$(dirname "$lib")'))")" "$(basename "$lib")")
        fi
    done
}

# 6. Inject required binaries and their dependencies
echo "🔍 Resolving and copying dependencies..."
copy_bin_and_deps "$BIN_PATH"

echo "  Adding TPM2 tools..."
for tool in tpm2_createpolicy tpm2_createprimary tpm2_create tpm2_load \
            tpm2_unseal tpm2_quote tpm2_createak tpm2_pcrextend \
            tpm2_readpublic tpm2_flushcontext tpm2_startauthsession \
            tpm2_policypcr tpm2_getekcertificate; do
    copy_bin_and_deps "$tool"
done

# Copy TSS configuration if it exists
if [ -d "/etc/tpm2-tss" ]; then
    mkdir -p ./etc
    cp -r /etc/tpm2-tss ./etc/
fi

echo "  Adding system tools..."
copy_bin_and_deps "ip"
copy_bin_and_deps "modprobe"
copy_bin_and_deps "depmod"
copy_bin_and_deps "insmod"
copy_bin_and_deps "curl"
copy_bin_and_deps "sha256sum"

echo "  Adding TSS2 TCTI libraries (for dynamic loading)..."
for lib in libtss2-tcti-device.so.0 libtss2-tctildr.so.0 libtss2-mu.so.0 libtss2-esys.so.0 libtss2-sys.so.0 libtss2-rc.so.0; do
    lib_path=$(find /lib /usr/lib /lib/x86_64-linux-gnu -name "$lib" -print -quit 2>/dev/null || true)
    if [ -n "$lib_path" ]; then
        copy_bin_and_deps "$lib_path"
    fi
done

# Ensure /sbin/ symlinks exist for tools our Rust binary expects at /sbin/*
# Ubuntu 25.10 merged /sbin -> /usr/sbin, but our init binary uses /sbin paths
echo "  Creating /sbin compatibility symlinks..."
mkdir -p ./sbin
for tool in modprobe depmod insmod ip; do
    real_path=$(command -v "$tool" 2>/dev/null || true)
    if [ -n "$real_path" ] && [ ! -e "./sbin/$tool" ]; then
        ln -sf "$real_path" "./sbin/$tool"
    fi
done

# 7. INJECT HIDDEN GLIBC MODULES (Critical for DNS / HTTPS)
echo "🌐 Adding NSS/DNS libraries for glibc networking..."
for nss_lib in libnss_dns.so.2 libnss_files.so.2 libresolv.so.2; do
    # Find the library on the host and copy it with dependencies
    lib_path=$(find /lib /usr/lib /lib/x86_64-linux-gnu -name "$nss_lib" -print -quit 2>/dev/null || true)
    if [ -n "$lib_path" ]; then
        copy_bin_and_deps "$lib_path"
    else
        echo "  ⚠️ Warning: $nss_lib not found. DNS resolution might fail!"
    fi
done

# 8. Configure Network & Certificate Data
echo "⚙️  Applying network and security configs..."
mkdir -p etc/ssl/certs
cp /etc/ssl/certs/ca-certificates.crt etc/ssl/certs/
# Create standard symlinks for OpenSSL/Reqwest discovery
ln -sf certs/ca-certificates.crt etc/ssl/cert.pem

echo "hosts: files dns" > etc/nsswitch.conf
echo "127.0.0.1 localhost" > etc/hosts

# 9. Ensure critical device nodes exist
echo "🛠️  Creating essential device nodes..."
mkdir -p dev
mknod -m 600 dev/console c 5 1 2>/dev/null || true
mknod -m 666 dev/null c 1 3 2>/dev/null || true
mknod -m 666 dev/random c 1 8 2>/dev/null || true
mknod -m 666 dev/urandom c 1 9 2>/dev/null || true

# 9b. Ensure kernel modules are discoverable by modprobe
# On Ubuntu 25.10, modules live at /usr/lib/modules/ but modprobe
# looks at /lib/modules/ — create a RELATIVE symlink so it works
# whether the initramfs is the rootfs or mounted elsewhere.
echo "🔗 Setting up /lib/modules symlink for modprobe..."
mkdir -p ./lib
if [ -d "./usr/lib/modules" ] && [ ! -e "./lib/modules" ]; then
    ln -sf ../usr/lib/modules ./lib/modules
fi

# 9c. Decompress critical kernel modules so insmod can load them directly.
# insmod cannot handle .ko.zst, and modprobe may fail if depmod data
# is incomplete. Decompress the essential network drivers we need at boot.
KERNEL_VER=$(ls -1 ./usr/lib/modules 2>/dev/null | head -1 || true)
if [ -n "$KERNEL_VER" ] && [ -d "./usr/lib/modules/$KERNEL_VER" ]; then
    echo "🗜️  Decompressing critical kernel modules for insmod..."
    for zst_mod in \
        "./usr/lib/modules/$KERNEL_VER/kernel/drivers/net/ethernet/google/gve/gve.ko.zst" \
        "./usr/lib/modules/$KERNEL_VER/kernel/drivers/virtio/virtio_pci.ko.zst" \
        "./usr/lib/modules/$KERNEL_VER/kernel/drivers/virtio/virtio.ko.zst" \
        "./usr/lib/modules/$KERNEL_VER/kernel/net/core/virtio_net.ko.zst"; do
        if [ -f "$zst_mod" ]; then
            ko_out="${zst_mod%.zst}"
            echo "  decompressing $(basename "$zst_mod") → $(basename "$ko_out")"
            zstd -d -f "$zst_mod" -o "$ko_out" 2>/dev/null || true
        fi
    done

    # Also search for any other .ko.zst in the gve and virtio directories
    # and decompress them (dependencies of gve like gve_drv if present)
    for dir in \
        "./usr/lib/modules/$KERNEL_VER/kernel/drivers/net/ethernet/google/gve" \
        "./usr/lib/modules/$KERNEL_VER/kernel/drivers/virtio"; do
        if [ -d "$dir" ]; then
            for zst in "$dir"/*.ko.zst; do
                [ -f "$zst" ] || continue
                ko_out="${zst%.zst}"
                [ -f "$ko_out" ] && continue  # already decompressed
                echo "  decompressing $(basename "$zst")"
                zstd -d -f "$zst" -o "$ko_out" 2>/dev/null || true
            done
        fi
    done

    # Generate module dependency data now that .ko files exist
    echo "📋 Running depmod for kernel $KERNEL_VER..."
    if command -v depmod >/dev/null 2>&1; then
        depmod -b . "$KERNEL_VER" 2>/dev/null || true
    fi
fi

# 10. Repack the initramfs
echo "📦 Repacking initramfs..."
find . | sort | cpio -o -H newc -R 0:0 --quiet | zstd -T0 -19 -f -o "$OUTPUT_FILE"

# Clean up
cd /
rm -rf "$STAGING_DIR"
rm -f "$BASE_IMG"
chown "$(whoami):$(whoami)" "$OUTPUT_FILE"

# 11. Generate manifest and SHA256
cd "$OUTPUT_DIR"
HASH=$(sha256sum "$(basename "$OUTPUT_FILE")" | cut -d' ' -f1)
echo "$HASH" > "$(basename "$OUTPUT_FILE").sha256"

RUST_VER=$(rustc --version 2>/dev/null || echo "pre-built container")
cat > build-manifest.json << EOF
{
  "timestamp": "$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)",
  "source_date_epoch": "$SOURCE_DATE_EPOCH",
  "kernel_version": "$KERNEL_VERSION",
  "rust_version": "$RUST_VER",
  "target": "$BUILD_TARGET",
  "initramfs_sha256": "$HASH"
}
EOF

echo "✅ Build complete! SHA256: $HASH"
echo "🚀 Output ready at: $OUTPUT_FILE"
# Extract kernel, shim, and grub for GPT image builder
cp "$KERNEL_FILE" "$OUTPUT_DIR/vmlinuz"

# Find shim and grub more robustly in Debian 13
SHIM_SRC=$(find /usr/lib/shim -name "shimx64.efi.signed" -print -quit 2>/dev/null || find /usr/lib/shim -name "shimx64.efi" -print -quit 2>/dev/null || true)
GRUB_SRC=$(find /usr/lib/grub -name "grubx64.efi.signed" -print -quit 2>/dev/null || find /usr/lib/grub -name "grubx64.efi" -print -quit 2>/dev/null || true)

if [ -n "$SHIM_SRC" ]; then
    echo "  Found shim at $SHIM_SRC"
    cp "$SHIM_SRC" "$OUTPUT_DIR/shimx64.efi"
else
    echo "  ⚠️ Warning: shimx64.efi.signed not found!"
fi

if [ -n "$GRUB_SRC" ]; then
    echo "  Found grub at $GRUB_SRC"
    cp "$GRUB_SRC" "$OUTPUT_DIR/grubx64.efi"
else
    echo "  ⚠️ Warning: grubx64.efi.signed not found!"
fi
