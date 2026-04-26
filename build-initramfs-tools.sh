#!/bin/bash
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

chmod +x "$BIN_PATH"
SRC_ROOT="$(pwd)"

# 2. Prepare build environment
mkdir -p "$OUTPUT_DIR"
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR"

# In Debian, the kernel is in /boot/vmlinuz-*-amd64 or /boot/vmlinuz-*-cloud-amd64
KERNEL_FILE=$(ls /boot/vmlinuz-*amd64 | sort -V | tail -n 1)
# The modules are in /lib/modules/
KERNEL_VERSION=$(basename "$KERNEL_FILE" | sed 's/vmlinuz-//')
echo "🔍 Using kernel version: $KERNEL_VERSION"

# Workarounds for Ubuntu mkinitramfs hook warnings
touch /etc/iscsi/initiatorname.iscsi 2>/dev/null || true
chmod 644 /etc/iscsi/initiatorname.iscsi 2>/dev/null || true

# Force inclusion of GCP network and hardware modules in the base image
echo "gve" | tee -a /etc/initramfs-tools/modules >/dev/null
echo "virtio_net" | tee -a /etc/initramfs-tools/modules >/dev/null
echo "virtio_scsi" | tee -a /etc/initramfs-tools/modules >/dev/null
echo "virtio_blk" | tee -a /etc/initramfs-tools/modules >/dev/null
echo "nvme" | tee -a /etc/initramfs-tools/modules >/dev/null
echo "nvme_core" | tee -a /etc/initramfs-tools/modules >/dev/null
echo "sev_guest" | tee -a /etc/initramfs-tools/modules >/dev/null
echo "sev-guest" | tee -a /etc/initramfs-tools/modules >/dev/null
echo "vfat" | tee -a /etc/initramfs-tools/modules >/dev/null
echo "nls_cp437" | tee -a /etc/initramfs-tools/modules >/dev/null
echo "nls_ascii" | tee -a /etc/initramfs-tools/modules >/dev/null
echo "nf_tables" | tee -a /etc/initramfs-tools/modules >/dev/null
echo "nft_chain_filter" | tee -a /etc/initramfs-tools/modules >/dev/null
echo "nft_reject_ipv4" | tee -a /etc/initramfs-tools/modules >/dev/null
echo "nft_limit" | tee -a /etc/initramfs-tools/modules >/dev/null
echo "nf_conntrack" | tee -a /etc/initramfs-tools/modules >/dev/null
echo "nft_ct" | tee -a /etc/initramfs-tools/modules >/dev/null
echo "tsm" | tee -a /etc/initramfs-tools/modules >/dev/null
echo "amd_tsm" | tee -a /etc/initramfs-tools/modules >/dev/null

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

# 🚀 Installing Enclave Init...
echo "🚀 Installing Enclave Init..."
# Use our robust helper to ensure all shared libraries (libc, libssl, libcrypto, etc.) are included
copy_bin_and_deps "$BIN_PATH"

# Now symlink the binary to /init as expected by the kernel
ln -sf "$BIN_PATH" ./init
chmod 755 ./init

# 5b. Forcefully inject attestation modules (tsm, amd_tsm, sev-guest, virtio_net, gve)
# mkinitramfs may skip these if not running on the target hardware.
echo "🛡️  Injecting hardware and network modules..."
MODULES_BASE="/lib/modules/$KERNEL_VERSION"
for modname in configfs tsm amd_tsm sev_guest sev-guest coco_guest gve virtio_net virtio_pci virtio_blk virtio_scsi nvme nvme_core vfat nls_cp437 nls_ascii nf_tables nft_chain_filter nft_reject_ipv4 nft_limit nf_conntrack nft_ct; do
    # Find the module file (could be .ko, .ko.gz, .ko.xz, or .ko.zst)
    # Search deeper to find all variants (handle hyphen/underscore mismatch)
    altname="${modname//_/-}"
    mod_files=$(find "$MODULES_BASE" \( -name "${modname}.ko*" -o -name "${altname}.ko*" \) 2>/dev/null || true)
    if [ -n "$mod_files" ]; then
        for mod_file in $mod_files; do
            echo "  Found $modname at $mod_file, copying..."
            # Recreate the directory structure in staging
            dest_rel_path=$(python3 -c "import os; print(os.path.relpath('$mod_file', '/'))")
            mkdir -p "./$(dirname "$dest_rel_path")"
            cp "$mod_file" "./$dest_rel_path"
        done
    else
        echo "  ⚠️ Warning: $modname.ko not found in $MODULES_BASE"
    fi
done

# 6. Inject required binaries and their dependencies
echo "🔍 Resolving and copying dependencies..."
copy_bin_and_deps "$BIN_PATH"

echo "  Adding TPM2 tools..."
for tool in tpm2 tpm2_createpolicy tpm2_createprimary tpm2_create tpm2_load \
            tpm2_unseal tpm2_quote tpm2_createak tpm2_pcrextend \
            tpm2_pcrread tpm2_nvread \
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
copy_bin_and_deps "date"
copy_bin_and_deps "insmod"
copy_bin_and_deps "curl"
copy_bin_and_deps "sha256sum"

echo "  Adding PayPal Root CA..."
mkdir -p ./etc/ssl/certs
cp "$SRC_ROOT/src/paypal.pem" ./etc/ssl/certs/paypal.pem
copy_bin_and_deps "nft"

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

# 9. Ensure critical device nodes exist
mkdir -p dev
mknod -m 600 dev/console c 5 1 2>/dev/null || true
mknod -m 666 dev/null c 1 3 2>/dev/null || true
mknod -m 666 dev/random c 1 8 2>/dev/null || true
mknod -m 666 dev/urandom c 1 9 2>/dev/null || true

# 9b. Ensure kernel modules are discoverable by modprobe
# In modern Debian/Ubuntu, modules might live in /lib or /usr/lib.
# We unify them in /lib/modules so modprobe always finds them.
echo "🔗 Unifying /lib/modules..."
if [ -d "./usr/lib/modules" ]; then
    mkdir -p ./lib/modules
    cp -rn ./usr/lib/modules/* ./lib/modules/ 2>/dev/null || true
    rm -rf ./usr/lib/modules
    (cd ./usr/lib && ln -sf ../lib/modules modules)
fi

# 9c. Decompress critical kernel modules so insmod can load them directly.
# insmod cannot handle .ko.zst, and modprobe may fail if depmod data
# is incomplete. Decompress the essential network drivers we need at boot.
KERNEL_VER=$(ls -1 ./lib/modules 2>/dev/null | head -1 || true)
if [ -n "$KERNEL_VER" ] && [ -d "./lib/modules/$KERNEL_VER" ]; then
    echo "🗜️  Decompressing critical kernel modules for insmod..."
    # Robustly find ALL modules in the initramfs and decompress them
    find ./lib/modules/"$KERNEL_VER" -name "*.ko.zst" | while read -r zst_mod; do
        ko_out="${zst_mod%.zst}"
        echo "  decompressing $(basename "$zst_mod")"
        zstd -d -f "$zst_mod" -o "$ko_out" 2>/dev/null || true
        rm -f "$zst_mod"
    done
    find ./lib/modules/"$KERNEL_VER" -name "*.ko.xz" | while read -r xz_mod; do
        ko_out="${xz_mod%.xz}"
        echo "  decompressing $(basename "$xz_mod")"
        xz -d -f "$xz_mod"
    done

    # Generate module dependency data now that .ko files exist
    echo "📋 Running depmod for kernel $KERNEL_VER..."
    depmod -b . "$KERNEL_VER" || true
fi

echo "  Adding libgcc_s.so.1..."
copy_bin_and_deps "libgcc_s.so.1"

# Normalize ELF binaries and shared libraries with add-det before repacking
if command -v add-det > /dev/null; then
    echo "🔧 Normalizing ELF files with add-det..."
    find . -type f \( -name "*.so*" -o -name "*.ko" -o -name "*.ko.xz" -o -name "*.ko.zst" \) -print0 | \
        xargs -0 -r add-det 2>/dev/null || true
    find . -type f -executable ! -name "*.sh" -print0 | \
        xargs -0 -r add-det 2>/dev/null || true
fi

# Ensure all files and directories in staging have a fixed timestamp for bitwise reproducibility
# Use -depth to ensure parent directories are touched AFTER their children
find . -depth -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

# Ensure no extracted device nodes persist in the staging directory.
# Docker preserves device nodes via cpio, but rootless Podman silently drops them because mknod fails.
# Since our custom init unconditionally mounts devtmpfs on boot, we don't need any pre-seeded devices,
# and clearing them out guarantees file-level sync between Podman and Docker.
rm -rf dev/*

# Use a custom Python normalizer to eliminate OverlayFS nlink/inode divergence between Docker and Podman
cat << 'EOF' > /tmp/normalize_cpio.py
import sys

def normalize(in_path, out_path, epoch):
    with open(in_path, 'rb') as f:
        data = bytearray(f.read())
    
    pos = 0
    ino = 1
    while pos < len(data):
        hdr = data[pos:pos+110]
        if len(hdr) < 110 or hdr[:6] != b'070701':
            break
            
        namesize = int(hdr[94:102], 16)
        filesize = int(hdr[54:62], 16)
        
        # Override fields: inode, uid, gid, nlink, mtime, dev/rdev
        data[pos+6:pos+14]   = f"{ino:08x}".encode('ascii')       # ino
        data[pos+22:pos+30]  = b"00000000"                        # uid
        data[pos+30:pos+38]  = b"00000000"                        # gid
        data[pos+38:pos+46]  = b"00000001"                        # nlink
        data[pos+46:pos+54]  = f"{epoch:08x}".encode('ascii')     # mtime
        data[pos+62:pos+70]  = b"00000000"                        # devmajor
        data[pos+70:pos+78]  = b"00000000"                        # devminor
        data[pos+78:pos+86]  = b"00000000"                        # rdevmajor
        data[pos+86:pos+94]  = b"00000000"                        # rdevminor
        
        name_pad = (namesize + 110 + 3) // 4 * 4 - namesize - 110
        file_pad = (filesize + 3) // 4 * 4 - filesize
        pos += 110 + namesize + name_pad + filesize + file_pad
        ino += 1

    with open(out_path, 'wb') as f:
        f.write(data)

if __name__ == '__main__':
    normalize(sys.argv[1], sys.argv[2], int(sys.argv[3]))
EOF

# 10. Repack the initramfs
echo "📦 Repacking initramfs (with CPIO header normalization)..."
find . | sort | cpio -o -H newc -R 0:0 --quiet > /tmp/initramfs-raw.cpio
python3 /tmp/normalize_cpio.py /tmp/initramfs-raw.cpio /tmp/initramfs-norm.cpio "$SOURCE_DATE_EPOCH"
zstd -T1 -19 -f --no-progress /tmp/initramfs-norm.cpio -o "$OUTPUT_FILE"
rm -f /tmp/initramfs-raw.cpio /tmp/initramfs-norm.cpio /tmp/normalize_cpio.py


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
