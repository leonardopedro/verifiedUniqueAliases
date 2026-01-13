#!/bin/bash
# Build initramfs using Dracut (for Docker/VM environments)
# This script runs INSIDE an Oracle Linux Docker container or VM

set -e

echo "🏗️  Building reproducible initramfs with Dracut..."

# Reproducibility environment
export SOURCE_DATE_EPOCH=1640995200  # 2022-01-01 00:00:00 UTC
export TZ=UTC
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

# Build target - use gnu for docker (glibc), musl for static
BUILD_TARGET="x86_64-unknown-linux-gnu"
BUILD_DIR=$(pwd)
cd $BUILD_DIR

echo "📦 Building Rust application for $BUILD_TARGET..."

# Add target if not already added
rustup target add $BUILD_TARGET 2>/dev/null || true

# Build Rust binary with full reproducibility flags
export RUSTFLAGS="-C target-cpu=generic -C codegen-units=1 -C strip=symbols"
export CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_OPT_LEVEL=2

cargo build --release --target $BUILD_TARGET || { echo "❌ Cargo build failed"; exit 1; }

BINARY_PATH="target/$BUILD_TARGET/release/paypal-auth-vm"
if [ ! -f "$BINARY_PATH" ]; then
    echo "❌ Binary not found at $BINARY_PATH"
    exit 1
fi

# Normalize the binary
echo "🔧 Normalizing binary..."
if command -v add-det &>/dev/null; then
    add-det "$BINARY_PATH"
fi
touch -d "@${SOURCE_DATE_EPOCH}" "$BINARY_PATH"

BINARY_SIZE=$(du -h "$BINARY_PATH" | cut -f1)
echo "📊 Binary size: $BINARY_SIZE"

# Prepare local dracut module
echo "📋 Preparing local dracut module..."

# Always remove and re-copy to ensure clean state
rm -rf /usr/lib/dracut/modules.d/99paypal-auth-vm
mkdir -p /usr/lib/dracut/modules.d/
cp -r ./dracut-module/99paypal-auth-vm /usr/lib/dracut/modules.d/
chmod +x /usr/lib/dracut/modules.d/99paypal-auth-vm/*.sh

# Update module-setup.sh with correct build path
sed -i "s|BINARY_SOURCE=.*|BINARY_SOURCE=\"$BUILD_DIR/$BINARY_PATH\"|g" \
    /usr/lib/dracut/modules.d/99paypal-auth-vm/module-setup.sh

# Normalize module timestamps
find /usr/lib/dracut/modules.d/99paypal-auth-vm -type f -exec touch -d "@${SOURCE_DATE_EPOCH}" {} \;

# Verify module
echo "🔍 Verifying dracut module..."
if [ -d /usr/lib/dracut/modules.d/99paypal-auth-vm ]; then
    echo "✅ Module directory exists"
else
    echo "❌ Module directory not found!"
    exit 1
fi

# Find kernel version
KERNEL_VERSION=$(ls /lib/modules | head -n1)
echo "🐧 Using kernel: $KERNEL_VERSION"

OUTPUT_FILE="initramfs-paypal-auth.img"

# Copy kernel to output directory
if [ -f "/boot/vmlinuz-$KERNEL_VERSION" ]; then
    cp "/boot/vmlinuz-$KERNEL_VERSION" ./vmlinuz
    echo "✅ Kernel copied to ./vmlinuz"
elif [ -f "/lib/modules/$KERNEL_VERSION/vmlinuz" ]; then
    cp "/lib/modules/$KERNEL_VERSION/vmlinuz" ./vmlinuz
    echo "✅ Kernel copied to ./vmlinuz"
else
    echo "⚠️ Kernel binary not found (will need to be provided externally)"
fi

# Build initramfs and UKI (Unified Kernel Image)
echo "🔨 Building initramfs and UKI with dracut..."
# --no-early-microcode: Prevent prepending uncompressed CPIO (fixes gzip error)
# --reproducible: Use SOURCE_DATE_EPOCH for timestamps
# --gzip: Use gzip compression
# --uefi: Create a Unified Kernel Image
CMDLINE="ro console=ttyS0,115200n8 earlycon earlyprintk=ttyS0 ignore_loglevel keep_bootcon loglevel=7 swiotlb=131072 mem_encrypt=on nokaslr iommu=pt random.trust_cpu=on ip=dhcp rd.neednet=1 rd.skipfsck"

# If we use --uefi, dracut creates a UKI. 
# We'll call it .efi from the start to avoid confusion.
UKI_FILE="paypal-auth-vm.efi"

dracut \
    --force \
    --reproducible \
    --gzip \
    --no-early-microcode \
    --hostonly \
    --uefi \
    --kernel-cmdline "$CMDLINE" \
    --add "qemu paypal-auth-vm" \
    --add-drivers "virtio virtio_net virtio_blk virtio_pci virtio_scsi" \
    --kver "$KERNEL_VERSION" \
    --fwdir "/lib/firmware" \
    "$UKI_FILE"

if [ ! -f "$UKI_FILE" ]; then
    echo "❌ Dracut failed to create UKI!"
    exit 1
fi

# Check if it's actually an EFI binary
if file "$UKI_FILE" | grep -q "EFI"; then
    echo "✅ UKI generated successfully: $UKI_FILE"
else
    echo "⚠️  Generated file is not an EFI binary!"
    file "$UKI_FILE"
fi

# We also still want a standard initramfs for fallback/legacy?
# Actually, for this project we want the UKI.
# But let's also generate a standard initramfs just in case.
dracut \
    --force \
    --reproducible \
    --gzip \
    --no-early-microcode \
    --hostonly \
    --add "qemu paypal-auth-vm" \
    --add-drivers "virtio virtio_net virtio_blk virtio_pci virtio_scsi sev-guest efi_secret dm-crypt dm-integrity" \
    --kver "$KERNEL_VERSION" \
    --fwdir "/lib/firmware" \
    "$OUTPUT_FILE"

if [ ! -f "$OUTPUT_FILE" ]; then
    echo "❌ Dracut failed to create initramfs!"
    exit 1
fi

# Normalize initramfs/UKI
echo "🔧 Normalizing artifacts..."
if command -v add-det &>/dev/null; then
    for f in "$OUTPUT_FILE" "paypal-auth-vm.efi"; do
        if [ -f "$f" ]; then
            if gzip -t "$f" 2>/dev/null; then
                echo "   (Detected gzip format for $f, applying normalization)"
                gzip -d -c "$f" > "$f.uncompressed"
                add-det "$f.uncompressed"
                gzip -n -9 < "$f.uncompressed" > "$f.tmp"
                mv "$f.tmp" "$f"
                rm -f "$f.uncompressed"
            else
                echo "   Applying add-det to $f..."
                add-det "$f"
            fi
            touch -d "@${SOURCE_DATE_EPOCH}" "$f"
        fi
    done
fi

# Build manifest
UKI_HASH="none"
if [ -f "paypal-auth-vm.efi" ]; then
    UKI_HASH=$(sha256sum "paypal-auth-vm.efi" | awk '{print $1}')
    echo "$UKI_HASH" > "paypal-auth-vm.efi.sha256"
fi

INITRAMFS_HASH="none"
if [ -f "$OUTPUT_FILE" ]; then
    INITRAMFS_HASH=$(sha256sum "$OUTPUT_FILE" | awk '{print $1}')
    echo "$INITRAMFS_HASH" > "$OUTPUT_FILE.sha256"
fi

cat > build-manifest.json <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "source_date_epoch": "$SOURCE_DATE_EPOCH",
  "build_environment": "docker/vm (Oracle Linux)",
  "kernel_version": "$KERNEL_VERSION",
  "target": "$BUILD_TARGET",
  "initramfs_sha256": "$INITRAMFS_HASH",
  "uki_sha256": "$UKI_HASH"
}
EOF

echo ""
echo "✅ Initramfs build complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📦 Output: $OUTPUT_FILE"
echo "   SHA256: $INITRAMFS_HASH"
echo "   Size: $(du -h "$OUTPUT_FILE" | cut -f1)"
echo ""
