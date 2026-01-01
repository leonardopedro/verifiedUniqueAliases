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

# Build initramfs
echo "🔨 Building initramfs with dracut..."
# --no-early-microcode: Prevent prepending uncompressed CPIO (fixes gzip error)
# --reproducible: Use SOURCE_DATE_EPOCH for timestamps
# --gzip: Use gzip compression
dracut \
    --force \
    --reproducible \
    --gzip \
    --no-early-microcode \
    --add "paypal-auth-vm" \
    --kver "$KERNEL_VERSION" \
    --fwdir "/lib/firmware" \
    "$OUTPUT_FILE"

if [ ! -f "$OUTPUT_FILE" ]; then
    echo "❌ Dracut failed to create initramfs!"
    exit 1
fi

# Normalize initramfs
echo "🔧 Normalizing initramfs..."
if command -v add-det &>/dev/null; then
    # Detect if it's gzip
    if gzip -t "$OUTPUT_FILE" 2>/dev/null; then
        echo "   (Detected gzip format, applying normalization)"
        gzip -d -c "$OUTPUT_FILE" > "$OUTPUT_FILE.uncompressed"
        add-det "$OUTPUT_FILE.uncompressed"
        gzip -n -9 < "$OUTPUT_FILE.uncompressed" > "$OUTPUT_FILE.tmp"
        mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
        rm -f "$OUTPUT_FILE.uncompressed"
    else
        echo "   ⚠️  Initramfs is not in gzip format (possibly multi-segment or uncompressed)"
        echo "       Relying on dracut --reproducible flags."
        # Still run add-det on the file itself just in case it's an uncompressed CPIO
        add-det "$OUTPUT_FILE"
    fi
fi
touch -d "@${SOURCE_DATE_EPOCH}" "$OUTPUT_FILE"

INITRAMFS_HASH=$(sha256sum "$OUTPUT_FILE" | awk '{print $1}')
echo "$INITRAMFS_HASH" > "$OUTPUT_FILE.sha256"

# Build manifest
cat > build-manifest.json <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "source_date_epoch": "$SOURCE_DATE_EPOCH",
  "build_environment": "docker/vm (Oracle Linux)",
  "kernel_version": "$KERNEL_VERSION",
  "target": "$BUILD_TARGET",
  "initramfs_sha256": "$INITRAMFS_HASH"
}
EOF

echo ""
echo "✅ Initramfs build complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📦 Output: $OUTPUT_FILE"
echo "   SHA256: $INITRAMFS_HASH"
echo "   Size: $(du -h "$OUTPUT_FILE" | cut -f1)"
echo ""
