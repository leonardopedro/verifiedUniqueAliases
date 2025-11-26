#!/bin/bash
set -e

echo "🏗️  Building reproducible initramfs with Dracut..."

# Detect if musl is available
if command -v x86_64-linux-musl-gcc &> /dev/null; then
    BUILD_TARGET="x86_64-unknown-linux-musl"
    echo "✅ Using musl target for smallest binary"
else
    BUILD_TARGET="x86_64-unknown-linux-gnu"
    echo "⚠️  musl not available, using glibc target (larger binary)"
    echo "   Install musl-tools for smaller binary: sudo apt-get install musl-tools"
fi
BUILD_TARGET="x86_64-unknown-linux-musl"

# Set reproducible build environment
export SOURCE_DATE_EPOCH=1640995200  # 2022-01-01 00:00:00 UTC
export TZ=UTC
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

# Build directory
BUILD_DIR=$(pwd)
cd $BUILD_DIR

echo "📦 Building Rust application for $BUILD_TARGET..."

# Add target if not already added
rustup target add $BUILD_TARGET 2>/dev/null || true

# Build Rust binary (reproducible)
export RUSTFLAGS="-C target-cpu=generic"

cargo build --release --target $BUILD_TARGET
strip target/$BUILD_TARGET/release/paypal-auth-vm

BINARY_SIZE=$(du -h target/$BUILD_TARGET/release/paypal-auth-vm | cut -f1)
echo "📊 Binary size: $BINARY_SIZE"

# Generate LUKS key
if [ ! -f luks.key ]; then
    echo "🔑 Generating LUKS key..."
    dd if=/dev/urandom of=luks.key bs=512 count=1
fi

# Prepare local dracut module
echo "📋 Preparing local dracut module..."
chmod +x dracut-module/99paypal-auth-vm/*.sh

# Update module-setup.sh with correct build path
sed -i "s|/build/paypal-auth-vm|$BUILD_DIR|g" \
    dracut-module/99paypal-auth-vm/module-setup.sh
sed -i "s|x86_64-unknown-linux-musl|$BUILD_TARGET|g" \
    dracut-module/99paypal-auth-vm/module-setup.sh


# Build initramfs
echo "🔨 Building initramfs with dracut..."

KERNEL_VERSION=$(find /lib/modules -maxdepth 1 -type d -name "[0-9]*" | xargs basename)
OUTPUT_FILE="initramfs-paypal-auth.img"

dracut \
    --force \
    --kver "$KERNEL_VERSION" \
    --conf ./dracut.conf \
    --confdir . \
    --add "99paypal-auth-vm" \
    --tmpdir $HOME/dracut-build \
    "$OUTPUT_FILE"

# Calculate hash for verification
HASH=$(sha256sum "$OUTPUT_FILE" | cut -d' ' -f1)

echo ""
echo "✅ Reproducible initramfs build complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 SHA256: $HASH"
echo "📦 Size: $(du -h "$OUTPUT_FILE" | cut -f1)"
echo "🔧 Built with dracut for reproducibility"
echo "🎯 Target: $BUILD_TARGET"
echo ""
echo "Files created:"
echo "  • $OUTPUT_FILE - Initramfs image"
echo "  • luks.key - LUKS encryption key"
echo ""
echo "To verify reproducibility:"
echo "  1. Build on another machine with same inputs"
echo "  2. Compare SHA256 hashes - they should match!"
echo ""

# Save hash
echo "$HASH" > "${OUTPUT_FILE}.sha256"

# Create build manifest
cat > build-manifest.json << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "source_date_epoch": "$SOURCE_DATE_EPOCH",
  "kernel_version": "$KERNEL_VERSION",
  "rust_version": "$(rustc --version)",
  "target": "$BUILD_TARGET",
  "initramfs_sha256": "$HASH",
  "binary_size": "$BINARY_SIZE",
  "components": {
    "rust_binary": "paypal-auth-vm",
    "dracut_version": "$(dracut --version 2>&1 | head -1)",
    "compression": "xz -9"
  }
}
EOF

echo "📝 Build manifest created: build-manifest.json"
echo ""
echo "Next steps:"
echo "1. Upload $OUTPUT_FILE to OCI Object Storage"
echo "2. Upload build-manifest.json for verification"
echo "3. Anyone can rebuild with same inputs and verify hash matches"
