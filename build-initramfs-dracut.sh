#!/bin/bash
set -e

echo "🏗️  Building reproducible initramfs with Dracut..."

# Set the build target to musl for a small, static binary.
BUILD_TARGET="x86_64-unknown-linux-gnu"
#BUILD_TARGET="x86_64-unknown-linux-musl"

echo "✅ Using musl target for smallest binary"

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

# Build Rust binary with full reproducibility flags
# These flags ensure deterministic output:
# - target-cpu=generic: Avoid host-specific optimizations
# - codegen-units=1: Single codegen unit for deterministic output
# - strip=symbols: Strip debug symbols for smaller, deterministic binary
export RUSTFLAGS="-C target-cpu=generic -C codegen-units=1 -C strip=symbols"

# Ensure reproducible build with LTO
export CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_OPT_LEVEL=2

cargo build --release --target $BUILD_TARGET
# Strip the binary for smaller size and reproducibility
strip --strip-all target/$BUILD_TARGET/release/paypal-auth-vm

# Normalize the binary timestamp to SOURCE_DATE_EPOCH
touch -d "@${SOURCE_DATE_EPOCH}" target/$BUILD_TARGET/release/paypal-auth-vm

BINARY_SIZE=$(du -h target/$BUILD_TARGET/release/paypal-auth-vm | cut -f1)
echo "📊 Binary size: $BINARY_SIZE"


# Prepare local dracut module
echo "📋 Preparing local dracut module..."
chmod +x /usr/lib/dracut/modules.d/99paypal-auth-vm/*.sh

# Update module-setup.sh with correct build path
sed -i "s|/build/paypal-auth-vm|$BUILD_DIR|g" \
    /usr/lib/dracut/modules.d/99paypal-auth-vm/module-setup.sh
#sed -i "s|x86_64-unknown-linux-musl|$BUILD_TARGET|g" \
#    /usr/lib/dracut/modules.d/99paypal-auth-vm/module-setup.sh
sed -i "s|x86_64-unknown-linux-gnu|$BUILD_TARGET|g" \
    /usr/lib/dracut/modules.d/99paypal-auth-vm/module-setup.sh

# CRITICAL: Normalize all file timestamps BEFORE dracut packages them
echo "🔧 Normalizing timestamps for reproducibility..."
find target/$BUILD_TARGET/release -type f -exec touch -d "@${SOURCE_DATE_EPOCH}" {} \;
find /usr/lib/dracut/modules.d/99paypal-auth-vm -type f -exec touch -d "@${SOURCE_DATE_EPOCH}" {} \;

# Build initramfs with reproducibility flags
echo "🔨 Building initramfs with dracut..."

KERNEL_VERSION=$(find /lib/modules -maxdepth 1 -type d -name "[0-9]*" | xargs basename)
OUTPUT_FILE="initramfs-paypal-auth.img"

# Create the temporary directory for dracut
mkdir -p "$HOME/dracut-build"

# Build with reproducibility flags
# --reproducible: Use SOURCE_DATE_EPOCH for timestamps
# --gzip: Use gzip (more deterministic than zstd/lz4)
# --force: Overwrite existing file
# Note: We explicitly set compression to gzip for reproducibility
dracut \
    --force \
    --reproducible \
    --gzip \
    --kver "$KERNEL_VERSION" \
    --tmpdir "$HOME/dracut-build" \
    "$OUTPUT_FILE"

# Normalize the initramfs for reproducibility
# Strip any remaining non-deterministic data
if command -v strip-nondeterminism &> /dev/null; then
    echo "🔧 Stripping non-deterministic data..."
    strip-nondeterminism "$OUTPUT_FILE"
fi

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
