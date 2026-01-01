#!/bin/bash
set -e

# Ensure cargo binaries are in PATH (for add-det and other tools)
export PATH="$HOME/.cargo/bin:/usr/local/cargo/bin:$PATH"

echo "🏗️  Building reproducible initramfs with Dracut..."

# Set the build target to musl for a small, static binary.
BUILD_TARGET="x86_64-unknown-linux-gnu"
#BUILD_TARGET="x86_64-unknown-linux-musl"

#echo "✅ Using musl target for smallest binary"

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

echo "📋 Preparing files for initramfs..."
# We cannot install to /usr/lib/dracut/modules.d (read-only), so we use --include.

# Determine kernel version
if [ -d "kernel-oracle" ] && [ -f "kernel-oracle/version.txt" ]; then
    echo "🌟 Using downloaded Oracle UEK Kernel..."
    KERNEL_VERSION=$(cat kernel-oracle/version.txt)
    # Dracut needs the real path so directory name matches version
    KMOD_DIR=$(readlink -f kernel-oracle/modules)
    KERNEL_BINARY="$(pwd)/kernel-oracle/vmlinuz"
    
    # Just in case readlink fails or dracut is picky
    export DRACUT_KMODDIR_OVERRIDE=1
elif [ -n "$KERNEL_DIR" ]; then
    echo "❄️  Using Nix-provided Kernel..."
    KERNEL_VERSION=$(ls "$KERNEL_DIR" | head -n1)
    KMOD_DIR="$KERNEL_DIR/$KERNEL_VERSION" 
    KERNEL_ROOT=$(dirname $(dirname "$KERNEL_DIR"))
    KERNEL_BINARY="$KERNEL_ROOT/bzImage"
else
    echo "🖥️  Using Application/System Kernel..."
    KERNEL_VERSION=$(uname -r)
    # If finding locally, check /lib/modules
    if [ -d "/lib/modules/$KERNEL_VERSION" ]; then
        KMOD_DIR="/lib/modules/$KERNEL_VERSION"
    else
        # Last resort fallback
        KERNEL_VERSION=$(find /lib/modules -maxdepth 1 -type d -name "[0-9]*" | xargs basename | head -n1)
        KMOD_DIR="/lib/modules/$KERNEL_VERSION"
    fi
    KERNEL_BINARY="/boot/vmlinuz-$KERNEL_VERSION"
fi

OUTPUT_FILE="initramfs-paypal-auth.img"

# Create the temporary directory for dracut
mkdir -p "$HOME/dracut-build"

# Copy kernel image to current directory for build-native.sh to find
if [ -f "$KERNEL_BINARY" ]; then 
    cp "$KERNEL_BINARY" ./vmlinuz || echo "⚠️ Could not copy kernel from $KERNEL_BINARY"
else
    echo "⚠️ Kernel binary not found at $KERNEL_BINARY"
fi

# Build with reproducibility flags
# --reproducible: Use SOURCE_DATE_EPOCH for timestamps
# --gzip: Use gzip (more deterministic than zstd/lz4)
# --include: Manually inject binary and hooks since we can't install a module
echo "🔨 Generatng initramfs..."

# Ensure hooks are executable
chmod +x dracut-module/99paypal-auth-vm/*.sh

dracut \
    --force \
    --reproducible \
    --gzip \
    --kmoddir "$KMOD_DIR" \
    --omit " dash plymouth syslog firmware " \
    --no-hostonly \
    --no-hostonly-cmdline \
    --nofscks \
    --no-early-microcode \
    --install "curl" \
    --include "$BINARY_PATH" "/bin/paypal-auth-vm" \
    --include "dracut-module/99paypal-auth-vm/parse-paypal-auth.sh" "/usr/lib/dracut/hooks/cmdline/00-parse-paypal-auth.sh" \
    --include "dracut-module/99paypal-auth-vm/start-app.sh" "/usr/lib/dracut/hooks/pre-pivot/99-start-app.sh" \
    --kver "$KERNEL_VERSION" \
    --fwdir "/usr/lib/firmware" \
    --tmpdir "$HOME/dracut-build" \
    "$OUTPUT_FILE"

# Check if dracut succeeded
# Note: We need to enable pipefail to catch dracut errors
set -o pipefail

# Simplified Normalization: Decompress -> add-det -> Recompress -> add-det
# This approach normalizes the cpio archive and gzip compression without extracting files

echo "🔧 Normalizing initramfs..."
if command -v gzip >/dev/null && command -v add-det &> /dev/null; then
    # 1. Decompress
    echo "   Decompressing..."
    gzip -d -c "$OUTPUT_FILE" > "$OUTPUT_FILE.uncompressed"
    
    # 2. Normalize uncompressed cpio archive
    echo "   Normalizing uncompressed archive with add-det..."
    add-det "$OUTPUT_FILE.uncompressed"
    
    # 3. Recompress with deterministic gzip
    echo "   Recompressing with gzip -n..."
    gzip -n -9 < "$OUTPUT_FILE.uncompressed" > "$OUTPUT_FILE.tmp"
    
    # 4. Normalize compressed archive
    echo "   Normalizing compressed archive with add-det..."
    add-det "$OUTPUT_FILE.tmp"
    
    # Replace original
    mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    rm -f "$OUTPUT_FILE.uncompressed"
    
    echo "✅ Normalization complete"
else
    echo "⚠️  gzip or add-det not found, skipping normalization..."
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
