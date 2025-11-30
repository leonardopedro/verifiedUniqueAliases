#!/bin/bash
# Native build script for firebase.studio
# Builds the initramfs and qcow2 image directly without QEMU/Docker/Podman/sudo

set -e

echo "🏗️  Building reproducible initramfs and qcow2 image natively (no-sudo)..."

# Set reproducible build environment
export SOURCE_DATE_EPOCH=1640995200  # 2022-01-01 00:00:00 UTC
export TZ=UTC
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

# Ensure cargo binaries are in PATH
export PATH="$HOME/.cargo/bin:/usr/local/cargo/bin:$PATH"

# Build configuration
# Build configuration
BUILD_DIR=$(pwd)
# Use gnu target for dynamic linking (glibc)
BUILD_TARGET="x86_64-unknown-linux-gnu"
INITRAMFS_FILE="$BUILD_DIR/initramfs-paypal-auth.img"
OUTPUT_IMG="$BUILD_DIR/paypal-auth-vm.qcow2"
ISO_FILE="$BUILD_DIR/boot.iso"
ISO_ROOT="$BUILD_DIR/iso_root"

echo "📍 Build directory: $BUILD_DIR"
echo "🎯 Target: $BUILD_TARGET"
echo ""

# Clean up previous build artifacts
rm -rf "$ISO_ROOT" "$INITRAMFS_FILE" "$ISO_FILE" result

# Step 1: Build Rust binary (Dynamic)
echo "🦀 Building Rust binary (dynamic)..."
# rustup target add "$BUILD_TARGET" 2>/dev/null || true # Usually installed by default

# Clear RUSTFLAGS to avoid static linking
export RUSTFLAGS=""
export CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_OPT_LEVEL=z

cargo build --release --target "$BUILD_TARGET"

BINARY_PATH="$BUILD_DIR/target/$BUILD_TARGET/release/paypal-auth-vm"

if [ ! -f "$BINARY_PATH" ]; then
    echo "❌ Cargo build failed! Binary not found: $BINARY_PATH"
    exit 1
fi

# Normalize binary
echo "🔧 Normalizing binary..."
if command -v add-det &>/dev/null; then
    add-det "$BINARY_PATH"
fi
touch -d "@${SOURCE_DATE_EPOCH}" "$BINARY_PATH"

# Step 2: Build Initramfs and get Kernel using Nix
echo "❄️  Building initramfs with Nix..."

# Build initramfs
nix-build initramfs.nix -A initramfs --arg binaryPath $BINARY_PATH -o result-initramfs
cp result-initramfs/initrd "$INITRAMFS_FILE"

# Get kernel
nix-build initramfs.nix -A kernel -o result-kernel
KERNEL_FILE="result-kernel/bzImage"

if [ ! -f "$KERNEL_FILE" ]; then
    echo "❌ Kernel not found at $KERNEL_FILE"
    exit 1
fi

if [ ! -f "$INITRAMFS_FILE" ]; then
    echo "❌ Initramfs build failed!"
    exit 1
fi

echo "✅ Initramfs built: $INITRAMFS_FILE"
echo "   Kernel found: $KERNEL_FILE"

# Normalize initramfs for reproducibility
echo "🔧 Normalizing initramfs..."
if command -v add-det &>/dev/null; then
    # Decompress initramfs
    echo "   Decompressing initramfs..."
    gzip -d -c "$INITRAMFS_FILE" > "$INITRAMFS_FILE.uncompressed"
    
    # Apply add-det to uncompressed initramfs
    echo "   Applying add-det to uncompressed initramfs..."
    add-det "$INITRAMFS_FILE.uncompressed"
    
    # Recompress with deterministic gzip
    echo "   Recompressing with deterministic gzip..."
    gzip -n -9 < "$INITRAMFS_FILE.uncompressed" > "$INITRAMFS_FILE.tmp"
    
    # Apply add-det to compressed initramfs
    echo "   Applying add-det to compressed initramfs..."
    add-det "$INITRAMFS_FILE.tmp"
    
    # Replace original
    mv "$INITRAMFS_FILE.tmp" "$INITRAMFS_FILE"
    rm -f "$INITRAMFS_FILE.uncompressed"
    
    echo "   ✅ Initramfs normalized"
else
    echo "   ⚠️  add-det not found, skipping initramfs normalization"
fi

INITRAMFS_HASH=$(sha256sum "$INITRAMFS_FILE" | awk '{print $1}')
echo "📊 Initramfs SHA256: $INITRAMFS_HASH"

# Step 3: Create bootable ISO image with GRUB
echo ""
echo "💿 Creating bootable ISO image..."

# Prepare ISO root directory
mkdir -p "$ISO_ROOT/boot/grub"

cp "$KERNEL_FILE" "$ISO_ROOT/boot/vmlinuz"
cp "$INITRAMFS_FILE" "$ISO_ROOT/boot/initramfs.img"

# Create GRUB config
tee "$ISO_ROOT/boot/grub/grub.cfg" > /dev/null <<EOF
set default=0
set timeout=1

menuentry 'PayPal Auth VM' {
    linux /boot/vmlinuz ro console=ttyS0
    initrd /boot/initramfs.img
}
EOF

# Create bootable ISO
grub-mkrescue -o "$ISO_FILE" "$ISO_ROOT"

# Clean up ISO root
rm -rf "$ISO_ROOT"

# Step 4: Convert ISO to QCOW2
echo "⚙️  Converting ISO to QCOW2..."
qemu-img convert -f raw -O qcow2 "$ISO_FILE" "$OUTPUT_IMG"
rm -f "$ISO_FILE"

QCOW2_HASH=$(sha256sum "$OUTPUT_IMG" | awk '{print $1}')

# Step 5: Record build metadata
echo ""
echo "📝 Recording build metadata..."
NIXPKGS_COMMIT=$(nix-instantiate --eval -E '(import <nixpkgs> {}).lib.version' 2>/dev/null | tr -d '"' || echo "unknown")

echo "$INITRAMFS_HASH" > "${INITRAMFS_FILE}.sha256"
echo "$QCOW2_HASH" > "${OUTPUT_IMG}.sha256"

cat > build-manifest.json <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "source_date_epoch": "$SOURCE_DATE_EPOCH",
  "build_environment": "firebase.studio native (nix-build)",
  "nixpkgs_version": "$NIXPKGS_COMMIT",
  "target": "$BUILD_TARGET",
  "initramfs_sha256": "$INITRAMFS_HASH",
  "qcow2_sha256": "$QCOW2_HASH"
}
EOF

echo ""
echo "✅ Build complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📦 Initramfs: $INITRAMFS_FILE"
echo "   SHA256: $INITRAMFS_HASH"
echo "   Size: $(du -h "$INITRAMFS_FILE" | cut -f1)"
echo ""
echo "💿 QCOW2 Image: $OUTPUT_IMG"
echo "   SHA256: $QCOW2_HASH"
echo "   Size: $(du -h "$OUTPUT_IMG" | cut -f1)"
echo ""
echo "To test the image:"
echo "  qemu-system-x86_64 -m 2G -drive file=$OUTPUT_IMG,format=qcow2 -nographic"
echo ""
