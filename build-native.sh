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
BUILD_DIR=$(pwd)
BUILD_TARGET="x86_64-unknown-linux-gnu"
INITRAMFS_FILE="initramfs-paypal-auth.img"
OUTPUT_IMG="paypal-auth-vm.qcow2"
ISO_FILE="boot.iso"

# Local directories for build artifacts
DRACUT_BASE_DIR="$BUILD_DIR/dracut-local"
DRACUT_MODULE_PATH="$DRACUT_BASE_DIR/modules.d"
DRACUT_TMP_DIR="$HOME/dracut-build"
ISO_ROOT="$BUILD_DIR/iso_root"

echo "📍 Build directory: $BUILD_DIR"
echo "🎯 Target: $BUILD_TARGET"
echo ""

# Clean up previous build artifacts
rm -rf "$DRACUT_BASE_DIR" "$DRACUT_TMP_DIR" "$ISO_ROOT" "$INITRAMFS_FILE" "$ISO_FILE"

# Step 1: Prepare dracut module in a local directory that mimics the system layout
echo "📋 Preparing dracut module..."
MODULE_DIR="$DRACUT_MODULE_PATH/99paypal-auth-vm"
MODULE_SETUP_SH="$MODULE_DIR/module-setup.sh"
mkdir -p "$MODULE_DIR"

cp ./dracut-module/99paypal-auth-vm/* "$MODULE_DIR/"
chmod +x "$MODULE_DIR"/*.sh

# Update module-setup.sh with correct paths using a robust awk script
TMP_MODULE_SETUP_SH="${MODULE_SETUP_SH}.tmp"
awk \
    -v build_dir="$BUILD_DIR" \
    -v home="$HOME" \
    -v path="$PATH" \
    -v target="$BUILD_TARGET" \
'
{
    sub("cd /app", "cd " build_dir);
    sub("source /usr/local/cargo/env", "export PATH=\"" home "/.cargo/bin:" path "\"");
    sub(" cargo build", " " home "/.cargo/bin/cargo build");
    sub(" add-det ", " " home "/.cargo/bin/add-det ");
    sub("x86_64-unknown-linux-gnu", target);
    print;
}
' "$MODULE_SETUP_SH" > "$TMP_MODULE_SETUP_SH"
mv "$TMP_MODULE_SETUP_SH" "$MODULE_SETUP_SH"

# Normalize module timestamps for reproducibility
echo "🔧 Normalizing module timestamps..."
find "$MODULE_DIR" -type f -exec touch -d "@${SOURCE_DATE_EPOCH}" {} \;

# Step 2: Configure dracut locally
echo "📝 Configuring dracut..."
# We will pass the config file directly on the command line

# Verify module is visible using the --dracutdir flag
echo "🔍 Verifying dracut module..."
if dracut --dracutdir "$DRACUT_BASE_DIR" --list-modules 2>&1 | grep -q paypal; then
    echo "✅ Dracut sees the paypal-auth-vm module"
else
    echo "⚠️  Warning: Dracut may not see the module. Please check directory structure."
    exit 1
fi

# Step 3: Build initramfs
echo "🔨 Building initramfs with dracut..."

KERNEL_VERSION=$(find /nix/store -path "*/lib/modules/*" -type d -name "[0-9]*" 2>/dev/null | head -1 | xargs basename)
if [ -z "$KERNEL_VERSION" ]; then
    echo "❌ Could not find kernel version in /nix/store"
    exit 1
fi
echo "   Kernel version: $KERNEL_VERSION"

# Create temporary directory
mkdir -p "$DRACUT_TMP_DIR"

# Build with reproducibility flags and the --dracutdir flag
dracut \
    --force \
    --reproducible \
    --gzip \
    --conf "$BUILD_DIR/dracut.conf" \
    --dracutdir "$DRACUT_BASE_DIR" \
    --omit " dash plymouth syslog firmware " \
    --no-hostonly \
    --no-hostonly-cmdline \
    --nofscks \
    --no-early-microcode \
    --add "paypal-auth-vm" \
    --kver "$KERNEL_VERSION" \
    --fwdir "/nix/store/*/lib/firmware" \
    --tmpdir "$DRACUT_TMP_DIR" \
    "$INITRAMFS_FILE"

# Check if dracut succeeded
if [ ! -f "$INITRAMFS_FILE" ]; then
    echo "❌ Initramfs build failed! File not found: $INITRAMFS_FILE"
    exit 1
fi

# Step 4: Normalize initramfs
echo "🔧 Normalizing initramfs for reproducibility..."
if command -v gzip >/dev/null && command -v add-det &>/dev/null; then
    gzip -d -c "$INITRAMFS_FILE" > "$INITRAMFS_FILE.uncompressed"
    add-det "$INITRAMFS_FILE.uncompressed"
    gzip -n -9 < "$INITRAMFS_FILE.uncompressed" > "$INITRAMFS_FILE.tmp"
    add-det "$INITRAMFS_FILE.tmp"
    mv "$INITRAMFS_FILE.tmp" "$INITRAMFS_FILE"
    rm -f "$INITRAMFS_FILE.uncompressed"
    echo "✅ Normalization complete"
else
    echo "⚠️  gzip or add-det not found, skipping normalization"
fi

INITRAMFS_HASH=$(sha256sum "$INITRAMFS_FILE" | awk '{print $1}')
echo "📊 Initramfs SHA256: $INITRAMFS_HASH"

# Step 5: Create bootable ISO image with GRUB
echo ""
echo "💿 Creating bootable ISO image..."

# Prepare ISO root directory
mkdir -p "$ISO_ROOT/boot/grub"

# Find and copy kernel
KERNEL_FILE=$(find /nix/store -name "vmlinuz-$KERNEL_VERSION" 2>/dev/null | head -1 || find /nix/store -path "*/boot/vmlinuz*" 2>/dev/null | head -1)
if [ -z "$KERNEL_FILE" ]; then
    echo "❌ No kernel found in /nix/store"
    exit 1
fi
echo "   Using kernel: $KERNEL_FILE"
cp "$KERNEL_FILE" "$ISO_ROOT/boot/vmlinuz"
cp "$INITRAMFS_FILE" "$ISO_ROOT/boot/initramfs.img"

# Create GRUB config
tee "$ISO_ROOT/boot/grub/gracut.cfg" > /dev/null <<EOF
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

# Step 6: Convert ISO to QCOW2
echo "⚙️  Converting ISO to QCOW2..."
qemu-img convert -f raw -O qcow2 "$ISO_FILE" "$OUTPUT_IMG"
rm -f "$ISO_FILE"

QCOW2_HASH=$(sha256sum "$OUTPUT_IMG" | awk '{print $1}')

# Step 7: Record build metadata
echo ""
echo "📝 Recording build metadata..."
NIXPKGS_COMMIT=$(nix-instantiate --eval -E '(import <nixpkgs> {}).lib.version' 2>/dev/null | tr -d '"' || echo "unknown")

echo "$INITRAMFS_HASH" > "${INITRAMFS_FILE}.sha256"
echo "$QCOW2_HASH" > "${OUTPUT_IMG}.sha256"

cat > build-manifest.json <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "source_date_epoch": "$SOURCE_DATE_EPOCH",
  "build_environment": "firebase.studio native (no-sudo)",
  "nixpkgs_channel": "stable-24.05",
  "nixpkgs_version": "$NIXPKGS_COMMIT",
  "kernel_version": "$KERNEL_VERSION",
  "rust_version": "$(rustc --version)",
  "target": "$BUILD_TARGET",
  "initramfs_sha256": "$INITRAMFS_HASH",
  "qcow2_sha256": "$QCOW2_HASH",
  "components": {
    "rust_binary": "paypal-auth-vm",
    "dracut_version": "$(dracut --version 2>&1 | head -1)",
    "compression": "gzip -9"
  }
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
echo "📝 Build manifest: build-manifest.json"
echo ""
echo "To test the image:"
echo "  qemu-system-x86_64 -m 2G -drive file=$OUTPUT_IMG,format=qcow2 -nographic"
echo ""
