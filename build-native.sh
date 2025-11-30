#!/bin/bash
# Native build script for firebase.studio
# Builds the initramfs and qcow2 image directly without QEMU/Docker/Podman

set -e

echo "🏗️  Building reproducible initramfs and qcow2 image natively..."

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
RAW_IMG="disk.raw"

echo "📍 Build directory: $BUILD_DIR"
echo "🎯 Target: $BUILD_TARGET"
echo ""

# Step 1: Build Rust binary with reproducibility flags
echo "📦 Building Rust application..."
rustup target add $BUILD_TARGET 2>/dev/null || true

export RUSTFLAGS="-C target-cpu=generic -C codegen-units=1 -C strip=symbols"
export CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_OPT_LEVEL=2

# Note: Binary build happens inside dracut module-setup.sh
# This keeps the build process consistent with the QEMU/Docker approach

# Step 2: Prepare dracut module
echo "📋 Preparing dracut module..."

# Always remove and re-copy to ensure clean state
sudo rm -rf /usr/lib/dracut/modules.d/99paypal-auth-vm
sudo mkdir -p /usr/lib/dracut/modules.d/
sudo cp -r ./dracut-module/99paypal-auth-vm /usr/lib/dracut/modules.d/
sudo chmod +x /usr/lib/dracut/modules.d/99paypal-auth-vm/*.sh

# Update module-setup.sh with correct build path
sudo sed -i "s|cd /app|cd $BUILD_DIR|g" \
    /usr/lib/dracut/modules.d/99paypal-auth-vm/module-setup.sh

# Update cargo paths for native environment
sudo sed -i "s|source /usr/local/cargo/env|export PATH=\"$HOME/.cargo/bin:\$PATH\"|g" \
    /usr/lib/dracut/modules.d/99paypal-auth-vm/module-setup.sh

# Ensure absolute cargo paths
sudo sed -i "s| cargo build| $HOME/.cargo/bin/cargo build|g" \
    /usr/lib/dracut/modules.d/99paypal-auth-vm/module-setup.sh
sudo sed -i "s| add-det | $HOME/.cargo/bin/add-det |g" \
    /usr/lib/dracut/modules.d/99paypal-auth-vm/module-setup.sh

# Update target architecture
sudo sed -i "s|x86_64-unknown-linux-gnu|$BUILD_TARGET|g" \
    /usr/lib/dracut/modules.d/99paypal-auth-vm/module-setup.sh

# Normalize module timestamps for reproducibility
echo "🔧 Normalizing module timestamps..."
sudo find /usr/lib/dracut/modules.d/99paypal-auth-vm -type f -exec touch -d "@${SOURCE_DATE_EPOCH}" {} \;

# Step 3: Configure dracut
echo "📝 Configuring dracut..."
sudo mkdir -p /etc/dracut.conf.d
sudo cp dracut.conf /etc/dracut.conf.d/99force-no-hostonly.conf
sudo cp dracut.conf /etc/dracut.conf

# Verify module is visible
echo "🔍 Verifying dracut module..."
if dracut --list-modules 2>&1 | grep -q paypal; then
    echo "✅ Dracut sees the paypal-auth-vm module"
else
    echo "⚠️  Warning: Dracut may not see the module"
fi

# Step 4: Build initramfs
echo "🔨 Building initramfs with dracut..."

KERNEL_VERSION=$(find /nix/store -path "*/lib/modules/*" -type d -name "[0-9]*" 2>/dev/null | head -1 | xargs basename)
if [ -z "$KERNEL_VERSION" ]; then
    echo "❌ Could not find kernel version in /nix/store"
    exit 1
fi
echo "   Kernel version: $KERNEL_VERSION"

# Create temporary directory
mkdir -p "$HOME/dracut-build"

# Build with reproducibility flags
sudo dracut \
    --force \
    --reproducible \
    --gzip \
    --omit " dash plymouth syslog firmware " \
    --no-hostonly \
    --no-hostonly-cmdline \
    --nofscks \
    --no-early-microcode \
    --add "paypal-auth-vm" \
    --kver "$KERNEL_VERSION" \
    --fwdir "/nix/store/*/lib/firmware" \
    --tmpdir "$HOME/dracut-build" \
    "$INITRAMFS_FILE"

# Fix permissions
sudo chown $(whoami):$(whoami) "$INITRAMFS_FILE" || true

# Check if dracut succeeded
if [ ! -f "$INITRAMFS_FILE" ]; then
    echo "❌ Initramfs build failed! File not found: $INITRAMFS_FILE"
    exit 1
fi

# Step 5: Normalize initramfs
echo "🔧 Normalizing initramfs for reproducibility..."
if command -v gzip >/dev/null && command -v add-det &>/dev/null; then
    # Decompress
    gzip -d -c "$INITRAMFS_FILE" > "$INITRAMFS_FILE.uncompressed"
    
    # Normalize uncompressed archive
    add-det "$INITRAMFS_FILE.uncompressed"
    
    # Recompress with deterministic gzip
    gzip -n -9 < "$INITRAMFS_FILE.uncompressed" > "$INITRAMFS_FILE.tmp"
    
    # Normalize compressed archive
    add-det "$INITRAMFS_FILE.tmp"
    
    # Replace original
    mv "$INITRAMFS_FILE.tmp" "$INITRAMFS_FILE"
    rm -f "$INITRAMFS_FILE.uncompressed"
    
    echo "✅ Normalization complete"
else
    echo "⚠️  gzip or add-det not found, skipping normalization"
fi

# Calculate hash
INITRAMFS_HASH=$(sha256sum "$INITRAMFS_FILE" | cut -d' ' -f1)
echo "📊 Initramfs SHA256: $INITRAMFS_HASH"

# Step 6: Create bootable qcow2 image
echo ""
echo "💿 Creating bootable QCOW2 image..."

# Create raw disk file (2GB)
truncate -s 2G "$RAW_IMG"

# Partition disk (GPT)
parted -s "$RAW_IMG" mklabel gpt
parted -s "$RAW_IMG" mkpart primary ext4 1MiB 100%
parted -s "$RAW_IMG" set 1 bios_grub on

# Setup loop device
LOOP_DEV=$(sudo losetup -fP --show "$RAW_IMG")
echo "   Loop device: $LOOP_DEV"

# Ensure cleanup on exit
trap "sudo losetup -d $LOOP_DEV 2>/dev/null || true" EXIT

# Format partition
sudo mkfs.ext4 "${LOOP_DEV}p1"

# Mount
MOUNT_DIR=$(mktemp -d)
sudo mount "${LOOP_DEV}p1" "$MOUNT_DIR" || { echo "❌ Mount failed"; exit 1; }

# Ensure cleanup includes umount
trap "sudo umount $MOUNT_DIR 2>/dev/null || true; sudo losetup -d $LOOP_DEV 2>/dev/null || true; rm -rf $MOUNT_DIR" EXIT

# Install kernel and initramfs
sudo mkdir -p "$MOUNT_DIR/boot"

# Find kernel in nix store
KERNEL_FILE=$(find /nix/store -name "vmlinuz-$KERNEL_VERSION" 2>/dev/null | head -1)
if [ -z "$KERNEL_FILE" ]; then
    # Try alternative pattern
    KERNEL_FILE=$(find /nix/store -path "*/boot/vmlinuz*" 2>/dev/null | head -1)
fi

if [ -z "$KERNEL_FILE" ]; then
    echo "❌ No kernel found in /nix/store"
    exit 1
fi

echo "   Using kernel: $KERNEL_FILE"
sudo cp "$KERNEL_FILE" "$MOUNT_DIR/boot/vmlinuz"
sudo cp "$INITRAMFS_FILE" "$MOUNT_DIR/boot/initramfs.img"

# Install GRUB with proper modules for reliable booting
sudo grub-install \
    --target=i386-pc \
    --boot-directory="$MOUNT_DIR/boot" \
    --modules="part_gpt part_msdos ext2 biosdisk" \
    --force \
    "$LOOP_DEV"

# Configure GRUB (create directory and config file)
sudo mkdir -p "$MOUNT_DIR/boot/grub"
sudo tee "$MOUNT_DIR/boot/grub/grub.cfg" > /dev/null <<EOF
set default=0
set timeout=1

menuentry 'PayPal Auth VM' {
    linux /boot/vmlinuz root=/dev/sda1 ro console=ttyS0
    initrd /boot/initramfs.img
}
EOF

# Cleanup mounts
sudo umount "$MOUNT_DIR"
sudo losetup -d "$LOOP_DEV"
rm -rf "$MOUNT_DIR"
trap - EXIT  # Clear trap

# Convert to QCOW2
qemu-img convert -f raw -O qcow2 "$RAW_IMG" "$OUTPUT_IMG"
rm -f "$RAW_IMG"

# Calculate final hash
QCOW2_HASH=$(sha256sum "$OUTPUT_IMG" | cut -d' ' -f1)

# Step 7: Record nixpkgs version for reproducibility
echo ""
echo "📝 Recording build metadata..."

# Try to find nixpkgs revision
NIXPKGS_COMMIT="unknown"
if [ -f "$HOME/.nix-profile/manifest.nix" ]; then
    NIXPKGS_COMMIT=$(nix-instantiate --eval -E '(import <nixpkgs> {}).lib.version' 2>/dev/null | tr -d '"' || echo "unknown")
fi

# Save hashes
echo "$INITRAMFS_HASH" > "${INITRAMFS_FILE}.sha256"
echo "$QCOW2_HASH" > "${OUTPUT_IMG}.sha256"

# Create build manifest
cat > build-manifest.json <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "source_date_epoch": "$SOURCE_DATE_EPOCH",
  "build_environment": "firebase.studio native",
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
