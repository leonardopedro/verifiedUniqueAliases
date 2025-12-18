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
# Use musl target for static linking
BUILD_TARGET="x86_64-unknown-linux-musl"
INITRAMFS_FILE="$BUILD_DIR/initramfs-paypal-auth.img"
OUTPUT_IMG="$BUILD_DIR/paypal-auth-vm.qcow2"
ISO_FILE="$BUILD_DIR/boot.iso"
ISO_ROOT="$BUILD_DIR/iso_root"

echo "📍 Build directory: $BUILD_DIR"
echo "🎯 Target: $BUILD_TARGET"
echo ""

# Clean up previous build artifacts
rm -rf "$ISO_ROOT" "$INITRAMFS_FILE" "$ISO_FILE" result

# Step 1: Build Rust binary (Static)
echo "🦀 Building Rust binary (static)..."
rustup target add "$BUILD_TARGET" 2>/dev/null || true

# Check if linker is available
if ! command -v x86_64-unknown-linux-musl-gcc &>/dev/null; then
    echo "⚠️  Linker 'x86_64-unknown-linux-musl-gcc' not found in PATH."
    echo "    Please ensure you are in the nix-shell environment."
    echo "    Run: nix-shell"
    exit 1
fi

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

# Step 3: Create UEFI Disk Image (FAT32 ESP)
echo ""
echo "💿 Creating UEFI disk image..."

RAW_DISK="disk.raw"
ESP_IMG="esp.img"

# 1. Create a 256MB raw disk image
qemu-img create -f raw "$RAW_DISK" 256M

# 2. Partition it with GPT and a single ESP partition
# Start at 1MB (2048 sectors), End at 255MB (leaving 1MB for backup GPT)
# We use 'parted' which is in shell.nix
parted -s "$RAW_DISK" mklabel gpt mkpart ESP fat32 2048s 255MB set 1 esp on

# 3. Create the ESP filesystem image separately
# Size = 254MB (Fits within the 1MB to 255MB range)
dd if=/dev/zero of="$ESP_IMG" bs=1M count=254

# Format as FAT32 using mtools
mformat -i "$ESP_IMG" -F ::

# Create directory structure
mmd -i "$ESP_IMG" ::EFI
mmd -i "$ESP_IMG" ::EFI/BOOT
mmd -i "$ESP_IMG" ::boot

# 4. Create GRUB EFI bootloader
echo "   Building GRUB EFI binary..."
GRUB_MODULES="part_gpt fat normal console serial terminal boot linux configfile xzio echo test loadenv search search_fs_file search_fs_uuid search_label cat"

# Check for grub modules location
GRUB_LIB="/usr/lib/grub/x86_64-efi"
if [ ! -d "$GRUB_LIB" ]; then
    # Helper to find where nix installed grub
    GRUB_LIB=$(find /nix/store -name "x86_64-efi" -type d | head -n 1)
    if [ -z "$GRUB_LIB" ]; then
        echo "❌ Could not find GRUB EFI modules!"
        exit 1
    fi
fi
echo "   Using GRUB modules from: $GRUB_LIB"

grub-mkimage \
    -d "$GRUB_LIB" \
    -O x86_64-efi \
    -o BOOTX64.EFI \
    -p /EFI/BOOT \
    $GRUB_MODULES

# 5. Create GRUB config
cat > grub.cfg <<EOF
set timeout=1
set default=0

menuentry 'PayPal Auth VM' {
    # Search for the partition containing the kernel by looking for a marker file or just standard path
    # Since we have one partition, root=(hd0,gpt1) is likely but let's be safe
    linux /boot/vmlinuz ro console=ttyS0
    initrd /boot/initramfs.img
}
EOF

# 6. Copy files to ESP
echo "   Populating ESP..."
mcopy -i "$ESP_IMG" BOOTX64.EFI ::EFI/BOOT/BOOTX64.EFI
mcopy -i "$ESP_IMG" grub.cfg ::EFI/BOOT/grub.cfg
mcopy -i "$ESP_IMG" "$KERNEL_FILE" ::boot/vmlinuz
mcopy -i "$ESP_IMG" "$INITRAMFS_FILE" ::boot/initramfs.img

# 7. Merge ESP into the raw disk image at offset 1MB
echo "   Merging ESP into disk image..."
dd if="$ESP_IMG" of="$RAW_DISK" bs=1M seek=1 conv=notrunc status=none

# Cleanup intermediate files
rm -f "$ESP_IMG" BOOTX64.EFI grub.cfg

# Step 4: Convert to QCOW2
echo "⚙️  Converting to QCOW2..."
qemu-img convert -f raw -O qcow2 "$RAW_DISK" "$OUTPUT_IMG"
rm -f "$RAW_DISK"

# Normalize QCOW2 for reproducibility
echo "🔧 Normalizing QCOW2 image..."
if command -v add-det &>/dev/null; then
    add-det "$OUTPUT_IMG"
    echo "   ✅ QCOW2 normalized"
else
    echo "   ⚠️  add-det not found, skipping QCOW2 normalization"
fi

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
echo "  qemu-system-x86_64 -m 2G -drive file=$OUTPUT_IMG,format=qcow2 -nic user,model=virtio-net-pci -nographic"
echo ""
