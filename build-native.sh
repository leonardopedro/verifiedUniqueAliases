#!/bin/bash
# Native build script for firebase.studio
# Builds the initramfs and qcow2 image directly without QEMU/Docker/Podman/sudo
# qemu-system-x86_64 -bios /usr/share/ovmf/OVMF.fd -m 2G -drive file=paypal-auth-vm.qcow2,format=qcow2 -nic user,model=virtio-net-pci -nographic

set -e

# Parse arguments
SKIP_INITRAMFS=false
for arg in "$@"; do
    case $arg in
        --skip-initramfs)
            SKIP_INITRAMFS=true
            shift
            ;;
    esac
done

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
if [ "$SKIP_INITRAMFS" = true ]; then
    echo "🧹 Partial cleanup (preserving initramfs/kernel for skip)..."
    rm -rf "$ISO_ROOT" "$ISO_FILE" result ESP.img disk.raw
else
    echo "🧹 Full cleanup..."
    rm -rf "$ISO_ROOT" "$INITRAMFS_FILE" "$ISO_FILE" result ESP.img disk.raw vmlinuz
fi

# Step 1: Build Rust binary (Static)
if [ "$SKIP_INITRAMFS" = true ]; then
    echo "⏭️  Skipping Rust binary build (--skip-initramfs)"
else
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
    export BUILD_TARGET

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
fi

# Step 2: Build Initramfs and get Kernel using Dracut
INITRAMFS_SRC="initramfs-paypal-auth.img"
KERNEL_SRC="vmlinuz"

if [ "$SKIP_INITRAMFS" = true ]; then
    echo "⏭️  Skipping initramfs build (--skip-initramfs)"
    echo "   Using existing: $INITRAMFS_SRC and $KERNEL_SRC"
    
    if [ ! -f "$INITRAMFS_SRC" ]; then
        echo "❌ Initramfs not found! Run ./build-docker.sh first."
        exit 1
    fi
    if [ ! -f "$KERNEL_SRC" ]; then
        echo "❌ Kernel not found! Run ./build-docker.sh first."
        exit 1
    fi
else
    echo "❄️  Building initramfs with Dracut..."
    ./build-initramfs-dracut.sh
    
    if [ ! -f "$KERNEL_SRC" ]; then
        echo "❌ Kernel not found at $KERNEL_SRC"
        exit 1
    fi
    
    if [ ! -f "$INITRAMFS_SRC" ]; then
        echo "❌ Initramfs build failed!"
        exit 1
    fi
fi

# Move to expected locations
if [ "$(realpath "$INITRAMFS_SRC")" != "$(realpath "$INITRAMFS_FILE")" ]; then
    cp "$INITRAMFS_SRC" "$INITRAMFS_FILE"
fi
KERNEL_FILE="$KERNEL_SRC"

echo "✅ Initramfs: $INITRAMFS_FILE"
echo "   Kernel: $KERNEL_FILE"

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
# 4. Create Unified Kernel Image (UKI)
echo "   Creating Unified Kernel Image (UKI)..."

# Find UEFI boot stub (portable across Nix and FHS distros like Debian)
STUB_FILE=""
SEARCH_PATHS=(
    "/usr/lib/systemd/boot/efi/linuxx64.efi.stub"
    "/lib/systemd/boot/efi/linuxx64.efi.stub"
    "/usr/lib/systemd/boot/efi/x86_64/linuxx64.efi.stub"
)

# Check standard FHS paths first
for path in "${SEARCH_PATHS[@]}"; do
    if [ -f "$path" ]; then
        STUB_FILE="$path"
        break
    fi
done

# Fallback to nix-store if not found
if [ -z "$STUB_FILE" ]; then
    STUB_FILE=$(find /nix/store -name "linuxx64.efi.stub" 2>/dev/null | head -n 1)
fi

if [ -z "$STUB_FILE" ]; then
    echo "❌ Could not find linuxx64.efi.stub!"
    echo "   On Debian/Ubuntu: sudo apt install systemd-boot"
    echo "   On Nix: Ensure 'systemd' is in buildInputs"
    exit 1
fi
echo "   Using UEFI Stub: $STUB_FILE"

# Create kernel command line
# Note: root= is handled by initrd, but we need basic console/debug flags
echo "ro console=ttyS0,115200n8 earlyprintk=ttyS0 ignore_loglevel keep_bootcon nomodeset panic=0 swiotlb=65536 pci=nommconf mem_encrypt=on nokaslr iommu=off random.trust_cpu=on acpi=noirq noapic" > cmdline.txt

# Create BOOTX64.EFI using objcopy
objcopy \
    --add-section .osrel=/etc/os-release --change-section-vma .osrel=0x20000 \
    --add-section .cmdline="cmdline.txt" --change-section-vma .cmdline=0x30000 \
    --add-section .linux="$KERNEL_FILE" --change-section-vma .linux=0x40000 \
    --add-section .initrd="$INITRAMFS_FILE" --change-section-vma .initrd=0x3000000 \
    "$STUB_FILE" BOOTX64.EFI

echo "   ✅ Generated BOOTX64.EFI"

# 5. Populate ESP
echo "   Populating ESP..."
mcopy -i "$ESP_IMG" BOOTX64.EFI ::EFI/BOOT/BOOTX64.EFI

# 6. Merge ESP into the raw disk image at offset 1MB
echo "   Merging ESP into disk image..."
dd if="$ESP_IMG" of="$RAW_DISK" bs=1M seek=1 conv=notrunc status=none

# Cleanup intermediate files
rm -f "$ESP_IMG" BOOTX64.EFI cmdline.txt

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
