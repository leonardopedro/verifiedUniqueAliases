#!/bin/bash
# Quick verification script to check if the environment is ready for native builds

echo "🔍 Checking build environment..."
echo ""

# Check for required commands
MISSING_TOOLS=()

check_tool() {
    if ! command -v "$1" &> /dev/null; then
        MISSING_TOOLS+=("$1")
        echo "❌ Missing: $1"
    else
        VERSION=$($1 --version 2>&1 | head -1 || echo "installed")
        echo "✅ Found: $1 ($VERSION)"
    fi
}

echo "Checking required tools:"
check_tool rustc
check_tool cargo
check_tool dracut
check_tool grub-install
check_tool parted
check_tool mkfs.ext4
check_tool qemu-img
check_tool losetup
check_tool add-det

echo ""

# Check for sudo access
if sudo -n true 2>/dev/null; then
    echo "✅ Sudo access: Available"
else
    echo "⚠️  Sudo access: May require password"
    echo "   (Needed for dracut module installation and loop devices)"
fi

echo ""

# Check for kernel
KERNEL_COUNT=$(find /nix/store -path "*/lib/modules/*" -type d -name "[0-9]*" 2>/dev/null | wc -l)
if [ "$KERNEL_COUNT" -gt 0 ]; then
    KERNEL_VERSION=$(find /nix/store -path "*/lib/modules/*" -type d -name "[0-9]*" 2>/dev/null | head -1 | xargs basename)
    echo "✅ Kernel found: $KERNEL_VERSION"
else
    echo "❌ No kernel found in /nix/store"
    echo "   Install with: pkgs.linux in dev.nix"
fi

echo ""

# Summary
if [ ${#MISSING_TOOLS[@]} -eq 0 ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "✅ Environment ready for native builds!"
    echo "   Run: ./build-native.sh"
else
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "❌ Missing required tools:"
    for tool in "${MISSING_TOOLS[@]}"; do
        echo "   - $tool"
    done
    echo ""
    echo "Please update .idx/dev.nix and rebuild the workspace"
fi
