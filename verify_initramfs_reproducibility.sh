#!/bin/bash
# verify-initramfs-reproducibility.sh (Refined for Ubuntu 25.10 Build)
set -e

echo "🔬 TESTING BIT-BY-BIT REPRODUCIBILITY OF UBUNTU 25.10 INITRAMFS..."
echo "================================================================"

# Create temporary work directory
REPRO_WORKDIR="${PROJECT_ROOT:-$(pwd)}/repro-workdir"
mkdir -p "$REPRO_WORKDIR"
export TMPDIR="$REPRO_WORKDIR"
export TMP="$REPRO_WORKDIR"

REPRO_TEST_DIR="$REPRO_WORKDIR/test-$(date +%s)"
mkdir -p "$REPRO_TEST_DIR/build1" "$REPRO_TEST_DIR/build2"

function build_and_extract() {
    local target_dir=$1
    local extra_args=$2
    
    echo "🏗️  Starting build in $target_dir (args: $extra_args)..."
    # Set TMPDIR for podman/buildah specifically
    env TMPDIR="$REPRO_WORKDIR" TMP="$REPRO_WORKDIR" docker build -t repro-builder-tmp $extra_args .
    
    echo "📦 Extracting artifacts from container..."
    docker rm -f repro-dummy-tmp 2>/dev/null || true
    docker create --name repro-dummy-tmp repro-builder-tmp
    docker cp repro-dummy-tmp:/img/initramfs-paypal-auth.img "$target_dir/"
    docker cp repro-dummy-tmp:/img/vmlinuz "$target_dir/"
    docker rm -f repro-dummy-tmp
}

# 1. Build 1
build_and_extract "$REPRO_TEST_DIR/build1" ""

# 2. Build 2 (Forcing no cache to test real synthesis reproducibility)
build_and_extract "$REPRO_TEST_DIR/build2" "--no-cache"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔍 BIT-BY-BIT COMPARISON RESULTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Comparison - Initramfs
IMG1="$REPRO_TEST_DIR/build1/initramfs-paypal-auth.img"
IMG2="$REPRO_TEST_DIR/build2/initramfs-paypal-auth.img"

HASH1=$(sha256sum "$IMG1" | cut -d' ' -f1)
HASH2=$(sha256sum "$IMG2" | cut -d' ' -f1)

echo "📦 [initramfs-paypal-auth.img]"
echo "   Build 1: $HASH1"
echo "   Build 2: $HASH2"

if [ "$HASH1" = "$HASH2" ]; then
    echo "✅ SUCCESS: Initramfs images are BIT-BY-BIT IDENTICAL! 🎉"
else
    echo "❌ FAILURE: Initramfs images DIFFER!"
    if command -v diffoscope &> /dev/null; then
        echo "🔬 Running diffoscope for analysis..."
        diffoscope --html "$REPRO_WORKDIR/diff_report.html" "$IMG1" "$IMG2" || true
        echo "📄 Diff report generated at: $REPRO_WORKDIR/diff_report.html"
    fi
    exit 1
fi

# Comparison - Kernel
KERN1="$REPRO_TEST_DIR/build1/vmlinuz"
KERN2="$REPRO_TEST_DIR/build2/vmlinuz"
KHASH1=$(sha256sum "$KERN1" | cut -d' ' -f1)
KHASH2=$(sha256sum "$KERN2" | cut -d' ' -f1)

echo ""
echo "💿 [vmlinuz (Kernel)]"
echo "   Build 1: $KHASH1"
echo "   Build 2: $KHASH2"

if [ "$KHASH1" = "$KHASH2" ]; then
    echo "✅ SUCCESS: Kernel images are IDENTICAL!"
else
    echo "⚠️  WARNING: Kernel images differ (this is expected if they are pulled as 'latest' generic image version)."
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🧹 CLEANING UP..."
# rm -rf "$REPRO_TEST_DIR"
echo "✅ Test complete! (Artifacts kept for verification at $REPRO_TEST_DIR)"
