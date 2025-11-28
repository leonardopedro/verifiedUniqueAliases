#!/bin/bash
set -e

echo "🔬 Testing Initramfs Reproducibility"
echo "===================================="
echo ""

# Create temporary directories for builds
mkdir -p /tmp/repro-test/build1
mkdir -p /tmp/repro-test/build2

echo "📦 Building Initramfs - Build 1..."
DOCKER_BUILDKIT=1 docker build --output /tmp/repro-test/build1 .

echo ""
echo "📦 Building Initramfs - Build 2..."
DOCKER_BUILDKIT=1 docker build --output /tmp/repro-test/build2 .

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔍 Comparison Results"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

IMG1="/tmp/repro-test/build1/img/initramfs-paypal-auth.img"
IMG2="/tmp/repro-test/build2/img/initramfs-paypal-auth.img"

if [ ! -f "$IMG1" ] || [ ! -f "$IMG2" ]; then
    echo "❌ Error: Build artifacts not found!"
    exit 1
fi

HASH1=$(sha256sum "$IMG1" | cut -d' ' -f1)
HASH2=$(sha256sum "$IMG2" | cut -d' ' -f1)

echo "   Build 1 SHA256: $HASH1"
echo "   Build 2 SHA256: $HASH2"
echo ""

if [ "$HASH1" = "$HASH2" ]; then
    echo "✅ SUCCESS: Initramfs images are IDENTICAL! 🎉"
    echo "   The build is reproducible."
else
    echo "❌ FAILURE: Initramfs images are DIFFERENT!"
    echo "   The build is NOT reproducible."
    
    if command -v diffoscope &> /dev/null; then
        echo ""
        echo "🔬 Running diffoscope..."
        diffoscope "$IMG1" "$IMG2"
    fi
    exit 1
fi

echo ""
echo "🧹 Cleaning up..."
rm -rf /tmp/repro-test

echo "✅ Test complete!"
