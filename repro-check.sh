#!/bin/bash
set -e

echo "🧪 Starting Reproducibility Check..."

# Build 1
echo "🔄 Running Build 1..."
/app/build-initramfs-dracut.sh
mv initramfs-paypal-auth.img initramfs.1.img

# Build 2
echo "🔄 Running Build 2..."
/app/build-initramfs-dracut.sh
mv initramfs-paypal-auth.img initramfs.2.img

# Compare
echo "🔍 Comparing builds..."
SHA1=$(sha256sum initramfs.1.img | cut -d' ' -f1)
SHA2=$(sha256sum initramfs.2.img | cut -d' ' -f1)

echo "Build 1 SHA256: $SHA1"
echo "Build 2 SHA256: $SHA2"

if [ "$SHA1" == "$SHA2" ]; then
    echo "✅ Builds are REPRODUCIBLE!"
else
    echo "❌ Builds are NOT reproducible."
    echo "Running diffoscope..."
    diffoscope --html diff.html initramfs.1.img initramfs.2.img
    echo "Diff report saved to diff.html"
    exit 1
fi
