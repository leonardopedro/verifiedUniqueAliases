#!/bin/bash
# ==============================================================================
# build-alibaba-docker.sh - Build Alibaba Cloud disk image using Docker
#
# This script builds the initramfs and binary inside a Docker container for 100%
# reproducibility, then creates the disk image on the host (loop devices don't
# work inside containers without --privileged).
#
# Usage: bash build-alibaba-docker.sh
# ==============================================================================
set -eo pipefail

echo "============================================================"
echo "🐳 Building Alibaba Cloud VM using Docker"
echo "============================================================"

# Build the Docker image (initramfs + binary)
docker build -f Dockerfile.alibaba -t paypal-auth-vm:alibaba .

# Extract artifacts from the container
echo ""
echo "📦 Extracting initramfs and binaries..."
docker rm -f tmp_alibaba 2>/dev/null || true
docker create --name tmp_alibaba paypal-auth-vm:alibaba
docker cp tmp_alibaba:/initramfs-paypal-auth.img ./initramfs-alibaba.img
docker cp tmp_alibaba:/packages.txt ./packages-alibaba.txt
docker cp tmp_alibaba:/paypal-auth-vm-bin ./paypal-auth-vm
docker rm tmp_alibaba

echo ""
echo "✅ Initramfs extracted (contains kernel + binary)"
echo "   The initramfs is all you need to boot - no separate disk required!"
echo ""

# Create disk image on host (optional, for persistent data)
echo "Creating optional ext4 filesystem for persistent data..."
bash build-alibaba-simple.sh "$BINARY"

# Compute hashes
echo ""
echo "📋 Computing SHA256 hashes..."
INITRD_SHA=$(sha256sum initramfs-alibaba.img | cut -d' ' -f1)
FS_SHA=$(sha256sum output-alibaba-simple/alibaba-fs.img 2>/dev/null | cut -d' ' -f1 || echo "N/A")

echo ""
echo "============================================================"
echo "✅ Alibaba Cloud Build Complete!"
echo "============================================================"
echo "   initramfs-alibaba.img:  $INITRD_SHA (REQUIRED for boot)"
echo "   alibaba-fs.img:         $FS_SHA (optional, persistent data)"
echo "============================================================"
echo ""
echo "Next steps:"
echo "  1. Upload initramfs-alibaba.img to OSS:"
echo "     ossutil cp initramfs-alibaba.img oss://your-bucket/paypal-auth-vm/"
echo "     OR upload alibaba-fs.img if you need persistent storage"
echo "  2. Import as custom image via ECS console or API"
echo "  3. Deploy: bash deploy-alibaba.sh"
echo ""

# Output for GitHub Actions if present
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "disk-sha256=$DISK_SHA" >> "$GITHUB_OUTPUT"
    echo "initrd-sha256=$INITRD_SHA" >> "$GITHUB_OUTPUT"
fi
