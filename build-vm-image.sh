#!/bin/bash
# ==============================================================================
# build-vm-image.sh - Build VM image for GCP Confidential VM
# Works locally and in GitHub Actions (without GCP-specific deployment)
# ==============================================================================
set -euo pipefail

echo "🏗️  Building reproducible VM image..."

# Build the Docker image
docker build -f Dockerfile.repro -t paypal-auth-vm .

# Extract artifacts from the container
echo "📦 Extracting artifacts..."
docker rm -f tmp_disk 2>/dev/null || true
docker create --name tmp_disk paypal-auth-vm
docker cp tmp_disk:/disk.tar.gz ./disk.tar.gz
docker cp tmp_disk:/initramfs-paypal-auth.img ./initramfs.img
docker rm tmp_disk

# Compute hashes
echo "📋 Computing SHA256 hashes..."
DISK_SHA=$(sha256sum disk.tar.gz | cut -d' ' -f1)
INITRD_SHA=$(sha256sum initramfs.img | cut -d' ' -f1)

echo "disk-sha256:$DISK_SHA"
echo "initrd-sha256:$INITRD_SHA"

echo ""
echo "✅ Build Complete!"
echo "   disk.tar.gz:    $DISK_SHA"
echo "   initramfs.img: $INITRD_SHA"

# Output for GitHub Actions
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "disk-sha256=$DISK_SHA" >> "$GITHUB_OUTPUT"
    echo "initrd-sha256=$INITRD_SHA" >> "$GITHUB_OUTPUT"
fi