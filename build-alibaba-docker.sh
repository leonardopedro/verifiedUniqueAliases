#!/bin/bash
# =============================================================================
# build-alibaba-docker.sh - Build Alibaba Cloud bootable disk image using
# docker or podman (rootless podman works: the assembler stage needs no loop
# devices — mtools/parted operate on plain files).
#
# Produces:
#   output-alibaba/disk-alibaba.raw  - GPT + ESP (shim/grub/vmlinuz/initrd) <- upload this
#   initramfs-alibaba.img            - the initramfs alone (debug/reference)
#   paypal-auth-vm                   - the enclave binary (debug/reference)
#
# Usage: bash build-alibaba-docker.sh
# =============================================================================
set -eo pipefail

ENGINE="${CONTAINER_ENGINE:-}"
if [[ -z "$ENGINE" ]]; then
    if command -v docker >/dev/null 2>&1; then ENGINE=docker
    elif command -v podman >/dev/null 2>&1; then ENGINE=podman
    else
        echo "❌ Neither docker nor podman found"
        exit 1
    fi
fi
echo "Container engine: $ENGINE"

echo "============================================================"
echo "🐳 Building Alibaba Cloud TDX disk image"
echo "============================================================"

# Build the Docker image (initramfs + binary + assembled ESP disk)
$ENGINE build -f Dockerfile.alibaba -t paypal-auth-vm:alibaba .

# Extract artifacts from the container
echo ""
echo "📦 Extracting disk image, initramfs and binaries..."
$ENGINE rm -f tmp_alibaba 2>/dev/null || true
$ENGINE create --name tmp_alibaba paypal-auth-vm:alibaba
mkdir -p output-alibaba
$ENGINE cp tmp_alibaba:/disk-alibaba.raw ./output-alibaba/disk-alibaba.raw
$ENGINE cp tmp_alibaba:/initramfs-paypal-auth.img ./initramfs-alibaba.img
$ENGINE cp tmp_alibaba:/packages.txt ./packages-alibaba.txt
$ENGINE cp tmp_alibaba:/paypal-auth-vm-bin ./paypal-auth-vm
$ENGINE rm tmp_alibaba

echo ""
echo "============================================================"
echo "✅ Alibaba Cloud Build Complete!"
echo "============================================================"
DISK_SHA=$(sha256sum output-alibaba/disk-alibaba.raw | cut -d' ' -f1)
INITRD_SHA=$(sha256sum initramfs-alibaba.img | cut -d' ' -f1)
echo "   output-alibaba/disk-alibaba.raw: $DISK_SHA  (UPLOAD THIS)"
echo "   initramfs-alibaba.img:           $INITRD_SHA"
echo "   Size: $(du -h output-alibaba/disk-alibaba.raw | cut -f1)"
echo "============================================================"
echo ""
echo "Next steps:"
echo "  1. Export OSS bucket + import (requires aliyun CLI configured):"
echo "       export ALI_OSS_BUCKET=paypal-image-<yourid>"
echo "       bash import-alibaba-image.sh"
echo "  2. Deploy (TDX spot instance):"
echo "       export ALI_IMAGE_ID=<image id printed above>"
echo "       bash deploy-alibaba.sh"
echo ""

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "disk-sha256=$DISK_SHA" >> "$GITHUB_OUTPUT"
    echo "initrd-sha256=$INITRD_SHA" >> "$GITHUB_OUTPUT"
fi
