#!/bin/bash
# ==============================================================================
# build-alibaba-docker.sh - Canonical, reproducible Alibaba Cloud build.
#
# Builds the binary + initramfs + minimal EFI RAW disk IMAGE entirely inside a
# Docker container (pinned Debian snapshot, pinned Rust) for 100% reproducibility,
# then extracts the finished disk image (disk-alibaba.raw) to the host.
#
# The instance receives the finished image (no in-cloud reassembly).
#
# Usage: bash build-alibaba-docker.sh
# ==============================================================================
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================================"
echo "🐳 Building Alibaba Cloud image using Docker (reproducible)"
echo "============================================================"

# Build only the 'assembler' stage (which chains rust-builder -> image-builder).
# The local engine is podman; mknod (used to create the /dev device nodes in
# the initramfs) is blocked by the default seccomp profile, which would
# silently drop the device nodes and make the local initramfs differ from CI.
# --security-opt seccomp=unconfined + --cap-add CAP_MKNOD permits mknod, matching
# CI's privileged Docker runner so the outputs are byte-identical.
docker build --security-opt seccomp=unconfined --cap-add CAP_MKNOD --target assembler -f Dockerfile.alibaba -t paypal-auth-vm:alibaba .

# Extract the finished disk image (built deterministically inside the container)
echo ""
echo "📦 Extracting disk-alibaba.raw from container..."
docker rm -f tmp_alibaba 2>/dev/null || true
docker create --name tmp_alibaba paypal-auth-vm:alibaba
docker cp tmp_alibaba:/disk-alibaba.raw ./disk-alibaba.raw
docker rm tmp_alibaba

echo ""
echo "📋 Computing SHA256..."
DISK_SHA=$(sha256sum disk-alibaba.raw | cut -d' ' -f1)
DISK_SIZE=$(stat -c%s disk-alibaba.raw)

echo ""
echo "============================================================"
echo "✅ Alibaba Cloud Build Complete!"
echo "============================================================"
echo "   disk-alibaba.raw: $DISK_SHA"
echo "   size:             $DISK_SIZE bytes ($(( DISK_SIZE / 1048576 )) MiB)"
echo "============================================================"
echo ""
echo "Next steps:"
echo "  1. Push disk-alibaba.raw to GitHub LFS (or upload directly to OSS):"
echo "       git lfs track disk-alibaba.raw && git add disk-alibaba.raw && git commit && git push"
echo "  2. On the build instance, pull it and upload to OSS (internal endpoint):"
echo "       ossutil -c ossutil-internal.config cp disk-alibaba.raw oss://paypal-auth-vm/disk-alibaba.raw"
echo "  3. Import as custom image via ECS and deploy: bash deploy-alibaba.sh"
echo ""

# Output for GitHub Actions if present
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "disk-sha256=$DISK_SHA" >> "$GITHUB_OUTPUT"
    echo "disk-size=$DISK_SIZE" >> "$GITHUB_OUTPUT"
fi
