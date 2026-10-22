#!/bin/bash
# =============================================================================
# build-relay-image.sh - Build the minimal 1 GiB OSS-transfer relay disk.
#
# The relay is a helper VM only: it shuttles the enclave disk image between
# the HK bucket and the Beijing bucket (intranet PUT), driven purely by an
# IMDS user_data script at boot, then powers itself off. No sshd, no aliyun
# agent, no cloud-init — see Dockerfile.relay.
#
# Usage: bash build-relay-image.sh
# Produces: output-relay/disk-relay.raw  (upload this + ImportImage)
# =============================================================================
set -eo pipefail

ENGINE="${CONTAINER_ENGINE:-}"
if [[ -z "$ENGINE" ]]; then
    if command -v docker >/dev/null 2>&1; then ENGINE=docker
    elif command -v podman >/dev/null 2>&1; then ENGINE=podman
    else echo "❌ Neither docker nor podman found"; exit 1
    fi
fi

echo "=============================================================="
echo "🌉 Building minimal relay disk image (1 GiB, BIOS)"
echo "=============================================================="
# debootstrap needs in-container mounts (proc bind) — grant them explicitly;
# rootless podman maps SYS_ADMIN inside the build user namespace, which is
# enough for proc/tmpfs/bind mounts and touches nothing outside the build.
$ENGINE build --security-opt seccomp=unconfined --cap-add=SYS_ADMIN \
    -f Dockerfile.relay -t paypal-relay:latest .

$ENGINE rm -f tmp_relay 2>/dev/null || true
$ENGINE create --name tmp_relay paypal-relay:latest >/dev/null
mkdir -p output-relay
$ENGINE cp tmp_relay:/disk-relay.raw ./output-relay/disk-relay.raw
$ENGINE rm tmp_relay >/dev/null

SHA=$(sha256sum output-relay/disk-relay.raw | cut -d' ' -f1)
SIZE=$(stat -c%s output-relay/disk-relay.raw)
echo "=============================================================="
echo "✅ Relay disk built"
echo "   output-relay/disk-relay.raw  sha256=$SHA"
echo "   size: $SIZE bytes"
echo "=============================================================="
echo "Next: upload (via the CURRENT relay, its last job), ImportImage,"
echo "      then rewrite the EXISTING relay's disk in place:"
echo "      StopInstance -> ReplaceSystemDisk --ImageId <new> -> StartInstance."
echo "      Do NOT create a new relay VM or release the old one"
echo "      (see AGENTS.md 'Instance & Disk Policy'):"
echo "   export ALI_OSS_BUCKET=paypal-tdx-image-1792145409"
echo "   bash import-alibaba-image.sh   # then ReplaceSystemDisk + self-test boot"
