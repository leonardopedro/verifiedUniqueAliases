#!/bin/bash
# =============================================================================
# build-forwarder-image.sh - Build the 1 GiB TCP pass-through helper disk.
#
# The forwarder is the egress remedy for a target that refuses the notary's
# source address on every pinned address at once (docs/tls-proxy.md, "Egress,
# and what compensates for it"). It is a haproxy `mode tcp` byte pipe to
# api-m's pinned edges: the notary pins `api-m.paypal.com@<forwarder IP>`, the
# TLS handshake passes through untouched, and PayPal's own certificate is what
# gets verified — so the transcript, the measurement audit and verify.html are
# unchanged by its presence.
#
# Usage: bash build-forwarder-image.sh
# Produces: output-forwarder/disk-forwarder.raw  (upload this + ImportImage)
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
echo "🔀 Building TCP pass-through forwarder disk (1 GiB, BIOS)"
echo "=============================================================="
# debootstrap needs in-container mounts (proc bind): grant them explicitly, the
# same way the relay build does. Rootless podman maps SYS_ADMIN inside the
# build user namespace, which is enough and touches nothing outside the build.
$ENGINE build --security-opt seccomp=unconfined --cap-add=SYS_ADMIN \
    -f Dockerfile.forwarder -t paypal-forwarder:latest . || {
    # userns-based builds need the newer builder; fall back to it with a note
    echo "⚠️  classic build failed; retrying with --userns=host"
    $ENGINE build --userns=host --security-opt seccomp=unconfined --cap-add=SYS_ADMIN \
        -f Dockerfile.forwarder -t paypal-forwarder:latest .
}

$ENGINE rm -f tmp_forwarder 2>/dev/null || true
$ENGINE create --name tmp_forwarder paypal-forwarder:latest >/dev/null
mkdir -p output-forwarder
$ENGINE cp tmp_forwarder:/disk-forwarder.raw ./output-forwarder/disk-forwarder.raw
$ENGINE rm tmp_forwarder >/dev/null

SHA=$(sha256sum output-forwarder/disk-forwarder.raw | cut -d' ' -f1)
SIZE=$(stat -c%s output-forwarder/disk-forwarder.raw)
echo "=============================================================="
echo "✅ Forwarder disk built"
echo "   output-forwarder/disk-forwarder.raw  sha256=$SHA"
echo "   size: $SIZE bytes"
echo "=============================================================="
cat <<'NEXT'
Next:
  1. Upload to the HONG KONG bucket (ImportImage rejects cross-region, and the
     OSS data plane is geo-blocked from outside mainland for the Beijing one):
       aliyun oss cp output-forwarder/disk-forwarder.raw \
         oss://paypal-tdx-relay-1792227992/forwarder/disk-forwarder.raw
  2. aliyun ecs ImportImage --RegionId cn-hongkong \
       --ImageName paypal-tcp-forwarder-$(date +%Y%m%d%H%M) \
       --DiskDeviceMapping.1.OSSBucket paypal-tdx-relay-1792227992 \
       --DiskDeviceMapping.1.OSSObject forwarder/disk-forwarder.raw \
       --DiskDeviceMapping.1.Format RAW --Architecture x86_64 \
       --OSType Linux --Platform Debian --BootMode BIOS
  3. RunInstances in cn-hongkong with a VPC + security group that admits 443,
     then bind an EIP. See deploy-forwarder.sh.
NEXT
