#!/bin/bash
# =============================================================================
# extract-ol10-platform.sh — pull OL10 boot binaries from the OCI platform image
#
# Launches a short-lived (spot) 1-OCPU/1-GB instance from Oracle's official
# "Oracle Linux 10" platform image, copies vmlinuz + kernel modules + the UEFI
# shim/grub binaries off its boot volume, then TERMINATES the instance.
#
# The staged output (default: ./ol10) is consumed directly by Dockerfile.oci's
# ol10-builder stage (see `COPY ol10 /host-ol10` + fallback logic). If ./ol10
# does not contain vmlinuz (CI checkouts), the Dockerfile falls back to the
# pinned-yum extraction in extract-ol10-binaries.sh.
#
# Prerequisites:
#   - oci CLI configured
#   - ~/.ssh key for the temporary instance (default: ~/.ssh/id_ed25519_leo.pub)
#
# Usage:
#   export OCI_COMPARTMENT_ID=ocid1.compartment...
#   export OCI_SUBNET_ID=ocid1.subnet...
#   # optional: OL10_IMAGE_ID, OL10_ADMINS_SSH_KEY, OCI_AVAILABILITY_DOMAIN
#   bash extract-ol10-platform.sh [output-dir]
# =============================================================================
set -eo pipefail

COMPARTMENT_ID="${OCI_COMPARTMENT_ID:-}"
SUBNET_ID="${OCI_SUBNET_ID:-}"
IMAGE_ID="${OL10_IMAGE_ID:-ocid1.image.oc1.eu-frankfurt-1.aaaaaaaada4cogim4qsd5txra7fr7fwpcwpq6upp6kvfeah2r2aibe24afaq}"  # Oracle-Linux-10.2-2026.09.18-0
SSH_PUB="${OL10_SSH_KEY:-$HOME/.ssh/id_ed25519_leo.pub}"
OUT="${1:-ol10}"
SHAPE="${OCI_SHAPE:-VM.Standard.E5.Flex}"

if ! command -v oci &> /dev/null || ! command -v ssh &> /dev/null || ! command -v scp &> /dev/null; then
    echo "❌ need 'oci', 'ssh' and 'scp' in PATH"; exit 1
fi
if [[ -z "$COMPARTMENT_ID" || -z "$SUBNET_ID" ]]; then
    echo "❌ Set OCI_COMPARTMENT_ID and OCI_SUBNET_ID"; exit 1
fi
if [[ ! -f "$SSH_PUB" ]]; then
    echo "❌ SSH public key not found: $SSH_PUB"; exit 1
fi

if [[ -z "${OCI_AVAILABILITY_DOMAIN:-}" ]]; then
    OCI_AVAILABILITY_DOMAIN=$(oci iam availability-domain list \
        --compartment-id "$COMPARTMENT_ID" --query 'data[0].name' --raw-output)
fi

# Extraction does not need the confidential platform — allow OCI_PREEMPTIBLE=false
# (on-demand) as a capacity fallback, and any x86 flex shape via OCI_SHAPE.
if [[ "${OCI_PREEMPTIBLE:-true}" == "true" ]]; then
    PREEMPTIBLE_ARGS=(--preemptible-instance-config '{"preemptionAction":{"type":"TERMINATE","preserveBootVolume":false}}')
else
    PREEMPTIBLE_ARGS=()
fi

echo "============================================================"
echo "🐧 Extracting OL10 boot binaries from OCI platform image"
echo "============================================================"
echo "   Image : $IMAGE_ID"
echo "   Shape : $SHAPE (1 OCPU / 1 GB, preemptible)"
echo "   Out   : $OUT"
echo ""

# ------------------------------------------------------------------ Launch
# OL10_INSTANCE_ID=<id> resumes against an already-running instance
if [[ -n "${OL10_INSTANCE_ID:-}" ]]; then
    INSTANCE_ID="$OL10_INSTANCE_ID"
    echo "⏳ [1/4] Reusing existing instance: $INSTANCE_ID"
else
echo "⏳ [1/4] Launching short-lived extraction instance..."
LAUNCH_OUT=$(oci compute instance launch \
    --compartment-id "$COMPARTMENT_ID" \
    --availability-domain "$OCI_AVAILABILITY_DOMAIN" \
    --subnet-id "$SUBNET_ID" \
    --assign-public-ip true \
    --image-id "$IMAGE_ID" \
    --shape "$SHAPE" \
    --shape-config '{"ocpus": 1, "memoryInGBs": 1}' \
    --display-name "ol10-extract-tmp" \
    --metadata "{\"ssh_authorized_keys\": \"$(tr -d '\n' < "$SSH_PUB")\"}" \
    "${PREEMPTIBLE_ARGS[@]}" \
    --wait-for-state RUNNING --max-wait-seconds 600 \
    --query 'data.id' --raw-output 2>&1) || {
        echo "❌ Launch failed:"; echo "$LAUNCH_OUT"; exit 1
    }
# NOTE: with --wait-for-state the CLI also prints "Action completed. Waiting..."
# on stdout, so always pull the OCID out with grep instead of trusting the raw output.
INSTANCE_ID=$(echo "$LAUNCH_OUT" | grep -oE 'ocid1\.instance\.[a-z0-9.-]+' | head -1)
if [[ -z "$INSTANCE_ID" ]]; then
    echo "❌ Could not parse instance OCID from:"; echo "$LAUNCH_OUT"; exit 1
fi
echo "✅ Instance running: $INSTANCE_ID"
fi

# Always terminate, even on failure (trap on EXIT once we have the id)
cleanup() {
    echo ""
    echo "🛑 Terminating extraction instance $INSTANCE_ID..."
    # NOTE: `instance action` only accepts power actions (start/stop/reset...);
    # TERMINATE lives on `instance terminate`. --preserve-boot-volume false
    # (default) drops the temp boot volume with the instance.
    oci compute instance terminate --instance-id "$INSTANCE_ID" \
        --preserve-boot-volume false --force \
        --query 'data."lifecycle-state"' \
        --raw-output 2>/dev/null || true
}
trap cleanup EXIT

# ------------------------------------------------------------------ SSH ready
echo "⏳ [2/4] Waiting for SSH..."
IP=""
for i in $(seq 1 30); do
    IP=$(oci compute instance list-vnics --instance-id "$INSTANCE_ID" \
        --query 'data[0]."public-ip"' --raw-output 2>/dev/null || true)
    case "$IP" in ""|None|null) IP="" ;; esac
    [[ -n "$IP" ]] && break
    sleep 5
done
if [[ -z "$IP" ]]; then
    echo "❌ No public IP"; exit 1
fi
echo "   IP: $IP"

SSH_OPTS="-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o BatchMode=yes -o LogLevel=ERROR"
for i in $(seq 1 36); do
    if ssh $SSH_OPTS "opc@$IP" true 2>/dev/null; then
        echo "✅ SSH ready"; break
    fi
    if [[ "$i" -eq 36 ]]; then echo "❌ SSH never became ready"; exit 1; fi
    sleep 5
done

# ------------------------------------------------------------------ Extract
echo "⏳ [3/4] Copying /boot + ESP + kernel modules..."
ssh $SSH_OPTS "opc@$IP" 'bash -s' <<'REMOTE'
set -euo pipefail
sudo bash -c '
set -euo pipefail
KV=$(ls -1 /lib/modules | head -1)
echo "kernel: $KV"
rm -rf /tmp/stage && mkdir -p /tmp/stage
cp "/lib/modules/$KV/vmlinuz" /tmp/stage/vmlinuz
cp -a "/lib/modules/$KV" /tmp/stage/modules_kv
cp /boot/efi/EFI/BOOT/BOOTX64.EFI /tmp/stage/BOOTX64.EFI
cp /boot/efi/EFI/redhat/grubx64.efi /tmp/stage/grubx64.efi
{
    echo "# Oracle Linux 10 boot binaries extracted from the OCI platform image"
    echo "# by extract-ol10-platform.sh (see OL10_IMAGE_ID in that script)"
    echo "# kernel: $KV"
    rpm -q --qf "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n" \
        kernel-uek-core kernel-uek-modules-core kernel-uek-modules \
        kernel-uek-modules-extra shim-x64 grub2-efi-x64 2>/dev/null || true
    echo "# sha256 of extracted boot artifacts:"
    (cd /tmp/stage && sha256sum vmlinuz BOOTX64.EFI grubx64.efi)
} > /tmp/stage/VERSIONS.txt
mv /tmp/stage/modules_kv /tmp/stage/modules_tmp
mkdir -p /tmp/stage/modules
mv /tmp/stage/modules_tmp "/tmp/stage/modules/$KV"
tar -C /tmp/stage -czf /tmp/ol10-binaries.tar.gz .
cat /tmp/stage/VERSIONS.txt
'
REMOTE

mkdir -p "$OUT"
scp $SSH_OPTS "opc@$IP:/tmp/ol10-binaries.tar.gz" /tmp/ol10-binaries.tar.gz >/dev/null
# Clear previous extraction but keep the git-tracked SOURCE.txt placeholder
find "$OUT" -mindepth 1 -maxdepth 1 ! -name SOURCE.txt -exec rm -rf {} +
tar -C "$OUT" -xzf /tmp/ol10-binaries.tar.gz
rm -f /tmp/ol10-binaries.tar.gz

# ------------------------------------------------------------------ Verify
echo ""
echo "⏳ [4/4] Verifying staged output..."
for f in vmlinuz BOOTX64.EFI grubx64.efi VERSIONS.txt; do
    if [[ ! -f "$OUT/$f" ]]; then echo "❌ missing $OUT/$f"; exit 1; fi
done
if ! ls -d "$OUT/modules/"*/ >/dev/null 2>&1; then
    echo "❌ missing $OUT/modules/<kernel>/"; exit 1
fi

echo ""
echo "============================================================"
echo "✅ OL10 platform binaries staged in $OUT"
echo "============================================================"
cat "$OUT/VERSIONS.txt"
echo ""
echo "Next: bash build-oci-docker.sh   (uses ./ol10 automatically)"
echo ""
