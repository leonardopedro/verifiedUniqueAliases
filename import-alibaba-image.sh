#!/bin/bash
# =============================================================================
# import-alibaba-image.sh - Import the bootable ESP disk image as a custom
# Alibaba Cloud ECS image.
#
# Uploads output-alibaba/disk-alibaba.raw (GPT + ESP: shim/grub/vmlinuz/initrd)
# to OSS and imports it via ECS ImportImage. NOTE: the bare initramfs is NOT a
# disk image and cannot boot — the ESP disk is what ECS needs.
#
# Prerequisites:
#   - aliyun CLI configured (its built-in `oss` subcommand is used; ossutil not
#     required)
#   - An OSS bucket in the SAME region (ImportImage rejects cross-region)
#   - bash build-alibaba-docker.sh run first
#
# Usage:
#   export ALI_OSS_BUCKET=your-bucket-name        # required
#   export ALI_REGION=cn-beijing                  # default
#   bash import-alibaba-image.sh
# =============================================================================
set -eo pipefail

ALI_REGION="${ALI_REGION:-cn-beijing}"
ALI_OSS_BUCKET="${ALI_OSS_BUCKET:-}"
DISK_FILE="${DISK_FILE:-output-alibaba/disk-alibaba.raw}"

if [[ -z "$ALI_OSS_BUCKET" ]]; then
    echo "❌ Set ALI_OSS_BUCKET environment variable"
    echo "   Example: export ALI_OSS_BUCKET=my-paypal-bucket"
    exit 1
fi

if [[ ! -f "$DISK_FILE" ]]; then
    echo "❌ $DISK_FILE not found"
    echo "   Run: bash build-alibaba-docker.sh first"
    exit 1
fi

OSS_OBJECT="paypal-auth-vm/$(basename "$DISK_FILE")"
IMAGE_NAME="paypal-tdx-esp-$(date +%Y%m%d%H%M)"
DISK_SHA=$(sha256sum "$DISK_FILE" | cut -d' ' -f1)

echo "============================================================"
echo "📦 Importing ESP disk as Alibaba Cloud Custom Image"
echo "============================================================"
echo "   File    : $DISK_FILE ($(du -h "$DISK_FILE" | cut -f1))"
echo "   SHA256  : $DISK_SHA"
echo "   Region  : $ALI_REGION"
echo "   Bucket  : oss://$ALI_OSS_BUCKET/$OSS_OBJECT"
echo ""

# Step 1: Upload to OSS (aliyun CLI built-in; no ossutil needed)
echo "⏳ [1/3] Uploading to OSS..."
aliyun oss cp "$DISK_FILE" "oss://$ALI_OSS_BUCKET/$OSS_OBJECT" >/dev/null
echo "✅ Uploaded"

# Verify the upload byte-for-byte before importing (cheap insurance: an
# interrupted multipart upload otherwise yields an image that fails at boot)
REMOTE_SHA=$(aliyun oss hash "oss://$ALI_OSS_BUCKET/$OSS_OBJECT" --method sha256 2>/dev/null | tr -d '"' || true)
if [[ -n "$REMOTE_SHA" && "$REMOTE_SHA" != "$DISK_SHA" ]]; then
    echo "❌ OSS object SHA256 mismatch: $REMOTE_SHA != $DISK_SHA"
    exit 1
fi

# Step 2: Import as custom UEFI image
echo "⏳ [2/3] Starting ImportImage (BootMode=UEFI, format=raw)..."
IMPORT_OUTPUT=$(aliyun ecs ImportImage \
    --RegionId "$ALI_REGION" \
    --ImageName "$IMAGE_NAME" \
    --Description "PayPal Auth VM ESP (Intel TDX) sha256=$DISK_SHA" \
    --BootMode UEFI \
    --DiskDeviceMapping.1.OSSBucket "$ALI_OSS_BUCKET" \
    --DiskDeviceMapping.1.OSSObject "$OSS_OBJECT" \
    --DiskDeviceMapping.1.ImageFormat raw 2>&1) || true

TASK_ID=$(echo "$IMPORT_OUTPUT" | jq -r '.TaskId // empty' 2>/dev/null || true)
if [[ -z "$TASK_ID" ]]; then
    echo "❌ Failed to start image import:"
    echo "$IMPORT_OUTPUT"
    exit 1
fi
echo "✅ Import task: $TASK_ID"

# Step 3: Poll the task, then resolve the resulting ImageId
echo "⏳ [3/3] Waiting for import..."
IMAGE_ID=""
for i in $(seq 1 120); do
    TASK_JSON=$(aliyun ecs DescribeTasks --RegionId "$ALI_REGION" --TaskId "[\"$TASK_ID\"]" 2>/dev/null || true)
    STATUS=$(echo "$TASK_JSON" | jq -r '.Tasks.Task[0].TaskStatus // "Unknown"' 2>/dev/null || echo Unknown)
    case "$STATUS" in
        Success|Finished)
            IMAGE_ID=$(echo "$TASK_JSON" | jq -r '.Tasks.Task[0].ImageId // empty' 2>/dev/null || true)
            break ;;
        Failed|Error)
            echo "❌ Import task failed:"
            echo "$TASK_JSON" | jq '.Tasks.Task[0]' 2>/dev/null || echo "$TASK_JSON"
            exit 1 ;;
    esac
    sleep 5
done

# Fallback: find the image by name (DescribeTasks sometimes omits ImageId)
if [[ -z "$IMAGE_ID" ]]; then
    IMAGE_ID=$(aliyun ecs DescribeImages --RegionId "$ALI_REGION" --ImageName "$IMAGE_NAME" --Owner self 2>/dev/null \
        | jq -r '.Images.Image[0].ImageId // empty' 2>/dev/null || true)
fi

if [[ -z "$IMAGE_ID" ]]; then
    echo "⚠️ Timeout waiting for import — check:"
    echo "   aliyun ecs DescribeTasks --RegionId $ALI_REGION --TaskId \"[\\\"$TASK_ID\\\"]\""
    exit 1
fi

echo ""
echo "============================================================"
echo "✅ Image import complete!"
echo "============================================================"
echo "   Image ID : $IMAGE_ID"
echo "   Name     : $IMAGE_NAME"
echo "============================================================"
echo ""
echo "Next step:"
echo "  export ALI_IMAGE_ID=$IMAGE_ID"
echo "  bash deploy-alibaba.sh"
echo ""
