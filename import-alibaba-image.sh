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
#
# Relay notes (2026-10-20):
#   - OSS data-plane calls from outside mainland China are geo-blocked, so the
#     upload path is: local → HK bucket (paypal-tdx-relay-*) → relay ECS in
#     cn-beijing → intranet PUT to the Beijing bucket (see the /tmp/relay*
#     transfer flow; `aliyun oss cp` below only works FROM a mainland host).
#   - NEXT relay instance: a 1 GiB cloud_auto system disk is enough (the relay
#     only shuttles the 46 MiB disk image). Start it for the upload, then stop
#     it economically:  aliyun ecs StopInstance --InstanceId <id> --StoppedMode StopCharging
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

# Verify the upload before importing (cheap insurance: an interrupted upload
# otherwise yields an image that fails at boot with no useful error).
# NOTE: `aliyun oss hash` has no sha256 method in CLI 3.3.15, and its ETag is
# the MD5 only for single-part uploads — so we check size + ETag/MD5, and fall
# back to a redownload-and-compare if the stat output cannot be parsed.
STAT=$(aliyun oss stat "oss://$ALI_OSS_BUCKET/$OSS_OBJECT" 2>&1) || {
    echo "❌ Cannot stat uploaded object:"; echo "$STAT"; exit 1; }
REMOTE_SIZE=$(echo "$STAT" | grep -oE 'Content-Length[^0-9]*[0-9]+' | grep -oE '[0-9]+$' | head -1)
LOCAL_SIZE=$(stat -c%s "$DISK_FILE")
if [[ "$REMOTE_SIZE" != "$LOCAL_SIZE" ]]; then
    echo "❌ OSS object size mismatch: remote=$REMOTE_SIZE local=$LOCAL_SIZE"
    exit 1
fi
LOCAL_MD5=$(md5sum "$DISK_FILE" | cut -d' ' -f1)
REMOTE_ETAG=$(echo "$STAT" | grep -oiE 'etag[^a-f0-9]*[a-f0-9]{32}(-[0-9]+)?' | grep -oiE '[a-f0-9]{32}(-[0-9]+)?' | head -1 | tr 'A-Z' 'a-z')
if [[ -n "$REMOTE_ETAG" && "$REMOTE_ETAG" != *-* && "$REMOTE_ETAG" != "$LOCAL_MD5" ]]; then
    echo "❌ OSS object ETag/MD5 mismatch: remote=$REMOTE_ETAG local=$LOCAL_MD5"
    exit 1
fi
echo "✅ Upload verified (size=$LOCAL_SIZE bytes, etag=${REMOTE_ETAG:-n/a})"

# Step 2: Import as custom UEFI image
echo "⏳ [2/3] Starting ImportImage (BootMode=UEFI, format=raw)..."
# NOTE (2026-10-19, live-verified): the aliyun CLI rejects
# `--DiskDeviceMapping.1.ImageFormat` outright ("is not a valid parameter or
# flag") — ImportImage takes the FLAT `--DiskDeviceMapping.1.Format` flag.
IMPORT_OUTPUT=$(aliyun ecs ImportImage \
    --RegionId "$ALI_REGION" \
    --ImageName "$IMAGE_NAME" \
    --Description "PayPal Auth VM ESP (Intel TDX) sha256=$DISK_SHA" \
    --BootMode UEFI \
    --DiskDeviceMapping.1.OSSBucket "$ALI_OSS_BUCKET" \
    --DiskDeviceMapping.1.OSSObject "$OSS_OBJECT" \
    --DiskDeviceMapping.1.Format raw 2>&1) || true

TASK_ID=$(echo "$IMPORT_OUTPUT" | jq -r '.TaskId // empty' 2>/dev/null || true)
IMAGE_ID=$(echo "$IMPORT_OUTPUT" | jq -r '.ImageId // empty' 2>/dev/null || true)
if [[ -z "$TASK_ID" && -z "$IMAGE_ID" ]]; then
    echo "❌ Failed to start image import:"
    echo "$IMPORT_OUTPUT"
    exit 1
fi
[[ -n "$TASK_ID" ]] && echo "✅ Import task: $TASK_ID"

# Step 3: Wait until the image exists and is Available.
# NOTE (2026-10-19, live-verified): polling DescribeTasks does NOT work with
# this CLI — `--TaskId` is rejected outright ("Did you mean: TaskIds") and the
# `--TaskIds '["..."]'` filter returns an empty TaskSet even for a Finished
# task, so a task-status loop hangs until timeout. Poll the IMAGE instead: it
# only becomes visible/Available once the import has completed. The current
# CLI also returns ImageId directly in the ImportImage response, so the
# name-based lookup below is only a fallback.
echo "⏳ [3/3] Waiting for import..."
if [[ -z "$IMAGE_ID" ]]; then
    for i in $(seq 1 30); do
        IMAGE_ID=$(aliyun ecs DescribeImages --RegionId "$ALI_REGION" --ImageName "$IMAGE_NAME" 2>/dev/null \
            | jq -r '.Images.Image[0].ImageId // empty' 2>/dev/null || true)
        [[ -n "$IMAGE_ID" ]] && break
        sleep 10
    done
fi

if [[ -z "$IMAGE_ID" ]]; then
    echo "⚠️ Timeout waiting for the imported image to appear — check:"
    echo "   aliyun ecs DescribeTasks --RegionId $ALI_REGION --TaskIds '[\"$TASK_ID\"]'"
    echo "   aliyun ecs DescribeImages --RegionId $ALI_REGION --ImageName $IMAGE_NAME"
    exit 1
fi

# A visible image is not yet a usable one: poll Status until Available.
STATUS=""
for i in $(seq 1 60); do
    STATUS=$(aliyun ecs DescribeImages --RegionId "$ALI_REGION" --ImageId "$IMAGE_ID" 2>/dev/null \
        | jq -r '.Images.Image[0].Status // "Unknown"' 2>/dev/null || echo Unknown)
    echo "   image $IMAGE_ID status: $STATUS"
    [[ "$STATUS" == "Available" ]] && break
    case "$STATUS" in
        Failed|Discarded|Expired)
            echo "❌ Image import failed (status=$STATUS)"
            exit 1 ;;
    esac
    sleep 10
done
if [[ "$STATUS" != "Available" ]]; then
    echo "⚠️ Image $IMAGE_ID not Available (status=$STATUS) — retry later:"
    echo "   aliyun ecs DescribeImages --RegionId $ALI_REGION --ImageId $IMAGE_ID"
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
echo "   export ALI_IMAGE_ID=$IMAGE_ID"
echo "   bash deploy-alibaba.sh"
echo ""
