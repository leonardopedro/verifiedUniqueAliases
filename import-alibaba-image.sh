#!/bin/bash
# ==============================================================================
# import-alibaba-image.sh - Import initramfs as custom image on Alibaba Cloud
#
# This script uploads the initramfs to OSS and imports it as a custom ECS image.
#
# Prerequisites:
#   - aliyun CLI configured
#   - ossutil configured
#   - An OSS bucket in the same region as your target VPC
#
# Usage:
#   export ALI_REGION=cn-hangzhou
#   export ALI_OSS_BUCKET=your-bucket-name
#   bash import-alibaba-image.sh
# ==============================================================================
set -eo pipefail

ALI_REGION="${ALI_REGION:-cn-hangzhou}"
ALI_OSS_BUCKET="${ALI_OSS_BUCKET:-}"

if [[ -z "$ALI_OSS_BUCKET" ]]; then
    echo "❌ Set ALI_OSS_BUCKET environment variable"
    echo "   Example: export ALI_OSS_BUCKET=my-paypal-bucket"
    exit 1
fi

INITRD_FILE="initramfs-alibaba.img"

if [[ ! -f "$INITRD_FILE" ]]; then
    echo "❌ $INITRD_FILE not found"
    echo "   Run: bash build-alibaba-docker.sh first"
    exit 1
fi

echo "============================================================"
echo "📦 Importing initramfs as Alibaba Cloud Custom Image"
echo "============================================================"
echo ""

# Step 1: Upload to OSS
echo "⏳ [1/3] Uploading to OSS..."
ossutil cp "$INITRD_FILE" "oss://$ALI_OSS_BUCKET/paypal-auth-vm/$INITRD_FILE" --force

INITRD_SHA=$(sha256sum "$INITRD_FILE" | cut -d' ' -f1)
echo "✅ Uploaded: oss://$ALI_OSS_BUCKET/paypal-auth-vm/$INITRD_FILE"
echo "   SHA256: $INITRD_SHA"
echo ""

# Step 2: Import as custom image
echo "⏳ [2/3] Importing as custom image..."

IMPORT_OUTPUT=$(aliyun ecs ImportImage \
    --RegionId "$ALI_REGION" \
    --ImageName "paypal-auth-vm-$(date +%Y%m%d)" \
    --Description "PayPal Auth VM with Intel TDX support" \
    --DiskDeviceMapping.1.OSSBucket "$ALI_OSS_BUCKET" \
    --DiskDeviceMapping.1.OSSObject "paypal-auth-vm/$INITRD_FILE" \
    --DiskDeviceMapping.1.ImageFormat "raw" \
    --DiskDeviceMapping.1.Device "/dev/sda" \
    --Output json \
    2>&1) || true

IMAGE_TASK_ID=$(echo "$IMPORT_OUTPUT" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('ImageId', d.get('TaskId', '')))
except:
    print('')
" 2>/dev/null)

if [[ -z "$IMAGE_TASK_ID" ]]; then
    echo "❌ Failed to start image import:"
    echo "$IMPORT_OUTPUT"
    exit 1
fi

echo "✅ Image import started: $IMAGE_TASK_ID"
echo ""

# Step 3: Wait for completion
echo "⏳ [3/3] Waiting for image import to complete..."

for i in $(seq 1 120); do
    TASK_STATUS=$(aliyun ecs DescribeTasks \
        --RegionId "$ALI_REGION" \
        --TaskId "[\"$IMAGE_TASK_ID\"]" \
        --Output json 2>/dev/null) || true
    
    STATUS=$(echo "$TASK_STATUS" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    tasks = d.get('Tasks', {}).get('Task', [])
    if tasks:
        print(tasks[0].get('TaskStatus', ''))
    else:
        print('Unknown')
except:
    print('Error')
" 2>/dev/null)
    
    if [[ "$STATUS" == "Success" ]]; then
        IMAGE_ID=$(echo "$TASK_STATUS" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    tasks = d.get('Tasks', {}).get('Task', [])
    if tasks:
        # Get image ID from task result
        desc = tasks[0].get('Description', '{}')
        data = json.loads(desc) if desc else {}
        img_id = data.get('ImageId', '')
        if not img_id:
            # Try to get from Tasks response directly
            img_id = tasks[0].get('ImageId', '')
        print(img_id)
    else:
        print('')
except Exception as e:
    print('')
" 2>/dev/null)
        
        if [[ -z "$IMAGE_ID" ]]; then
            # Fallback: list images to find the one we just created
            IMAGE_ID=$(aliyun ecs DescribeImages \
                --RegionId "$ALI_REGION" \
                --ImageName "paypal-auth-vm-*" \
                --OwnerAccount "self" \
                --Output json 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
imgs = d.get('Images', {}).get('Image', [])
if imgs:
    # Get most recent
    print(sorted(imgs, key=lambda x: x.get('CreationTime', ''))[-1]['ImageId'])
else:
    print('')
" 2>/dev/null)
        fi
        
        if [[ -n "$IMAGE_ID" ]]; then
            echo ""
            echo "============================================================"
            echo "✅ Image import complete!"
            echo "============================================================"
            echo "   Image ID : $IMAGE_ID"
            echo "   Name     : paypal-auth-vm-$(date +%Y%m%d)"
            echo "============================================================"
            echo ""
            echo "Next step:"
            echo "  export ALI_IMAGE_ID=$IMAGE_ID"
            echo "  bash deploy-alibaba.sh"
            echo ""
            exit 0
        fi
    fi
    
    if [[ $i -eq 120 ]]; then
        echo "⚠️ Timeout waiting for image import"
        echo "   Check status manually: aliyun ecs DescribeTasks --TaskId \"[$IMAGE_TASK_ID]\""
        exit 1
    fi
    
    sleep 10
done
