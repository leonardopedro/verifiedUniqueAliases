#!/bin/bash
set -eo pipefail

echo "============================================================"
echo "🚀 Deploying Alibaba Cloud Confidential Auth VM (SEV-SNP)"
echo "============================================================"

REGION="cn-hangzhou"
ZONE="cn-hangzhou-j"
IMAGE_ID="${DISK_IMAGE_ID:-}"
VM_NAME="${VM_NAME:-paypal-alicloud-v1}"
INSTANCE_TYPE="ecs.r9i.xlarge" # AMD EPYC 9004 with SEV-SNP support
SECURITY_GROUP_ID="${SECURITY_GROUP_ID:-sg-group-id}"

echo "Configuration:"
echo " - Region: $REGION ($ZONE)"
echo " - Instance Type: $INSTANCE_TYPE (Spot as price go)"

if [[ -z "$Alicloud_ACCESS_KEY" || -z "$ALIYUN_SECRET_KEY" ]]; then
    echo "⚠️ Warning: ALICLOUD_ACCESS_KEY or SECRET_KEY not set."
fi

# Provision Spot Instance (No minimum duration guaranteed)
aliyun ecs RunInstances \
    --RegionId $REGION \
    --ZoneId $ZONE \
    --ImageId $IMAGE_ID \
    --InstanceType $INSTANCE_TYPE \
    --IoOptimized enhanced \
    --SpotStrategy SpotAsPriceGo \
    --SystemDisk.Category cloud_essd \
    --Output json 2>&1
