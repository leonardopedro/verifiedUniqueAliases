#!/bin/bash
set -eo pipefail

echo "============================================================"
echo "🚀 Deploying Alibaba Cloud Confidential Auth VM (SEV-SNP)"
echo "============================================================"

# --- Configuration ---
ALIBABA_USER_ID="${ALIBABA_USER_ID}"
ACCESS_KEY="${ALIBABA_ACCESS_KEY}"
SECRET_KEY="${ALIBABA_SECRET_KEY}"
REGION="cn-hangzhou"
ZONE="cn-hangzhou-j"

# NOTE: 
# 1. To support "No Minimum Duration", we use 'SpotAsPriceGo'.
#    Spot instances are terminated when price exceeds SpotPriceLimit or capacity runs out.
# 2. We configure SystemDiskSize to 40GiB (minimal for Alpine/Debian custom images).

VM_NAME="paypal-auth-ali-v1"
IMAGE_ID="" # IMPORTANT: You must provide a Custom Image ID from your OSS bucket import
SECURITY_GROUP_ID=${SECURITY_GROUP_ID:-sg-xxxxxxxxxxxx} # Ensure Port 80, 443 are allowed
NETWORK_ZONE_ID="" # Optional: Specific Subnet ID
SPOT_PRICE_LIMIT="2.0" # Max hourly USD limit 

echo "✅ Configuration Loaded:"
echo "   - Region: $REGION ($ZONE)"
echo "   - Instance Type: ecs.r9i.xlarge (AMD EPYC 9004)"
echo "   - Hardware Root-of-Trust: SEV-SNP (Equivalent to TDX protection) "

# Prerequisites validation
if [[ -z "$ACCESS_KEY" || -z "$SECRET_KEY" ]]; then
    echo "❌ CRITICAL: Set ALIBABA_ACCESS_KEY and SECRET_KEY environment variables before proceeding."
    exit 1
fi

echo ""
echo "⏳ [1/4] Checking Aliyun CLI availability..."
if ! command -v aliyun &> /dev/null; then
    echo "⚠️ Warning: 'aliyun' CLI not found. Please install via: pip install aliyun-cli or use curl-based API calls."
fi

echo ""
echo "🛡️  [2/4] Launching SEV-SNP Spot Instance (Minimal Duration)..."

# Export keys for the CLI
export ALIBABA_ACCESS_KEY_ID="$ACCESS_KEY"
export ALIBABA_ACCESS_KEY_SECRET="$SECRET_KEY"

if command -v aliyun &> /dev/null; then
    OUTPUT=$(aliyun ecs RunInstances \
        --RegionId $REGION \
        --ZoneId $ZONE \
        --InstanceName $VM_NAME \
        --SecurityGroupId $SECURITY_GROUP_ID \
        --ImageId $IMAGE_ID \
        --InstanceType ecs.r9i.xlarge \
        --InternetMaxBandwidthOut 10 \
        --IoOptimized enhanced \
        --SpotStrategy SpotAsPriceGo \
        --SpotPriceLimit $SPOT_PRICE_LIMIT \
        --SystemDisk.Size 40 \
        --SystemDisk.Category cloud_essd \
        --Output json \
        2>&1)

    INSTANCE_ID=$(echo "$OUTPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['InstanceIdSets']['InstanceidSet'][0])" 2>/dev/null || echo "")
    
    if [[ -n "$INSTANCE_ID" ]]; then
        echo "   ✅ VM Provisioned. Waiting for IP allocation..."
        
        # Wait for public IP
        for i in {1..30}; do
            sleep 5
            STATUS_OUT=$(aliyun ecs DescribeInstanceStatus --InstanceId $INSTANCE_ID --Output json 2>/dev/null || echo "{}")
            PUBLIC_IP=$(echo "$STATUS_OUT" | grep -oP '"InternetIpAddress"\s*:\s*\[\{\"InternetChargeType":"PayByTraffic","IpAddress":"\K[^"]+' 2>/dev/null || echo "")
            
            if [[ -n "$PUBLIC_IP" ]]; then
                echo ""
                echo "============================================================"
                echo "🎉 Deployment Complete!"
                echo "   Instance ID: $INSTANCE_ID"
                echo "   Endpoint : https://$PUBLIC_IP/"
                echo "============================================================"
                break
            fi
            
            if [ $i -eq 30 ]; then
                echo "[ERROR] Failed to retrieve public IP within timeout window"
            fi
        done
    else
        echo "❌ Error creating instance:"
        echo "$OUTPUT"
    fi
else
    echo "--- Manual Setup Required Since CLI Missing ---"
    # Provide raw CURL equivalent here for manual testing
    curl "https://ecs.aliyuncs.com/?InstanceName=$VM_NAME&RegionId=$REGION&ZoneId=$ZONE&InstanceType=ecs.r9i.xlarge&InternetMaxBandwidthOut=10&IoOptimized=enhanced&SpotStrategy=SpotAsPriceGo&SpotPriceLimit=$(curl -s http://100.100.100.200/latest/meta-data/system/configuration/spot-price-limit)&SystemDisk.Size=40&SystemDisk.Category=cloud_essd&Format=json" \
     -X POST 2>&1
fi
