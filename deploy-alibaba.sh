#!/bin/bash
set -eo pipefail

# ==============================================================================
# deploy-alibaba.sh - Deploy PayPal Auth Confidential VM to Alibaba Cloud ECS
#
# Target:  ecs.r9i.xlarge (Intel TDX) or AMD Rome SEV-SNP depending on pool
# Region:  configurable via ALI_REGION
# Network: VPC with security group allowing HTTP/HTTPS
#
# Prerequisites:
#   - aliyun CLI installed and configured
#   - Custom VM image uploaded to OSS (initramfs-based or disk image)
#   - PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET etc. set as env vars OR config file
#   - A domain with DNS pointing to the ECS instance IP
#
# Boot Architecture:
#   GRUB → kernel + initramfs (20M, contains binary inside)
#     └── /build/paypal-auth-vm-bin runs as PID 1
#
# Usage:
#   export ALI_ACCESS_KEY_ID=xxx
#   export ALI_ACCESS_KEY_SECRET=xxx
#   export ALI_IMAGE_ID=xxx        # After importing custom image
#   export ALI_VPC_ID=vpc-xxx
#   export ALI_VSWITCH_ID=vsw-xxx
#   export ALI_SECURITY_GROUP_ID=sg-xxx
#   export DOMAIN=your-domain.example.com
#   # Optional: export PAYPAL_CLIENT_ID=... PAYPAL_CLIENT_SECRET=...
#   ./deploy-alibaba.sh
# ==============================================================================

echo "============================================================"
echo "🚀 Deploying Alibaba Cloud Confidential Auth VM (Intel TDX)"
echo "============================================================"

# --- Configuration Defaults ---
ALI_REGION="${ALI_REGION:-cn-hangzhou}"
ALI_ZONE="${ALI_ZONE:-cn-hangzhou-j}"
ALI_INSTANCE_TYPE="ecs.r9i.xlarge"
ALI_INSTANCE_NAME="${ALI_INSTANCE_NAME:-paypal-auth-vm}"
ALI_IMAGE_ID="${ALI_IMAGE_ID:-}"
ALI_VPC_ID="${ALI_VPC_ID}"
ALI_VSWITCH_ID="${ALI_VSWITCH_ID}"
ALI_SECURITY_GROUP_ID="${ALI_SECURITY_GROUP_ID}"
ALI_SYSTEM_DISK_SIZE="${ALI_SYSTEM_DISK_SIZE:-20}"
ALI_SYSTEM_DISK_CATEGORY="${ALI_SYSTEM_DISK_CATEGORY:-cloud_efficiency}"
ALI_INTERNET_BW="${ALI_INTERNET_BW:-5}"
ALI_CONFIG_CONTENT="${ALI_CONFIG_CONTENT}"
ALI_CONFIG_FILE_PATH="${ALI_CONFIG_FILE_PATH:-/etc/paypal-auth/config.json}"

# Spot strategy: SpotAsPriceGo = pay market price up to OnPrice; no guaranteed duration
ALI_SPOT_STRATEGY="${ALI_SPOT_STRATEGY:-SpotAsPriceGo}"
ALI_SPOT_PRICE_LIMIT="${ALI_SPOT_PRICE_LIMIT:-0}"

# ------------------------------------------------------------------
# Prerequisites
# ------------------------------------------------------------------
if [[ -z "$ALI_ACCESS_KEY_ID" || -z "$ALI_ACCESS_KEY_SECRET" ]]; then
    echo "❌ Set ALI_ACCESS_KEY_ID and ALI_ACCESS_KEY_SECRET environment variables"
    exit 1
fi

if ! command -v aliyun &> /dev/null; then
    echo "❌ 'aliyun' CLI not found"
    echo "   Download from: https://github.com/aliyun/aliyun-cli"
    echo "   Or run: bash build-scripts/create-alien-deb.sh && sudo dpkg -i packages/aliyun-cli-*.deb"
    exit 1
fi

export ALIBABA_ACCESS_KEY_ID="$ALI_ACCESS_KEY_ID"
export ALIBABA_ACCESS_KEY_SECRET="$ALI_ACCESS_KEY_SECRET"

echo "✅ Configuration:"
echo "   Region: $ALI_REGION ($ALI_ZONE)"
echo "   Instance Type: $ALI_INSTANCE_TYPE"
if [[ -n "$ALI_IMAGE_ID" ]]; then
    echo "   Image ID: $ALI_IMAGE_ID (already imported)"
else
    echo "   ⚠️  ALI_IMAGE_ID not set - you need to import the image first:"
    echo ""
    echo "   Step 1: Upload initramfs to OSS"
    echo "     ossutil cp initramfs-alibaba.img oss://your-bucket/paypal-auth-vm/"
    echo ""
    echo "   Step 2: Import as custom image"
    echo "     aliyun ecs ImportImage \\"
    echo "       --RegionId $ALI_REGION \\"
    echo "       --ImageName paypal-auth-vm \\"
    echo "       --DiskDeviceMapping.1.OSSBucket your-bucket \\"
    echo "       --DiskDeviceMapping.1.OSSObject paypal-auth-vm/initramfs-alibaba.img \\"
    echo "       --DiskDeviceMapping.1.ImageFormat raw \\"
    echo "       --DiskDeviceMapping.1.Device /dev/sda"
    echo ""
    echo "   Then set ALI_IMAGE_ID=m-xxxxxxxxx and re-run this script"
    exit 1
fi

if [[ -z "$ALI_VPC_ID" || -z "$ALI_VSWITCH_ID" || -z "$ALI_SECURITY_GROUP_ID" ]]; then
    echo "❌ ALI_VPC_ID, ALI_VSWITCH_ID, and ALI_SECURITY_GROUP_ID are required"
    exit 1
fi

echo "   VPC: $ALI_VPC_ID"
echo "   VSwitch: $ALI_VSWITCH_ID"
echo "   Security Group: $ALI_SECURITY_GROUP_ID"
echo ""

# ------------------------------------------------------------------
# [1/4] Launch EC
# ------------------------------------------------------------------
echo "⏳ [1/4] Launching $ALI_INSTANCE_TYPE Spot Instance..."

CREATE_OUTPUT=$(aliyun ecs RunInstances \
    --RegionId "$ALI_REGION" \
    --ZoneId "$ALI_ZONE" \
    --InstanceName "$ALI_INSTANCE_NAME" \
    --VpcId "$ALI_VPC_ID" \
    --VSwitchId "$ALI_VSWITCH_ID" \
    --SecurityGroupId "$ALI_SECURITY_GROUP_ID" \
    --ImageId "$ALI_IMAGE_ID" \
    --InstanceType "$ALI_INSTANCE_TYPE" \
    --InternetMaxBandwidthOut "$ALI_INTERNET_BW" \
    --IoOptimized enhanced \
    --SpotStrategy "$ALI_SPOT_STRATEGY" \
    ${ALI_SPOT_PRICE_LIMIT:+--SpotPriceLimit "$ALI_SPOT_PRICE_LIMIT"} \
    --SystemDiskSize "$ALI_SYSTEM_DISK_SIZE" \
    --SystemDiskCategory "$ALI_SYSTEM_DISK_CATEGORY" \
    --Amount 1 \
    --Output json \
    2>&1) || true

# Parse instance ID
INSTANCE_ID=$(echo "$CREATE_OUTPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
ids = d.get('InstanceIdSets', {}).get('InstanceidSet', [])
print(ids[0]) if ids else print('')
" 2>/dev/null)

if [[ -z "$INSTANCE_ID" ]]; then
    echo "❌ Failed to create instance:"
    echo "$CREATE_OUTPUT"
    exit 1
fi

echo "✅ Instance created: $INSTANCE_ID"

# ------------------------------------------------------------------
# [2/4] Wait for RUNNING state and public IP
# ------------------------------------------------------------------
echo "⏳ [2/4] Waiting for instance to start and get public IP..."

PUBLIC_IP=""
for i in $(seq 1 60); do
    DESC_OUT=$(aliyun ecs DescribeInstances \
        --RegionId "$ALI_REGION" \
        --InstanceIds "[\"$INSTANCE_ID\"]" \
        --Output json 2>/dev/null) || true

    # Check status
    STATUS=$(echo "$DESC_OUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
instances = d.get('Instances', {}).get('Instance', [])
if instances:
    print(instances[0].get('Status', ''))
else:
    print('')
" 2>/dev/null)

    if [[ "$STATUS" == "Running" ]]; then
        PUBLIC_IP=$(echo "$DESC_OUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
instances = d.get('Instances', {}).get('Instance', [])
if instances:
    ips = instances[0].get('PublicIpAddress', {}).get('IpAddress', [])
    if ips:
        print(ips[0])
    else:
        eip = instances[0].get('EipAddress', {}).get('IpAddress', '')
        print(eip)
" 2>/dev/null)

        if [[ -n "$PUBLIC_IP" ]]; then
            echo "✅ Instance is Running with IP: $PUBLIC_IP"
            break
        fi
    fi

    if [[ $i -eq 60 ]]; then
        echo "⚠️ Instance status: $STATUS"
        echo "   Waiting for public IP timed out. Check ECS console."
    fi

    sleep 5
done

if [[ -z "$PUBLIC_IP" ]]; then
    echo "❌ No public IP obtained. Check ECS console: $INSTANCE_ID"
    exit 1
fi

# ------------------------------------------------------------------
# [3/4] Upload config file
# ------------------------------------------------------------------
echo "⏳ [3/4] Pushing configuration to instance..."

# Config priority: env vars -> config JSON content -> local config file
CONFIG_TMPFILE=$(mktemp)

if [[ -n "${PAYPAL_CLIENT_ID:-}" && -n "${PAYPAL_CLIENT_SECRET:-}" && -n "${DOMAIN:-}" ]]; then
    # Generate config from environment
    cat > "$CONFIG_TMPFILE" << JSONEOF
{
    "paypal_client_id": "${PAYPAL_CLIENT_ID}",
    "paypal_client_secret": "${PAYPAL_CLIENT_SECRET}",
    "paypal_verified_client_id": "${PAYPAL_VERIFIED_CLIENT_ID:-${PAYPAL_CLIENT_ID}}",
    "paypal_verified_client_secret": "${PAYPAL_VERIFIED_CLIENT_SECRET:-${PAYPAL_CLIENT_SECRET}}",
    "domain": "${DOMAIN}",
    "staging": ${STAGING:-false},
    "eab_key_id": "${EAB_KEY_ID:-}",
    "eab_hmac_key": "${EAB_HMAC_KEY:-}"
}
JSONEOF
    echo "   Generated config from environment variables"
elif [[ -n "$ALI_CONFIG_CONTENT" ]]; then
    echo "$ALI_CONFIG_CONTENT" > "$CONFIG_TMPFILE"
    echo "   Using provided ALI_CONFIG_CONTENT"
elif [[ -f "${ALI_CONFIG_FILE_PATH:-./config.example.json}" || -f "./config.example.json" ]]; then
    if [[ -f "${ALI_CONFIG_FILE_PATH}" ]]; then
        cp "${ALI_CONFIG_FILE_PATH}" "$CONFIG_TMPFILE"
    else
        cp "./config.example.json" "$CONFIG_TMPFILE"
    fi
    # Replace placeholders with env vars if set
    if [[ -n "${PAYPAL_CLIENT_ID:-}" ]]; then
        sed -i "s/YOUR_PAYPAL_CLIENT_ID/${PAYPAL_CLIENT_ID}/g" "$CONFIG_TMPFILE"
        sed -i "s/YOUR_PAYPAL_CLIENT_SECRET/${PAYPAL_CLIENT_SECRET}/g" "$CONFIG_TMPFILE"
        sed -i "s/YOUR_PAYPAL_VERIFIED_CLIENT_ID/${PAYPAL_VERIFIED_CLIENT_ID:-$PAYPAL_CLIENT_ID}/g" "$CONFIG_TMPFILE"
        sed -i "s/YOUR_PAYPAL_VERIFIED_CLIENT_SECRET/${PAYPAL_VERIFIED_CLIENT_SECRET:-$PAYPAL_CLIENT_SECRET}/g" "$CONFIG_TMPFILE"
    fi
    if [[ -n "${DOMAIN:-}" ]]; then
        sed -i "s/your-domain.example.com/${DOMAIN}/g" "$CONFIG_TMPFILE"
    fi
    echo "   Using local config file"
else
    echo "⚠️ No PayPal credentials provided. Service will only accept env-based config."
    echo "   Set PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, and DOMAIN to enable configuration"
fi

# Use aliyun to execute command and upload config
# Note: aliyun InvokeCommand is simpler, but requires the instance to have cloud-init/agent
echo "   Creating User Data to inject config at boot..."

USER_DATA="#!/bin/bash
mkdir -p /etc/paypal-auth
cat > /etc/paypal-auth/config.json << 'CONFEOF'
$(cat "$CONFIG_TMPFILE")
CONFEOF
"

# Encode user data
USER_DATA_B64=$(echo "$USER_DATA" | base64 -w0)

aliyun ecs ModifyInstanceAttribute \
    --RegionId "$ALI_REGION" \
    --InstanceId "$INSTANCE_ID" \
    --UserData "$USER_DATA_B64" \
    --Output json 2>/dev/null || true

echo "✅ User data injected"

# ------------------------------------------------------------------
# [4/4] Summary
# ------------------------------------------------------------------
echo ""
echo "============================================================"
echo "🎉 Deployment Complete!"
echo "============================================================"
echo "   Instance ID : $INSTANCE_ID"
echo "   Public IP   : https://$PUBLIC_IP/"
echo "   Region      : $ALI_REGION"
echo "============================================================"
echo ""
echo "Next steps:"
echo "  1. Ensure your DNS points to $PUBLIC_IP"
echo "  2. SSH in and check logs: ssh root@$PUBLIC_IP"
echo "     (or use Alibaba Cloud VNC console)"
echo "  3. Monitor service: curl https://$PUBLIC_IP/debug/attestation"
echo "  4. Check boot logs: dmesg | grep -i paypal"
echo ""

rm -f "$CONFIG_TMPFILE"
