#!/bin/bash
# =============================================================================
# deploy-alibaba.sh - Deploy PayPal Auth Confidential VM to Alibaba Cloud ECS
#
# Launches a TDX-enabled spot instance from the custom ESP image.
#
# Cheapest TDX-capable shape is ecs.c9i.large (2 vCPU / 4 GiB) in
# cn-beijing-i, live-verified 2026-10-23: a spot c9i.large with
# ConfidentialComputingMode=TDX booted the ESP image and produced a genuine
# hardware-signed TD Quote (5007 B via configfs_tsm, provider=tdx_guest),
# MRTD/RTMR1/RTMR2 byte-identical to the xlarge — only RTMR0 differs
# (ACPI/platform config is per-shape), so a shape change rotates that one pin.
# c9i.large spot $0.012/h < c9i.xlarge $0.024/h < c8i.large $0.013/h
# (8th-gen is NOT cheaper in Beijing despite being older). Verify current spot
# prices with:
#   aliyun ecs DescribeSpotPriceHistory --RegionId cn-beijing --ZoneId cn-beijing-i \
#     --InstanceType ecs.c9i.large --NetworkType vpc
#
# Prerequisites:
#   - aliyun CLI configured
#   - ALI_IMAGE_ID set (from import-alibaba-image.sh)
#   - Network: pass ALI_VPC_ID/ALI_VSWITCH_ID/ALI_SECURITY_GROUP_ID, or let this
#     script find/create a "paypal-tdx-vpc" in the target region
#
# Config delivery: the enclave fetches config JSON from the instance user_data
# metadata endpoint (http://100.100.100.200/latest/user-data). Set PayPal creds
# via env vars below, or provide ALI_CONFIG_FILE_PATH.
#
# Usage:
#   export ALI_IMAGE_ID=m-xxxxxxxx
#   export PAYPAL_CLIENT_ID=... PAYPAL_CLIENT_SECRET=... DOMAIN=...
#   bash deploy-alibaba.sh
# =============================================================================
set -eo pipefail

echo "============================================================"
echo "🚀 Deploying Alibaba Cloud Confidential Auth VM (Intel TDX)"
echo "============================================================"

# --- Configuration defaults: cheapest TDX-capable shape -----------------------
ALI_REGION="${ALI_REGION:-cn-beijing}"
ALI_ZONE="${ALI_ZONE:-cn-beijing-i}"
ALI_INSTANCE_TYPE="${ALI_INSTANCE_TYPE:-ecs.c9i.large}"    # 2 vCPU / 4 GiB, TDX-verified 2026-10-23, $0.012/h spot (cheapest TDX shape in Beijing)
ALI_INSTANCE_NAME="${ALI_INSTANCE_NAME:-paypal-auth-vm}"
ALI_IMAGE_ID="${ALI_IMAGE_ID:-}"
ALI_VPC_ID="${ALI_VPC_ID:-}"
ALI_VSWITCH_ID="${ALI_VSWITCH_ID:-}"
ALI_SECURITY_GROUP_ID="${ALI_SECURITY_GROUP_ID:-}"
# Minimum-cost system disk, verified via RunInstances --DryRun (2026-10-20):
#   - cloud_auto @ 1 GiB ACCEPTS TDX+imported image (baseline 3000 IOPS/125 MB/s
#     included; <=3 GiB cannot burst/预配置 so no performance fees) → ¥1.53/mo
#   - cloud_essd is hard-floored at 20 GiB on RunInstances (10 GiB rejected:
#     InvalidSystemDiskSize.ValueNotSupported) → ¥15.33/mo at 20 GiB
#   - cloud_essd_entry floors at 10 GiB; cloud_efficiency/cloud_ssd/cloud_essd_local
#     rejected outright (InvalidDisk.*). 1 GiB is the API floor (image=46 MiB
#     rounds to 1 GiB; disks are GiB-granular — 100 MB is not representable).
# ReplaceSystemDisk cannot reach this state (shrinking + type change both
# forbidden) → a fresh instance is required to get the 1 GiB disk.
ALI_SYSTEM_DISK_SIZE="${ALI_SYSTEM_DISK_SIZE:-1}"
ALI_SYSTEM_DISK_CATEGORY="${ALI_SYSTEM_DISK_CATEGORY:-cloud_auto}"
ALI_INTERNET_BW="${ALI_INTERNET_BW:-5}"

# Spot: pay market price, NO protection period (reclaimable immediately)
ALI_SPOT_STRATEGY="${ALI_SPOT_STRATEGY:-SpotAsPriceGo}"
ALI_SPOT_DURATION="${ALI_SPOT_DURATION:-0}"

# TDX toggle (set ALI_TDX=0 to launch a plain instance)
ALI_TDX="${ALI_TDX:-1}"

ALI_CONFIG_FILE_PATH="${ALI_CONFIG_FILE_PATH:-./config.example.json}"

command -v jq >/dev/null || { echo "❌ jq is required"; exit 1; }
command -v aliyun >/dev/null || { echo "❌ aliyun CLI not found — run: bash build-scripts/create-alien-deb.sh"; exit 1; }

# ------------------------------------------------------------------ Guards
if [[ -z "$ALI_IMAGE_ID" ]]; then
    echo "❌ ALI_IMAGE_ID not set. Run import-alibaba-image.sh first."
    exit 1
fi

# --- Resolve network: use provided IDs, else find/create paypal-tdx-vpc ------
if [[ -z "$ALI_VPC_ID" || -z "$ALI_VSWITCH_ID" || -z "$ALI_SECURITY_GROUP_ID" ]]; then
    echo "⏳ Resolving network in $ALI_REGION..."
    ALI_VPC_ID="${ALI_VPC_ID:-$(aliyun ecs DescribeVpcs --RegionId "$ALI_REGION" 2>/dev/null \
        | jq -r '.Vpcs.Vpc[]? | select(.VpcName=="paypal-tdx-vpc") | .VpcId' | head -1)}"
    if [[ -z "$ALI_VPC_ID" ]]; then
        echo "   Creating paypal-tdx-vpc..."
        ALI_VPC_ID=$(aliyun ecs CreateVpc --RegionId "$ALI_REGION" --CidrBlock 172.16.0.0/12 \
            --VpcName paypal-tdx-vpc | jq -r '.VpcId')
        for _ in $(seq 1 24); do
            ST=$(aliyun ecs DescribeVpcs --RegionId "$ALI_REGION" --VpcId "$ALI_VPC_ID" \
                | jq -r '.Vpcs.Vpc[0].Status')
            [[ "$ST" == "Available" ]] && break
            sleep 5
        done
    fi
    ALI_VSWITCH_ID="${ALI_VSWITCH_ID:-$(aliyun ecs DescribeVSwitches --RegionId "$ALI_REGION" \
        --VpcId "$ALI_VPC_ID" 2>/dev/null \
        | jq -r --arg z "$ALI_ZONE" '.VSwitches.VSwitch[]? | select(.ZoneId==$z) | .VSwitchId' | head -1)}"
    if [[ -z "$ALI_VSWITCH_ID" ]]; then
        echo "   Creating vSwitch in $ALI_ZONE..."
        ALI_VSWITCH_ID=$(aliyun ecs CreateVSwitch --RegionId "$ALI_REGION" --ZoneId "$ALI_ZONE" \
            --VpcId "$ALI_VPC_ID" --CidrBlock 172.16.0.0/24 --VSwitchName paypal-tdx-vsw \
            | jq -r '.VSwitchId')
        sleep 10
    fi
    ALI_SECURITY_GROUP_ID="${ALI_SECURITY_GROUP_ID:-$(aliyun ecs DescribeSecurityGroups \
        --RegionId "$ALI_REGION" --VpcId "$ALI_VPC_ID" 2>/dev/null \
        | jq -r '.SecurityGroups.SecurityGroup[]? | select(.SecurityGroupName=="paypal-tdx-sg") | .SecurityGroupId' | head -1)}"
    if [[ -z "$ALI_SECURITY_GROUP_ID" ]]; then
        echo "   Creating security group..."
        ALI_SECURITY_GROUP_ID=$(aliyun ecs CreateSecurityGroup --RegionId "$ALI_REGION" \
            --VpcId "$ALI_VPC_ID" --SecurityGroupName paypal-tdx-sg | jq -r '.SecurityGroupId')
        for P in 80 443; do
            aliyun ecs AuthorizeSecurityGroup --RegionId "$ALI_REGION" \
                --SecurityGroupId "$ALI_SECURITY_GROUP_ID" --IpProtocol tcp \
                --PortRange "$P/$P" --SourceCidrIp 0.0.0.0/0 >/dev/null 2>&1 || true
        done
    fi
fi

echo "✅ Configuration:"
echo "   Region/Zone : $ALI_REGION / $ALI_ZONE"
echo "   Instance    : $ALI_INSTANCE_TYPE (spot: $ALI_SPOT_STRATEGY, duration=${ALI_SPOT_DURATION}h)"
echo "   TDX         : $([[ "$ALI_TDX" == "1" ]] && echo enabled || echo disabled)"
echo "   Image       : $ALI_IMAGE_ID"
echo "   VPC/Switch/SG: $ALI_VPC_ID / $ALI_VSWITCH_ID / $ALI_SECURITY_GROUP_ID"
echo ""

# --- Build config JSON for user_data ----------------------------------------
CONFIG_TMPFILE=$(mktemp)
trap 'rm -f "$CONFIG_TMPFILE"' EXIT

if [[ -n "${PAYPAL_CLIENT_ID:-}" && -n "${PAYPAL_CLIENT_SECRET:-}" && -n "${DOMAIN:-}" ]]; then
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
    echo "   Config      : generated from env vars"
elif [[ -f "$ALI_CONFIG_FILE_PATH" ]]; then
    cp "$ALI_CONFIG_FILE_PATH" "$CONFIG_TMPFILE"
    echo "   Config      : $ALI_CONFIG_FILE_PATH"
else
    echo "⚠️  No PayPal credentials — enclave will log config errors at boot."
    echo "   Set PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, DOMAIN."
    echo '{}' > "$CONFIG_TMPFILE"
fi

# user_data = raw JSON (the enclave reads /latest/user-data directly; there is
# no cloud-init in the initramfs to interpret a bash script)
USER_DATA_B64=$(base64 -w0 < "$CONFIG_TMPFILE")

# ------------------------------------------------------------------ [1/4] Launch
echo "⏳ [1/4] Launching $ALI_INSTANCE_TYPE spot instance (TDX=$ALI_TDX)..."

RUN_ARGS=(--RegionId "$ALI_REGION" --ZoneId "$ALI_ZONE"
    --InstanceName "$ALI_INSTANCE_NAME"
    --VSwitchId "$ALI_VSWITCH_ID" --SecurityGroupId "$ALI_SECURITY_GROUP_ID"
    --ImageId "$ALI_IMAGE_ID" --InstanceType "$ALI_INSTANCE_TYPE"
    --InternetMaxBandwidthOut "$ALI_INTERNET_BW"
    --SystemDisk.Category "$ALI_SYSTEM_DISK_CATEGORY" --SystemDisk.Size "$ALI_SYSTEM_DISK_SIZE"
    --SpotStrategy "$ALI_SPOT_STRATEGY" --SpotDuration "$ALI_SPOT_DURATION"
    --UserData "$USER_DATA_B64" --Amount 1)

[[ "$ALI_TDX" == "1" ]] && RUN_ARGS+=(--SecurityOptions.ConfidentialComputingMode TDX)

CREATE_OUTPUT=$(aliyun ecs RunInstances "${RUN_ARGS[@]}" 2>&1) || true
INSTANCE_ID=$(echo "$CREATE_OUTPUT" | jq -r '.InstanceIdSets.InstanceIdSet[0] // .InstanceIdSets.InstanceidSet[0] // empty' 2>/dev/null || true)

if [[ -z "$INSTANCE_ID" ]]; then
    echo "❌ Failed to create instance:"
    echo "$CREATE_OUTPUT"
    exit 1
fi
echo "✅ Instance created: $INSTANCE_ID"

# ------------------------------------------------------------------ [2/4] Wait for IP
echo "⏳ [2/4] Waiting for instance to start and get public IP..."
PUBLIC_IP=""
for _ in $(seq 1 60); do
    INST=$(aliyun ecs DescribeInstances --RegionId "$ALI_REGION" 2>/dev/null \
        | jq -r --arg id "$INSTANCE_ID" '.Instances.Instance[]? | select(.InstanceId==$id)')
    STATUS=$(echo "$INST" | jq -r '.Status // empty')
    if [[ "$STATUS" == "Running" ]]; then
        PUBLIC_IP=$(echo "$INST" | jq -r '.PublicIpAddress.IpAddress[0] // .EipAddress.IpAddress // empty')
        [[ -n "$PUBLIC_IP" ]] && { echo "✅ Running: https://$PUBLIC_IP"; break; }
    fi
    sleep 5
done

if [[ -z "$PUBLIC_IP" ]]; then
    echo "⚠️  No public IP yet. Status: ${STATUS:-unknown}. Check ECS console: $INSTANCE_ID"
else
    echo ""
    echo "============================================================"
    echo "🎉 Deployment Complete!"
    echo "============================================================"
    echo "   Instance ID : $INSTANCE_ID"
    echo "   Public IP   : https://$PUBLIC_IP/"
    echo "   Region      : $ALI_REGION / $ALI_ZONE"
    echo "============================================================"
    echo ""
    echo "Debug: aliyun ecs GetInstanceConsoleOutput --InstanceId $INSTANCE_ID --RegionId $ALI_REGION"
    echo "       (TDX has no VNC; serial console is the only boot log channel)"
    echo ""
fi
