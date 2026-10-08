#!/bin/bash
set -eo pipefail

# ==============================================================================
# deploy-oci.sh - Deploy PayPal Auth Confidential VM to Oracle Cloud
#
# Target:  VM.Standard.E5.Flex (AMD EPYC Genoa, SEV-SNP) — 1 OCPU, minimal RAM
#          Preemptible (spot) instance by default; set OCI_PREEMPTIBLE=false for on-demand
# Region:  from your oci CLI profile/config
# Network: VCN subnet with an Internet Gateway + security list allowing 443/80
#
# Prerequisites:
#   - oci CLI configured (oci iam ... works)
#   - Custom image imported (bash import-oci-image.sh)
#   - VCN + subnet + security list exist
#   - PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, DOMAIN set as env vars (or config file)
#
# Boot Architecture:
#   UEFI → GRUB → kernel + initramfs (contains binary inside)
#     └── paypal-auth-vm runs as PID 1; reads config from instance user_data
#
# Usage:
#   export OCI_COMPARTMENT_ID=ocid1.compartment...
#   export OCI_SUBNET_ID=ocid1.subnet...
#   export OCI_IMAGE_ID=ocid1.image...
#   # optional:
#   #   OCI_AVAILABILITY_DOMAIN  (auto-discovered if unset)
#   #   OCI_SHAPE=VM.Standard.E5.Flex  OCI_OCPUS=1  OCI_MEM_GB=16
#   #   OCI_BOOT_VOLUME_GB=50  OCI_PREEMPTIBLE=true
#   export PAYPAL_CLIENT_ID=xxx PAYPAL_CLIENT_SECRET=xxx DOMAIN=your.domain.example.com
#   ./deploy-oci.sh
# ==============================================================================

echo "============================================================"
echo "🚀 Deploying Oracle Cloud Confidential Auth VM (AMD SEV-SNP)"
echo "============================================================"

# --- Configuration Defaults ---
OCI_COMPARTMENT_ID="${OCI_COMPARTMENT_ID:-}"
OCI_SUBNET_ID="${OCI_SUBNET_ID:-}"
OCI_IMAGE_ID="${OCI_IMAGE_ID:-}"
OCI_AVAILABILITY_DOMAIN="${OCI_AVAILABILITY_DOMAIN:-}"
OCI_SHAPE="${OCI_SHAPE:-VM.Standard.E5.Flex}"
OCI_OCPUS="${OCI_OCPUS:-1}"
OCI_MEM_GB="${OCI_MEM_GB:-16}"
OCI_BOOT_VOLUME_GB="${OCI_BOOT_VOLUME_GB:-50}"
OCI_INSTANCE_NAME="${OCI_INSTANCE_NAME:-paypal-auth-vm}"
OCI_PREEMPTIBLE="${OCI_PREEMPTIBLE:-true}"
OCI_CONFIG_FILE_PATH="${OCI_CONFIG_FILE_PATH:-/etc/paypal-auth/config.json}"

# ------------------------------------------------------------------
# Prerequisites
# ------------------------------------------------------------------
if ! command -v oci &> /dev/null; then
    echo "❌ 'oci' CLI not found"
    echo "   Install: https://docs.oracle.com/en-us/iaas/Content/API/Concepts/cliinstall.htm"
    exit 1
fi

if [[ -z "$OCI_COMPARTMENT_ID" || -z "$OCI_SUBNET_ID" || -z "$OCI_IMAGE_ID" ]]; then
    echo "❌ OCI_COMPARTMENT_ID, OCI_SUBNET_ID, and OCI_IMAGE_ID are required"
    echo "   Import the image first: bash import-oci-image.sh"
    echo "   Then: export OCI_IMAGE_ID=ocid1.image..."
    exit 1
fi

if [[ -z "$OCI_AVAILABILITY_DOMAIN" ]]; then
    echo "⏳ Discovering first availability domain..."
    OCI_AVAILABILITY_DOMAIN=$(oci iam availability-domain list \
        --compartment-id "$OCI_COMPARTMENT_ID" \
        --query 'data[0].name' --raw-output)
    if [[ -z "$OCI_AVAILABILITY_DOMAIN" || "$OCI_AVAILABILITY_DOMAIN" == "None" ]]; then
        echo "❌ Could not discover availability domain"
        exit 1
    fi
fi

echo "✅ Configuration:"
echo "   Shape:        $OCI_SHAPE ($OCI_OCPUS OCPU, ${OCI_MEM_GB}GB)"
echo "   Confidential: SEV-SNP (platformConfig AMD_VM / isMemoryEncryptionEnabled)"
echo "   Preemptible:  $OCI_PREEMPTIBLE"
echo "   AD:           $OCI_AVAILABILITY_DOMAIN"
echo "   Image:        $OCI_IMAGE_ID"
echo "   Subnet:       $OCI_SUBNET_ID"
echo ""

# ------------------------------------------------------------------
# [1/4] Build config JSON (delivered via instance user_data)
# ------------------------------------------------------------------
echo "⏳ [1/4] Preparing configuration for user_data delivery..."

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
    echo "   Generated config from environment variables"
elif [[ -n "${OCI_CONFIG_CONTENT:-}" ]]; then
    echo "$OCI_CONFIG_CONTENT" > "$CONFIG_TMPFILE"
    echo "   Using provided OCI_CONFIG_CONTENT"
elif [[ -f "${OCI_CONFIG_FILE_PATH}" ]]; then
    cp "$OCI_CONFIG_FILE_PATH" "$CONFIG_TMPFILE"
    echo "   Using local config file: $OCI_CONFIG_FILE_PATH"
elif [[ -f "./config.example.json" ]]; then
    cp "./config.example.json" "$CONFIG_TMPFILE"
    echo "   Using ./config.example.json"
else
    echo "⚠️ No PayPal credentials provided. Service will only accept env-based config."
    echo "   Set PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, and DOMAIN to enable configuration"
fi

# The enclave reads instance metadata "user_data" directly (base64 handled by the CLI)
# and parses it as config JSON — no cloud-init involved.

# ------------------------------------------------------------------
# [2/4] Launch confidential preemptible instance
# ------------------------------------------------------------------
if [[ "$OCI_PREEMPTIBLE" == "true" ]]; then
    PREEMPTIBLE_ARGS=(--preemptible-instance-config '{"preemptionAction":{"type":"TERMINATE","preserveBootVolume":false}}')
    echo "⏳ [2/4] Launching $OCI_SHAPE preemptible confidential instance..."
else
    PREEMPTIBLE_ARGS=()
    echo "⏳ [2/4] Launching $OCI_SHAPE confidential instance (on-demand)..."
fi

LAUNCH_OUTPUT=$(oci compute instance launch \
    --compartment-id "$OCI_COMPARTMENT_ID" \
    --availability-domain "$OCI_AVAILABILITY_DOMAIN" \
    --subnet-id "$OCI_SUBNET_ID" \
    --assign-public-ip true \
    --image-id "$OCI_IMAGE_ID" \
    --shape "$OCI_SHAPE" \
    --shape-config "{\"ocpus\": $OCI_OCPUS, \"memoryInGBs\": $OCI_MEM_GB}" \
    --source-details "{\"sourceType\": \"image\", \"imageId\": \"$OCI_IMAGE_ID\", \"bootVolumeSizeInGBs\": $OCI_BOOT_VOLUME_GB}" \
    --platform-config '{"type": "AMD_VM", "isMemoryEncryptionEnabled": true}' \
    --display-name "$OCI_INSTANCE_NAME" \
    --user-data-file "$CONFIG_TMPFILE" \
    "${PREEMPTIBLE_ARGS[@]}" \
    --wait-for-state RUNNING \
    --max-wait-seconds 600 \
    --output json 2>&1) || {
        echo "❌ Instance launch failed:"
        echo "$LAUNCH_OUTPUT"
        exit 1
    }

INSTANCE_ID=$(echo "$LAUNCH_OUTPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
data = d.get('data', d)
print(data.get('id', ''))
" 2>/dev/null || true)

if [[ -z "$INSTANCE_ID" ]]; then
    echo "❌ Could not parse instance id from launch response:"
    echo "$LAUNCH_OUTPUT"
    exit 1
fi
echo "✅ Instance running: $INSTANCE_ID"

# ------------------------------------------------------------------
# [3/4] Resolve public IP
# ------------------------------------------------------------------
echo "⏳ [3/4] Resolving public IP..."

PUBLIC_IP=""
for i in $(seq 1 30); do
    PUBLIC_IP=$(oci compute instance list-vnics --instance-id "$INSTANCE_ID" 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
data = d.get('data', d)
v = data[0] if isinstance(data, list) and data else {}
print(v.get('public-ip', v.get('publicIp', '')) or '')
" 2>/dev/null || true)

    if [[ -n "$PUBLIC_IP" ]]; then
        echo "✅ Public IP: $PUBLIC_IP"
        break
    fi
    sleep 5
done

if [[ -z "$PUBLIC_IP" ]]; then
    echo "⚠️ No public IP found yet. Check the instance: $INSTANCE_ID"
    echo "   oci compute instance list-vnics --instance-id $INSTANCE_ID"
fi

# ------------------------------------------------------------------
# [4/4] Summary
# ------------------------------------------------------------------
echo ""
echo "============================================================"
echo "🎉 Deployment Complete!"
echo "============================================================"
echo "   Instance ID : $INSTANCE_ID"
echo "   Public IP   : ${PUBLIC_IP:-<pending>}"
echo "   Shape       : $OCI_SHAPE (SEV-SNP confidential, preemptible=$OCI_PREEMPTIBLE)"
echo "   User data   : config JSON injected at launch (no cloud-init)"
echo "============================================================"
echo ""
echo "Next steps:"
echo "  1. Ensure your DNS points to ${PUBLIC_IP:-<the public IP>}"
echo "  2. Ensure the subnet security list allows 443/80 from the internet"
echo "  3. Check the service: curl https://${PUBLIC_IP:-<ip>}/debug/attestation"
echo "  4. Spot instances can be reclaimed at any time — redeploy with this script"
echo ""
