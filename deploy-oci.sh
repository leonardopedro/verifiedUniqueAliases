#!/bin/bash
set -eo pipefail

# ==============================================================================
# deploy-oci.sh - Deploy PayPal Auth Confidential VM to Oracle Cloud
#
# Target:  VM.Standard.E5.Flex (AMD EPYC Genoa, SEV-SNP) — 1 OCPU, minimal RAM
#          On-demand by default: OCI forbids preemptible capacity together with
#          confidential computing (platformConfig AMD_VM), so spot attempts are
#          rejected. Set OCI_PREEMPTIBLE=true to attempt spot anyway — the
#          launch is rejected and the script falls back to on-demand.
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
#   #   OCI_SHAPE=VM.Standard.E5.Flex  OCI_OCPUS=1  OCI_MEM_GB=1  (cheapest)
#   #   OCI_BOOT_VOLUME_GB=50  OCI_PREEMPTIBLE=true  (spot attempt; rejected for
#   #   confidential shapes and retried on-demand automatically)
#   #   EAB_KEY_ID / EAB_HMAC_KEY  Google Public CA EAB credentials — with them
#   #   the enclave issues TLS via Google Public CA (recommended) instead of
#   #   Let's Encrypt, whose per-week rate limits fight the per-boot re-issuance
#   #   ACME_ACCOUNT_KEY_FILE=path.pem  persist the ACME account across boots —
#   #   required for a long-lived Google account (EAB keys expire after 7 days)
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
# Cheapest possible confidential config: 1 OCPU, minimal RAM, minimal (50 GB
# = OCI minimum) boot volume, on-demand (OCI rejects preemptible + confidential;
# spot is opt-in via OCI_PREEMPTIBLE=true and falls back after rejection).
OCI_OCPUS="${OCI_OCPUS:-1}"
OCI_MEM_GB="${OCI_MEM_GB:-1}"
OCI_BOOT_VOLUME_GB="${OCI_BOOT_VOLUME_GB:-50}"  # OCI hard minimum (CLI rejects < 50)
OCI_INSTANCE_NAME="${OCI_INSTANCE_NAME:-paypal-auth-vm}"
OCI_PREEMPTIBLE="${OCI_PREEMPTIBLE:-false}"
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

# ------------------------------------------------------------------
# Reserved (static) public IP — OCI ephemeral IPs change on every relaunch
# (credential updates relaunch the instance) and break DNS. The reserved IP
# is discovered by name, created on first use, and moved to the new
# instance's primary private IP after each launch. Opt out with
# OCI_EPHEMERAL_IP=true (address will then change on every launch).
# ------------------------------------------------------------------
OCI_RESERVED_IP_ID="${OCI_RESERVED_IP_ID:-}"
if [[ "${OCI_EPHEMERAL_IP:-false}" != "true" ]]; then
    if [[ -z "$OCI_RESERVED_IP_ID" ]]; then
        echo "⏳ Discovering reserved public IP (paypal-auth-vm-ip)..."
        OCI_RESERVED_IP_ID=$(oci network public-ip list \
            --compartment-id "$OCI_COMPARTMENT_ID" --scope REGION --lifetime RESERVED \
            --query 'data[?"display-name"==`paypal-auth-vm-ip`].id | [0]' --raw-output 2>/dev/null || true)
        case "$OCI_RESERVED_IP_ID" in ""|None|null) OCI_RESERVED_IP_ID="" ;; esac
    fi
    if [[ -z "$OCI_RESERVED_IP_ID" ]]; then
        echo "⏳ Creating reserved public IP paypal-auth-vm-ip..."
        OCI_RESERVED_IP_ID=$(oci network public-ip create \
            --compartment-id "$OCI_COMPARTMENT_ID" --lifetime RESERVED \
            --display-name paypal-auth-vm-ip --query 'data.id' --raw-output 2>/dev/null || true)
        case "$OCI_RESERVED_IP_ID" in ""|None|null)
            echo "❌ Could not create the reserved public IP"
            exit 1
        ;; esac
        echo "   Created: $OCI_RESERVED_IP_ID"
    fi
    # A reserved public IP must be the ONLY public IP on its private IP
    ASSIGN_PUBLIC_IP="false"
else
    ASSIGN_PUBLIC_IP="true"
fi

echo "✅ Configuration:"
echo "   Shape:        $OCI_SHAPE ($OCI_OCPUS OCPU, ${OCI_MEM_GB}GB)"
echo "   Confidential: SEV-SNP (platformConfig AMD_VM / isMemoryEncryptionEnabled)"
echo "   Preemptible:  $OCI_PREEMPTIBLE"
echo "   Public IP:    $([[ "$ASSIGN_PUBLIC_IP" == "false" ]] && echo "reserved (static) $OCI_RESERVED_IP_ID" || echo "ephemeral")"
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

# Guard: partial credentials must not silently fall back to config.example.json
# (placeholder client IDs / your-domain.example.com) — that would launch a
# broken instance that looks healthy.
if [[ -n "${PAYPAL_CLIENT_ID:-}" && -z "${DOMAIN:-}" ]]; then
    echo "❌ PAYPAL_CLIENT_ID is set but DOMAIN is not — refusing to launch"
    echo "   with placeholder config. Export DOMAIN (and STAGING=true for sandbox)."
    exit 1
fi

if [[ -n "${PAYPAL_CLIENT_ID:-}" && -n "${PAYPAL_CLIENT_SECRET:-}" && -n "${DOMAIN:-}" ]]; then
    # Optional: cross-boot ACME account persistence. The PEM is embedded as a
    # JSON string (jq escapes newlines); the enclave then reuses this account
    # on every boot, so Google Public CA EAB keys (7-day expiry) are needed
    # only once — when the account is created — not on every boot.
    ACME_ACCOUNT_JSON_ESC='""'
    if [[ -n "${ACME_ACCOUNT_KEY_FILE:-}" ]]; then
        if [[ ! -f "$ACME_ACCOUNT_KEY_FILE" ]]; then
            echo "❌ ACME_ACCOUNT_KEY_FILE=$ACME_ACCOUNT_KEY_FILE not found"
            exit 1
        fi
        ACME_ACCOUNT_JSON_ESC=$(jq -Rs . < "$ACME_ACCOUNT_KEY_FILE")
        echo "   Embedding ACME account key from $ACME_ACCOUNT_KEY_FILE"
    fi
    cat > "$CONFIG_TMPFILE" << JSONEOF
{
    "paypal_client_id": "${PAYPAL_CLIENT_ID}",
    "paypal_client_secret": "${PAYPAL_CLIENT_SECRET}",
    "paypal_verified_client_id": "${PAYPAL_VERIFIED_CLIENT_ID:-${PAYPAL_CLIENT_ID}}",
    "paypal_verified_client_secret": "${PAYPAL_VERIFIED_CLIENT_SECRET:-${PAYPAL_CLIENT_SECRET}}",
    "domain": "${DOMAIN}",
    "staging": ${STAGING:-false},
    "eab_key_id": "${EAB_KEY_ID:-}",
    "eab_hmac_key": "${EAB_HMAC_KEY:-}",
    "acme_account_json": ${ACME_ACCOUNT_JSON_ESC}
}
JSONEOF
    # Loud failure on malformed config JSON (the enclave would otherwise get nothing)
    if ! jq empty "$CONFIG_TMPFILE" 2>/dev/null; then
        echo "❌ Generated config JSON is invalid:"
        cat "$CONFIG_TMPFILE"
        exit 1
    fi
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

launch_instance() {
    oci compute instance launch \
        --compartment-id "$OCI_COMPARTMENT_ID" \
        --availability-domain "$OCI_AVAILABILITY_DOMAIN" \
        --subnet-id "$OCI_SUBNET_ID" \
        --assign-public-ip "$ASSIGN_PUBLIC_IP" \
        --image-id "$OCI_IMAGE_ID" \
        --boot-volume-size-in-gbs "$OCI_BOOT_VOLUME_GB" \
        --shape "$OCI_SHAPE" \
        --shape-config "{\"ocpus\": $OCI_OCPUS, \"memoryInGBs\": $OCI_MEM_GB}" \
        --platform-config '{"type": "AMD_VM", "isMemoryEncryptionEnabled": true}' \
        --display-name "$OCI_INSTANCE_NAME" \
        --user-data-file "$CONFIG_TMPFILE" \
        "$@" \
        --wait-for-state RUNNING \
        --max-wait-seconds 600 \
        --query 'data.id' \
        --raw-output 2>&1
}

LAUNCH_OUTPUT=$(launch_instance "${PREEMPTIBLE_ARGS[@]}") || {
    # Observed in eu-frankfurt-1: confidential (platformConfig AMD_VM) instances
    # are rejected for preemptible/spot on E4/E5 — "... is not supported for VM
    # preemptible". Fall back to on-demand at the same minimal shape so the
    # deployment still lands on the cheapest AVAILABLE config.
    if [[ ${#PREEMPTIBLE_ARGS[@]} -gt 0 ]] && \
       echo "$LAUNCH_OUTPUT" | grep -qE "not supported for VM preemptible|Out of host capacity"; then
        echo "⚠️  Spot launch rejected: $(echo "$LAUNCH_OUTPUT" | grep -oE '"message": "[^"]*"' | head -1 | sed 's/"message": //')"
        echo "   Retrying on-demand with the same minimal config ($OCI_OCPUS OCPU / ${OCI_MEM_GB} GB)..."
        LAUNCH_OUTPUT=$(launch_instance) || {
            echo "❌ Instance launch failed:"
            echo "$LAUNCH_OUTPUT"
            exit 1
        }
    else
        echo "❌ Instance launch failed:"
        echo "$LAUNCH_OUTPUT"
        exit 1
    fi
}

# --query data.id --raw-output returns the OCID, but with --wait-for-state the
# CLI also prints "Action completed. Waiting until the resource..." on stdout —
# pull the OCID out with grep instead of trusting the raw output.
INSTANCE_ID=$(echo "$LAUNCH_OUTPUT" | grep -oE 'ocid1\.instance\.[a-z0-9.-]+' | head -1)

if [[ -z "$INSTANCE_ID" || "$INSTANCE_ID" == "None" ]]; then
    echo "❌ Could not parse instance id from launch response:"
    echo "$LAUNCH_OUTPUT"
    exit 1
fi
echo "✅ Instance running: $INSTANCE_ID"

# ------------------------------------------------------------------
# [2b/4] Attach the reserved (static) public IP to this instance
# ------------------------------------------------------------------
if [[ "$ASSIGN_PUBLIC_IP" == "false" && -n "$OCI_RESERVED_IP_ID" ]]; then
    echo "⏳ [2b/4] Attaching reserved public IP..."
    # Primary private IP (address) of the freshly launched instance
    PADDR=$(oci compute instance list-vnics --instance-id "$INSTANCE_ID" \
        --query 'data[0]."private-ip"' --raw-output)
    if [[ -z "$PADDR" || "$PADDR" == "None" ]]; then
        echo "❌ Could not resolve the instance's private IP"
        exit 1
    fi
    # private-ip OCID for that address (backticks come from printf's literal
    # format string — they are JMESPath literals, not shell substitution)
    Q="data[?\"ip-address\"==$(printf '`%s`' "$PADDR")].id | [0]"
    PRIV_IP_ID=$(oci network private-ip list --subnet-id "$OCI_SUBNET_ID" --query "$Q" --raw-output)
    if [[ -z "$PRIV_IP_ID" || "$PRIV_IP_ID" == "None" ]]; then
        echo "❌ Could not resolve private IP id for $PADDR"
        exit 1
    fi
    # Reassign from a previous instance if needed (direct move), else
    # detach first (the reserved IP may still point at a failed launch).
    if ! oci network public-ip update --public-ip-id "$OCI_RESERVED_IP_ID" \
            --private-ip-id "$PRIV_IP_ID" >/dev/null 2>&1; then
        oci network public-ip update --public-ip-id "$OCI_RESERVED_IP_ID" \
            --private-ip-id "" >/dev/null 2>&1 || true
        if ! oci network public-ip update --public-ip-id "$OCI_RESERVED_IP_ID" \
                --private-ip-id "$PRIV_IP_ID"; then
            echo "❌ Could not attach the reserved public IP"
            exit 1
        fi
    fi
    # Confirm and surface the address
    PUBLIC_IP=$(oci network public-ip get --public-ip-id "$OCI_RESERVED_IP_ID" \
        --query 'data."ip-address"' --raw-output)
    echo "✅ Reserved public IP attached: $PUBLIC_IP"
fi

# ------------------------------------------------------------------
# [3/4] Resolve public IP
# ------------------------------------------------------------------
echo "⏳ [3/4] Resolving public IP..."

PUBLIC_IP=""
for i in $(seq 1 30); do
    # --query data[0]."public-ip" --raw-output → bare IP or None/null while pending
    PUBLIC_IP=$(oci compute instance list-vnics --instance-id "$INSTANCE_ID" \
        --query 'data[0]."public-ip"' --raw-output 2>/dev/null || true)
    case "$PUBLIC_IP" in
        ""|None|null|"null") PUBLIC_IP="" ;;
    esac

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
