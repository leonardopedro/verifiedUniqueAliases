#!/bin/bash
# ==============================================================================
# import-oci-image.sh - Import the bootable QCOW2 as an Oracle Cloud custom image
#
# OCI image import accepts QCOW2 only (raw is rejected by the API).
# Uploads to Object Storage, then imports via `oci compute image import from-object`
# and polls the resulting image until AVAILABLE.
#
# Prerequisites:
#   - oci CLI configured (oci iam ... works)
#   - An Object Storage bucket in the target region
#
# Usage:
#   export OCI_COMPARTMENT_ID=ocid1.compartment.oc1..example
#   export OCI_BUCKET_NAME=paypal-auth-vm
#   # optional: export OCI_OS_NAMESPACE=... OCI_OBJECT_NAME=... IMAGE_DISPLAY_NAME=...
#   bash import-oci-image.sh
# ==============================================================================
set -eo pipefail

IMAGE_FILE="${IMAGE_FILE:-paypal-auth-vm-oci.qcow2}"
OCI_COMPARTMENT_ID="${OCI_COMPARTMENT_ID:-}"
OCI_BUCKET_NAME="${OCI_BUCKET_NAME:-}"
OCI_OBJECT_NAME="${OCI_OBJECT_NAME:-$IMAGE_FILE}"
IMAGE_DISPLAY_NAME="${IMAGE_DISPLAY_NAME:-paypal-auth-vm-$(date +%Y%m%d)}"

if ! command -v oci &> /dev/null; then
    echo "❌ 'oci' CLI not found"
    exit 1
fi

if [[ -z "$OCI_COMPARTMENT_ID" || -z "$OCI_BUCKET_NAME" ]]; then
    echo "❌ Set OCI_COMPARTMENT_ID and OCI_BUCKET_NAME environment variables"
    echo "   Example:"
    echo "     export OCI_COMPARTMENT_ID=ocid1.compartment.oc1..example"
    echo "     export OCI_BUCKET_NAME=paypal-auth-vm"
    exit 1
fi

if [[ ! -f "$IMAGE_FILE" ]]; then
    echo "❌ $IMAGE_FILE not found"
    echo "   Run: bash build-oci-docker.sh first"
    exit 1
fi

if [[ -z "${OCI_OS_NAMESPACE:-}" ]]; then
    echo "⏳ Resolving Object Storage namespace..."
    OCI_OS_NAMESPACE=$(oci os namespace get --raw-output)
fi

echo "============================================================"
echo "📦 Importing QCOW2 as Oracle Cloud Custom Image"
echo "============================================================"
echo "   File      : $IMAGE_FILE ($(du -h "$IMAGE_FILE" | cut -f1))"
echo "   SHA256    : $(sha256sum "$IMAGE_FILE" | cut -d' ' -f1)"
echo "   Bucket    : $OCI_BUCKET_NAME/$OCI_OBJECT_NAME (ns: $OCI_OS_NAMESPACE)"
echo "   Name      : $IMAGE_DISPLAY_NAME"
echo ""

# Step 1: Upload to Object Storage
echo "⏳ [1/3] Uploading to Object Storage..."
oci os object put \
    --bucket-name "$OCI_BUCKET_NAME" \
    --name "$OCI_OBJECT_NAME" \
    --file "$IMAGE_FILE" \
    --force --output json > /dev/null
echo "✅ Uploaded: $OCI_BUCKET_NAME/$OCI_OBJECT_NAME"

# Step 2: Import as custom image (returns Image in IMPORTING state)
echo "⏳ [2/3] Starting image import..."

IMPORT_OUTPUT=$(oci compute image import from-object \
    --compartment-id "$OCI_COMPARTMENT_ID" \
    --namespace "$OCI_OS_NAMESPACE" \
    --bucket-name "$OCI_BUCKET_NAME" \
    --name "$OCI_OBJECT_NAME" \
    --source-image-type QCOW2 \
    --launch-mode PARAVIRTUALIZED \
    --display-name "$IMAGE_DISPLAY_NAME" \
    --output json 2>&1) || {
        echo "❌ Image import failed:"
        echo "$IMPORT_OUTPUT"
        exit 1
    }

IMAGE_ID=$(echo "$IMPORT_OUTPUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
data = d.get('data', d)
print(data.get('id', data.get('imageId', '')))
" 2>/dev/null || true)

if [[ -z "$IMAGE_ID" ]]; then
    echo "❌ Could not parse image id from import response:"
    echo "$IMPORT_OUTPUT"
    exit 1
fi
echo "✅ Import started: $IMAGE_ID"

# Step 3: Poll until AVAILABLE
echo "⏳ [3/3] Waiting for image to become AVAILABLE..."
STATE=""
for i in $(seq 1 180); do
    STATE=$(oci compute image get --image-id "$IMAGE_ID" \
        --query 'data."lifecycle-state"' --raw-output 2>/dev/null || echo "UNKNOWN")
    echo "   state: $STATE"
    if [[ "$STATE" == "AVAILABLE" ]]; then
        echo ""
        echo "============================================================"
        echo "✅ Image import complete!"
        echo "============================================================"
        echo "   Image ID : $IMAGE_ID"
        echo "   Name     : $IMAGE_DISPLAY_NAME"
        echo "============================================================"
        echo ""
        echo "Next step:"
        echo "  export OCI_IMAGE_ID=$IMAGE_ID"
        echo "  bash deploy-oci.sh"
        echo ""
        exit 0
    fi
    if [[ "$STATE" == "FAILED" ]]; then
        echo "❌ Image import failed (see image details: $IMAGE_ID)"
        oci compute image get --image-id "$IMAGE_ID" --output json || true
        exit 1
    fi
    sleep 10
done

echo "⚠️ Timeout waiting for image import (last state: $STATE)"
echo "   Check: oci compute image get --image-id $IMAGE_ID"
exit 1
