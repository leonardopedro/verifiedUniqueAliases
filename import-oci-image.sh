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
    # NOTE: --raw-output alone still returns the full JSON envelope for this
    # endpoint; --query data unwraps it to the bare namespace string.
    OCI_OS_NAMESPACE=$(oci os ns get --query data --raw-output)
    if [[ -z "$OCI_OS_NAMESPACE" || "$OCI_OS_NAMESPACE" == "None" ]]; then
        echo "❌ Could not resolve Object Storage namespace"
        exit 1
    fi
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
echo "⏳ [1/4] Uploading to Object Storage..."
oci os object put \
    --bucket-name "$OCI_BUCKET_NAME" \
    --name "$OCI_OBJECT_NAME" \
    --file "$IMAGE_FILE" \
    --force --output json > /dev/null
echo "✅ Uploaded: $OCI_BUCKET_NAME/$OCI_OBJECT_NAME"

# Step 2: Import as custom image (returns Image in IMPORTING state)
echo "⏳ [2/4] Starting image import..."

IMPORT_OUTPUT=$(oci compute image import from-object \
    --compartment-id "$OCI_COMPARTMENT_ID" \
    --namespace "$OCI_OS_NAMESPACE" \
    --bucket-name "$OCI_BUCKET_NAME" \
    --name "$OCI_OBJECT_NAME" \
    --source-image-type QCOW2 \
    --launch-mode PARAVIRTUALIZED \
    --display-name "$IMAGE_DISPLAY_NAME" \
    --query 'data.id' \
    --raw-output 2>&1) || {
        echo "❌ Image import failed:"
        echo "$IMPORT_OUTPUT"
        exit 1
    }

# --query data.id --raw-output returns the bare OCID (no JSON, no python needed)
IMAGE_ID=$(echo "$IMPORT_OUTPUT" | tr -d '[:space:]')

if [[ -z "$IMAGE_ID" || "$IMAGE_ID" == "None" ]]; then
    echo "❌ Could not parse image id from import response:"
    echo "$IMPORT_OUTPUT"
    exit 1
fi
echo "✅ Import started: $IMAGE_ID"

# Step 3: Poll until AVAILABLE
echo "⏳ [3/4] Waiting for image to become AVAILABLE..."
STATE=""
for i in $(seq 1 180); do
    STATE=$(oci compute image get --image-id "$IMAGE_ID" \
        --query 'data."lifecycle-state"' --raw-output 2>/dev/null || echo "UNKNOWN")
    echo "   state: $STATE"
    if [[ "$STATE" == "AVAILABLE" ]]; then
        # Step 4: attach an image capability schema. Imported images have NO
        # capabilities by default and cannot launch — confidential (AMD SEV/SNP)
        # launches fail with "No image capabilities found for image", and the
        # firmware defaults to BIOS even for UEFI disks.
        echo "⏳ [4/4] Attaching image capability schema (UEFI + AMD SEV/SNP)..."
        EXISTING_SCHEMA=$(oci compute image-capability-schema list --image-id "$IMAGE_ID" \
            --query 'data[0].id' --raw-output 2>/dev/null || true)
        if [[ -n "$EXISTING_SCHEMA" && "$EXISTING_SCHEMA" != "None" ]]; then
            echo "✅ Capability schema already attached: $EXISTING_SCHEMA"
        else
            GLOBAL_VERSION=$(oci compute global-image-capability-schema list \
                --query 'data[0]."current-version-name"' --raw-output)
            CAPS_FILE=$(mktemp)
            trap 'rm -f "$CAPS_FILE"' EXIT
            cat > "$CAPS_FILE" <<'CAPSEOF'
{
  "Compute.AMD_SecureEncryptedVirtualization": {
    "default-value": true,
    "descriptor-type": "boolean",
    "source": "IMAGE"
  },
  "Compute.AMD_SecureEncryptedVirtualization_SecureNestedPaging": {
    "default-value": true,
    "descriptor-type": "boolean",
    "source": "IMAGE"
  },
  "Compute.Firmware": {
    "default-value": "UEFI_64",
    "descriptor-type": "enumstring",
    "source": "IMAGE",
    "values": ["BIOS", "UEFI_64"]
  },
  "Compute.LaunchMode": {
    "default-value": "PARAVIRTUALIZED",
    "descriptor-type": "enumstring",
    "source": "GLOBAL",
    "values": ["NATIVE", "EMULATED", "VDPA", "PARAVIRTUALIZED", "CUSTOM"]
  },
  "Compute.SecureBoot": {
    "default-value": false,
    "descriptor-type": "boolean",
    "source": "GLOBAL"
  },
  "Network.AttachmentType": {
    "default-value": "PARAVIRTUALIZED",
    "descriptor-type": "enumstring",
    "source": "GLOBAL",
    "values": ["VFIO", "PARAVIRTUALIZED", "E1000", "VDPA"]
  },
  "Network.IPv6Only": {
    "default-value": false,
    "descriptor-type": "boolean",
    "source": "GLOBAL"
  },
  "Storage.BootVolumeType": {
    "default-value": "PARAVIRTUALIZED",
    "descriptor-type": "enumstring",
    "source": "GLOBAL",
    "values": ["ISCSI", "PARAVIRTUALIZED", "SCSI", "IDE", "NVME"]
  },
  "Storage.ConsistentVolumeNaming": {
    "default-value": true,
    "descriptor-type": "boolean",
    "source": "GLOBAL"
  },
  "Storage.Iscsi.MultipathDeviceSupported": {
    "default-value": false,
    "descriptor-type": "boolean",
    "source": "GLOBAL"
  },
  "Storage.LocalDataVolumeType": {
    "default-value": "PARAVIRTUALIZED",
    "descriptor-type": "enumstring",
    "source": "GLOBAL",
    "values": ["ISCSI", "PARAVIRTUALIZED", "SCSI", "IDE", "NVME"]
  },
  "Storage.ParaVirtualization.AttachmentVersion": {
    "default-value": 2,
    "descriptor-type": "enuminteger",
    "source": "GLOBAL",
    "values": [1, 2]
  },
  "Storage.ParaVirtualization.EncryptionInTransit": {
    "default-value": true,
    "descriptor-type": "boolean",
    "source": "GLOBAL"
  },
  "Storage.RemoteDataVolumeType": {
    "default-value": "PARAVIRTUALIZED",
    "descriptor-type": "enumstring",
    "source": "GLOBAL",
    "values": ["ISCSI", "PARAVIRTUALIZED", "SCSI", "IDE", "NVME"]
  }
}
CAPSEOF
            SCHEMA_OUT=$(oci compute image-capability-schema create \
                --compartment-id "$OCI_COMPARTMENT_ID" \
                --image-id "$IMAGE_ID" \
                --global-image-capability-schema-version-name "$GLOBAL_VERSION" \
                --display-name "${IMAGE_DISPLAY_NAME}-caps" \
                --schema-data "file://$CAPS_FILE" \
                --wait-for-state ACTIVE \
                --query 'data.id' --raw-output 2>&1) || {
                    echo "❌ Capability schema creation failed:"
                    echo "$SCHEMA_OUT"
                    exit 1
                }
            SCHEMA_ID=$(echo "$SCHEMA_OUT" | grep -oE 'ocid1\.computeimgcapschema[^[:space:]]+' | head -1)
            echo "✅ Capability schema attached: ${SCHEMA_ID:-done}"
        fi

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
