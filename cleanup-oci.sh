#!/bin/bash
set -e

# Configuration
INSTANCE_NAME="paypal-auth-vm"
IMAGE_NAME="paypal-auth-cvm-v7"
BUCKET_NAME="paypal-vm-images"
OBJECT_NAME="paypal-auth-vm.qcow2"

echo "🧹 OCI Resource Cleanup Script"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check prerequisites
if [ -z "$COMPARTMENT_ID" ]; then
    echo "❌ Error: COMPARTMENT_ID environment variable is not set."
    echo "   Please export it: export COMPARTMENT_ID=\"ocid1.compartment...\""
    exit 1
fi

echo "   Compartment: $COMPARTMENT_ID"
echo ""

# 1. Terminate Instance
echo "🔍 Searching for instance '$INSTANCE_NAME'..."
INSTANCE_ID=$(oci compute instance list \
    --compartment-id "$COMPARTMENT_ID" \
    --display-name "$INSTANCE_NAME" \
    --lifecycle-state RUNNING \
    --query 'data[0].id' \
    --raw-output 2>/dev/null || echo "")

if [ -z "$INSTANCE_ID" ] || [ "$INSTANCE_ID" == "null" ]; then
    # Check for STOPPED instances too
    INSTANCE_ID=$(oci compute instance list \
        --compartment-id "$COMPARTMENT_ID" \
        --display-name "$INSTANCE_NAME" \
        --lifecycle-state STOPPED \
        --query 'data[0].id' \
        --raw-output 2>/dev/null || echo "")
fi

if [ -n "$INSTANCE_ID" ] && [ "$INSTANCE_ID" != "null" ]; then
    echo "   Found Instance: $INSTANCE_ID"

    # Get Availability Domain and Boot Volume ID
    AVAILABILITY_DOMAIN=$(oci compute instance get --instance-id "$INSTANCE_ID" --query 'data."availability-domain"' --raw-output)
    BOOT_VOLUME_ID=$(oci compute boot-volume-attachment list --instance-id "$INSTANCE_ID" --availability-domain "$AVAILABILITY_DOMAIN" --compartment-id "$COMPARTMENT_ID" --query 'data[0]."boot-volume-id"' --raw-output)
    if [ -n "$BOOT_VOLUME_ID" ] && [ "$BOOT_VOLUME_ID" != "null" ]; then
        echo "   Found Boot Volume: $BOOT_VOLUME_ID"
    else
        BOOT_VOLUME_ID=""
    fi
    echo "🗑️  Terminating instance..."
    oci compute instance terminate --instance-id "$INSTANCE_ID" --force
    
    echo "⏳ Waiting for instance to terminate..."
    oci compute instance get --instance-id "$INSTANCE_ID" --wait-for-state TERMINATED
    echo "✅ Instance terminated."

    # Delete Boot Volume
    if [ -n "$BOOT_VOLUME_ID" ]; then
        echo "🗑️  Deleting Boot Volume..."
        oci bv boot-volume delete  --boot-volume-id "$BOOT_VOLUME_ID" --force
        echo "✅ Boot Volume deleted."
    fi
else
    echo "   Instance not found (active or stopped). Skipping."
fi

echo ""

# 2. Delete Custom Image
echo "🔍 Searching for custom image '$IMAGE_NAME'..."
IMAGE_ID=$(oci compute image list \
    --compartment-id "$COMPARTMENT_ID" \
    --display-name "$IMAGE_NAME" \
    --lifecycle-state AVAILABLE \
    --query 'data[0].id' \
    --raw-output 2>/dev/null || echo "")

if [ -n "$IMAGE_ID" ] && [ "$IMAGE_ID" != "null" ]; then
    echo "   Found Image: $IMAGE_ID"
    echo "🗑️  Deleting image..."
    oci compute image delete --image-id "$IMAGE_ID" --force
    echo "✅ Image deleted."
else
    echo "   Image not found. Skipping."
fi

echo ""

# 3. Delete Object
echo "🔍 Searching for object '$OBJECT_NAME' in bucket '$BUCKET_NAME'..."
OBJECT_EXISTS=$(oci os object list \
    --bucket-name "$BUCKET_NAME" \
    --prefix "$OBJECT_NAME" \
    --query "data[?name=='$OBJECT_NAME'] | [0].name" \
    --raw-output 2>/dev/null || echo "")

if [ "$OBJECT_EXISTS" == "$OBJECT_NAME" ]; then
    echo "   Found Object: $OBJECT_NAME"
    echo "🗑️  Deleting object..."
    oci os object delete \
        --bucket-name "$BUCKET_NAME" \
        --object-name "$OBJECT_NAME" \
        --force
    echo "✅ Object deleted."
else
    echo "   Object not found. Skipping."
fi

echo ""
echo "🎉 Cleanup complete!"
