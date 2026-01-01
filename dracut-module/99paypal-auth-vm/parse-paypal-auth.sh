#!/bin/sh
# parse-paypal-auth.sh - Early boot configuration

type getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh

# Fetch metadata from OCI
fetch_metadata() {
    local key=$1
    curl -sf -H "Authorization: Bearer Oracle" \
        "http://169.254.169.254/opc/v1/instance/metadata/$key"
}

# Wait for metadata service with timeout
echo "Checking for OCI metadata service..."
if ! curl -sf --connect-timeout 2 http://169.254.169.254/ >/dev/null 2>&1; then
    echo "⚠️ OCI metadata service not found. Using local test defaults."
    export PAYPAL_CLIENT_ID="test_client_id"
    export DOMAIN="localhost"
    export SECRET_OCID="test_secret_ocid"
    export OCI_REGION="us-ashburn-1"
    export NOTIFICATION_TOPIC_ID="test_topic_id"
else
    # OCI flow
    while ! curl -sf http://169.254.169.254/ >/dev/null 2>&1; do
        echo "Waiting for metadata service (OCI)..."
        sleep 1
    done
    export PAYPAL_CLIENT_ID=$(fetch_metadata paypal_client_id)
    export DOMAIN=$(fetch_metadata domain)
    export SECRET_OCID=$(fetch_metadata secret_ocid)
    export OCI_REGION=$(curl -sf http://169.254.169.254/opc/v2/instance/region)
    export NOTIFICATION_TOPIC_ID=$(fetch_metadata notification_topic_id)
fi

# Persist for later stages
{
    echo "PAYPAL_CLIENT_ID=$PAYPAL_CLIENT_ID"
    echo "DOMAIN=$DOMAIN"
    echo "SECRET_OCID=$SECRET_OCID"
    echo "OCI_REGION=$OCI_REGION"
    echo "NOTIFICATION_TOPIC_ID=$NOTIFICATION_TOPIC_ID"
} > /run/paypal-auth.env
