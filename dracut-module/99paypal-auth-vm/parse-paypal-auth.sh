#!/bin/sh
# parse-paypal-auth.sh - Early boot configuration

type getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh

# Fetch metadata from OCI
fetch_metadata() {
    local key=$1
    curl -sf -H "Authorization: Bearer Oracle" \
        "http://169.254.169.254/opc/v1/instance/metadata/$key"
}

# Wait for network
while ! curl -sf http://169.254.169.254/ >/dev/null 2>&1; do
    echo "Waiting for metadata service..."
    sleep 1
done

# Export configuration
export PAYPAL_CLIENT_ID=$(fetch_metadata paypal_client_id)
export DOMAIN=$(fetch_metadata domain)
export SECRET_OCID=$(fetch_metadata secret_ocid)
export OCI_REGION=$(curl -sf http://169.254.169.254/opc/v2/instance/region)
export NOTIFICATION_TOPIC_ID=$(fetch_metadata notification_topic_id)
export SIGNING_KEY=$(fetch_metadata signing_key)

# Persist for later stages
{
    echo "PAYPAL_CLIENT_ID=$PAYPAL_CLIENT_ID"
    echo "DOMAIN=$DOMAIN"
    echo "SECRET_OCID=$SECRET_OCID"
    echo "OCI_REGION=$OCI_REGION"
    echo "NOTIFICATION_TOPIC_ID=$NOTIFICATION_TOPIC_ID"
    echo "SIGNING_KEY=$SIGNING_KEY"
} > /run/paypal-auth.env
