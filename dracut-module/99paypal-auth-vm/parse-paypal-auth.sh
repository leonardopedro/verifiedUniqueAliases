#!/bin/sh
# parse-paypal-auth.sh - Early boot configuration

type getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh

# Fetch metadata from GCP
fetch_metadata() {
    key="$1"
    curl -sf -H "Metadata-Flavor: Google" \
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/${key}"
}

# Ensure kernel modules for networking are loaded
echo "Loading GCP Virtual NIC and Virtio drivers..."
modprobe gve || true
modprobe virtio_net || true
udevadm settle

# Wait for a real network interface to appear
echo "Waiting for network interfaces to enumerate..."
while ! ip link show | grep -v 'lo:' | grep -q 'state'; do
    sleep 1
done

# Ensure network interface is up (fallback if dracut network module failed to initialize it)
echo "Bringing up network interfaces..."
ip link
for iface in $(ip link show | awk -F': ' '/^[0-9]+:/ {print $2}' | grep -v -e '^lo$'); do
    echo "Initializing $iface..."
    ip link set $iface up || true
    dhclient $iface -timeout 10 || true
done

# Wait for network and metadata service
while ! curl -sf -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/ >/dev/null 2>&1; do
    echo "Waiting for GCP metadata service..."
    sleep 1
done

# Export configuration (GCP-style via tee-env- attributes)
SECRET_NAME=$(fetch_metadata "tee-env-SECRET_NAME")
export SECRET_NAME
TLS_CACHE_SECRET=$(fetch_metadata "tee-env-TLS_CACHE_SECRET")
export TLS_CACHE_SECRET
RUST_LOG=$(fetch_metadata "tee-env-RUST_LOG")
export RUST_LOG

# Persist for later stages
{
    echo "SECRET_NAME=$SECRET_NAME"
    echo "TLS_CACHE_SECRET=$TLS_CACHE_SECRET"
    echo "RUST_LOG=${RUST_LOG:-info}"
} > /run/paypal-auth.env
