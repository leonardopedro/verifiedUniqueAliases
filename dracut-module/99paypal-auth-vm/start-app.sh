#!/bin/sh
# start-app.sh - Start the Rust application

. /run/paypal-auth.env

# Create runtime directories
mkdir -p /run/certs
mkdir -p /tmp/acme-challenge

# The Rust application will handle ACME certificate acquisition
# We just need to exec into it
echo "Starting PayPal Auth application..."

# Measure the binary into PCR 15
BIN_HASH=$(sha256sum /bin/paypal-auth-vm | awk '{print $1}')
echo "Measuring binary hash $BIN_HASH into PCR 15..."
tpm2_pcrextend 15:sha256=$BIN_HASH

# Execute application (this replaces init)
exec /bin/paypal-auth-vm
