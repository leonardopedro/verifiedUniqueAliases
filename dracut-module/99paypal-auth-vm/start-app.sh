#!/bin/sh
# start-app.sh - Start the Rust application

. /run/paypal-auth.env

# Create runtime directories
mkdir -p /run/certs
mkdir -p /tmp/acme-challenge

# The Rust application will handle ACME certificate acquisition
# We just need to exec into it
echo "Starting PayPal Auth application..."

# Execute application (this replaces init)
exec /bin/paypal-auth-vm
