#!/bin/sh
# Debug startup script for Confidential Space

# Try writing to kernel log
log_kmsg() {
    echo "$1" > /dev/kmsg 2>/dev/null || true
}

# Try writing to stderr
log() {
    echo "$1" >&2
    log_kmsg "PAYPAL-AUTH: $1"
}

log "Script starting"
log "PAYPAL_CLIENT_ID=${PAYPAL_CLIENT_ID:-(empty)}"
log "DOMAIN=${DOMAIN:-(empty)}"
log "PATH=$PATH"

# Check if binary exists
if [ ! -f /usr/local/bin/paypal-auth-vm ]; then
    log "ERROR: Binary not found at /usr/local/bin/paypal-auth-vm"
    exit 1
fi

log "Binary exists, launching..."
exec /usr/local/bin/paypal-auth-vm
