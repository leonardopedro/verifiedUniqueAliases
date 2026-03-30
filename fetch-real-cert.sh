#!/usr/bin/env bash
# =============================================================================
# fetch-real-cert.sh
#
# Removes the temporary self-signed certificates and restarts the service
# to allow it to fetch a real, browser-trusted Let's Encrypt certificate.
#
# Run this script AFTER 20:25 UTC when the Let's Encrypt rate limit expires.
# =============================================================================

set -euo pipefail

VM_HOST="${VM_HOST:-34.41.85.160}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519_leo}"
SSH_USER="${SSH_USER:-opc}"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          PayPal Auth Service — Fetch Real Cert              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

ssh $SSH_OPTS "${SSH_USER}@${VM_HOST}" bash <<EOF
set -e

# Let's Encrypt unlocks exactly at 22:45:59 UTC
CURRENT_UTC_EPOCH=\$(date -u +%s)
UNLOCK_UTC_EPOCH=\$(date -u -d "2026-03-29 22:46:00" +%s)

if [ "\$CURRENT_UTC_EPOCH" -lt "\$UNLOCK_UTC_EPOCH" ]; then
    REMAINING=\$((UNLOCK_UTC_EPOCH - CURRENT_UTC_EPOCH))
    MINS=\$((REMAINING / 60))
    SECS=\$((REMAINING % 60))
    echo "❌ Let's Encrypt limit is still active!"
    echo "Wait exactly \${MINS}m \${SECS}s before running this script again."
    echo "The UI is still up using the proxy cert."
    exit 1
fi

echo "🗑️  Deleting temporary self-signed certificates..."
sudo rm -f /etc/paypal-auth.cert.pem /etc/paypal-auth.key.pem

echo "🔄 Restarting paypal-auth service..."
sudo systemctl restart paypal-auth.service

echo "⏳ Waiting for Let's Encrypt..."
sleep 15

echo "📋 Service Status:"
sudo systemctl status paypal-auth.service --no-pager

echo ""
echo "📜 Recent Logs:"
sudo journalctl -u paypal-auth.service -n 15 --no-pager
EOF

echo ""
echo "✅ Done!"
