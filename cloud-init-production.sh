#!/bin/bash
# ==============================================================================
# Final Production Cloud-Init for PayPal Auth (Oracle Linux 10 + IMA + Firewall)
# ==============================================================================

set -e

# 1. Fetch metadata
PAYPAL_CLIENT_ID=$(curl -sL http://169.254.169.254/opc/v2/instance/metadata/paypal_client_id -H "Authorization: Bearer Oracle")
DOMAIN=$(curl -sL http://169.254.169.254/opc/v2/instance/metadata/domain -H "Authorization: Bearer Oracle")

echo "PAYPAL_CLIENT_ID=$PAYPAL_CLIENT_ID" > /etc/paypal-auth.env
echo "DOMAIN=$DOMAIN" >> /etc/paypal-auth.env

# 2. Download the Rust Application Binary
PAR_URL="https://objectstorage.eu-frankfurt-1.oraclecloud.com/p/DLgugSBEJmZEA_VRMBZv2swHioLZokpYXZ7Nw20Jnl97rJSVJEQKJQeNrOBBAqP-/n/fronpbp0mpan/b/paypal-vm-images/o/paypal-auth-vm-latest"
curl -sL "$PAR_URL" -o /usr/bin/paypal-auth-vm
chmod +x /usr/bin/paypal-auth-vm

# 3. Create the Systemd Service
cat << 'EOF' > /etc/systemd/system/paypal-auth.service
[Unit]
Description=Confidential PayPal Auth Service
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/paypal-auth-vm
Restart=always
User=root
EnvironmentFile=/etc/paypal-auth.env

[Install]
WantedBy=multi-user.target
EOF

# 4. Open Guest Firewall (Crucial for ACME and API Access)
# Oracle Linux has firewalld enabled by default. We must open 80, 443, and 22.
dnf install -y tpm2-tools
systemctl start firewalld
firewall-cmd --permanent --add-port=22/tcp
firewall-cmd --permanent --add-port=80/tcp
firewall-cmd --permanent --add-port=443/tcp
firewall-cmd --reload

# 5. Enable IMA (Integrity Measurement Architecture)
# Use grubby to update all kernel entries safely
dnf install -y grubby
grubby --update-kernel=ALL --args="ima_policy=tcb ima_hash=sha256"

# 6. Enable and Start the Application
systemctl daemon-reload
systemctl enable paypal-auth.service

# 7. Flag for Reboot (to apply IMA configuration)
if [ ! -f /var/lib/cloud/instance/ima_configured ]; then
    touch /var/lib/cloud/instance/ima_configured
    echo "🔒 IMA and Firewall configured. Triggering final reboot for attestation..."
    reboot
fi

echo "✅ PayPal Auth VM successfully deployed via cloud-init!"
