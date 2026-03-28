#!/bin/bash
# ==============================================================================
# cloud-init user_data for PayPal Auth VM (Confidential Node)
# ==============================================================================

# Enable exit on error
set -e

# 1. Fetch metadata configured in the OCI launch command
PAYPAL_CLIENT_ID=$(curl -sL http://169.254.169.254/opc/v2/instance/metadata/paypal_client_id -H "Authorization: Bearer Oracle")
DOMAIN=$(curl -sL http://169.254.169.254/opc/v2/instance/metadata/domain -H "Authorization: Bearer Oracle")

echo "PAYPAL_CLIENT_ID=$PAYPAL_CLIENT_ID" > /etc/paypal-auth.env
echo "DOMAIN=$DOMAIN" >> /etc/paypal-auth.env

# 2. Download the Rust Application Binary from Object Storage
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

# Retrieve instance metadata environment variables safely
EnvironmentFile=/etc/paypal-auth.env

[Install]
WantedBy=multi-user.target
EOF

# 4. Enable and Start the Application
systemctl daemon-reload
systemctl enable paypal-auth.service
systemctl start paypal-auth.service

echo "✅ PayPal Auth VM successfully deployed via cloud-init!"
