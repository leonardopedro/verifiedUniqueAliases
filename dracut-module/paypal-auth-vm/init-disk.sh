#!/bin/bash
# init-disk.sh - Creates the encrypted partition on first boot
# This script is ONLY needed once to set up the disk

set -e

echo "💾 Initializing encrypted certificate storage..."

# Check if already initialized
if [ -b /dev/mapper/encrypted_data ]; then
    echo "✅ Encrypted storage already initialized"
    exit 0
fi

# Check if partition exists
if [ ! -b /dev/sda2 ]; then
    echo "Creating partition for certificate storage..."
    # Create 1GB partition for certs (more than enough)
    parted /dev/sda -s mkpart primary ext4 1GB 2GB
    sleep 2
fi

# Format with LUKS using key from initramfs
echo "🔐 Encrypting partition..."
cryptsetup luksFormat /dev/sda2 --key-file /etc/luks.key

# Open encrypted volume
cryptsetup luksOpen /dev/sda2 encrypted_data --key-file /etc/luks.key

# Create filesystem
mkfs.ext4 -L "cert_storage" /dev/mapper/encrypted_data

# Mount
mount /dev/mapper/encrypted_data /mnt/encrypted

# Create directory structure
mkdir -p /mnt/encrypted/tls

echo "✅ Encrypted certificate storage initialized"
echo "ℹ️  Disk will only store TLS certificates"
echo "ℹ️  All application code runs from initramfs"

# Unmount
umount /mnt/encrypted
cryptsetup luksClose encrypted_data

echo "🎉 Setup complete! Reboot to start normal operation"