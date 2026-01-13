#!/bin/bash
set -e

# Target partition
PARTITION_PATH="/media/leo/e7ed9d6f-5f0a-4e19-a74e-83424bc154ba"

# Source Nix profile if it exists (for re-runs)
if [ -e /etc/profile.d/nix.sh ]; then
    . /etc/profile.d/nix.sh
fi

echo "🚀 Preparing Nix installation on $PARTITION_PATH..."

# 1. Prepare storage path
sudo mkdir -p "$PARTITION_PATH/nix"
sudo mkdir -p /nix

# 2. Set up bind mount
if ! mountpoint -q /nix; then
    sudo mount --bind "$PARTITION_PATH/nix" /nix
    echo "✅ /nix bind-mounted to $PARTITION_PATH/nix"
else
    echo "ℹ️ /nix is already a mountpoint"
fi

# 3. Persistent mount in fstab
if ! grep -q "/nix" /etc/fstab; then
    echo "$PARTITION_PATH/nix  /nix  none  bind  0  0" | sudo tee -a /etc/fstab
    echo "✅ Added bind mount to /etc/fstab"
else
    echo "ℹ️ /nix already in /etc/fstab"
fi

# 4. Install Nix
if ! command -v nix &> /dev/null; then
    echo "📦 Installing Nix..."
    sh <(curl -L https://nixos.org/nix/install) --daemon --yes
    
    # Source the nix profile to make commands available in this script session
    if [ -e /etc/profile.d/nix.sh ]; then
        . /etc/profile.d/nix.sh
    fi
else
    echo "ℹ️ Nix is already installed"
fi

# 5. Configure Nix Flakes
sudo mkdir -p /etc/nix
if ! grep -q "experimental-features" /etc/nix/nix.conf 2>/dev/null; then
    echo "experimental-features = nix-command flakes" | sudo tee -a /etc/nix/nix.conf
    echo "✅ Enabled Nix flakes"
fi

# 6. Configure Channel
nix-channel --add https://nixos.org/channels/nixos-25.05 nixpkgs
nix-channel --update

echo "🎉 Nix installation complete! Please restart your shell."
