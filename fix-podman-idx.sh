#!/bin/bash
# fix-podman-idx.sh - Fixes Podman configuration in IDX/Nix environments

set -e

# Handle both potential home directories in IDX
TARGET_DIRS=("$HOME/.config/containers")
if [ -d "/home/user" ]; then TARGET_DIRS+=("/home/user/.config/containers"); fi
if [ -d "/home/leo" ]; then TARGET_DIRS+=("/home/leo/.config/containers"); fi

for CONF_DIR in "${TARGET_DIRS[@]}"; do
    echo "🔧 Checking $CONF_DIR..."
    mkdir -p "$CONF_DIR" 2>/dev/null || continue
    
    echo "   Writing policy.json..."
    cat <<EOF > "$CONF_DIR/policy.json"
{
    "default": [
        {
            "type": "insecureAcceptAnything"
        }
    ]
}
EOF

    echo "   Writing registries.conf..."
    cat <<EOF > "$CONF_DIR/registries.conf"
unqualified-search-registries = ["docker.io", "quay.io", "container-registry.oracle.com"]

[[registry]]
location = "docker.io"

[[registry]]
location = "container-registry.oracle.com"
EOF

    echo "   Writing containers.conf..."
    cat <<EOF > "$CONF_DIR/containers.conf"
[containers]
# Ensure Podman doesn't use /var/tmp which is missing in IDX
[engine]
# Temporary directory for image content
tmp_dir = "/tmp"
EOF
    echo "   ✅ Updated $CONF_DIR"
done

echo "🚀 Setup complete. Please run: ./build-docker.sh"
