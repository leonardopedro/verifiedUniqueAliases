#!/bin/bash
# fix-podman-idx.sh - Fixes Podman configuration in IDX/Nix environments

set -e

CONTAINERS_CONF_DIR="$HOME/.config/containers"
mkdir -p "$CONTAINERS_CONF_DIR"

echo "🔧 Configuring Podman policy..."
cat <<EOF > "$CONTAINERS_CONF_DIR/policy.json"
{
    "default": [
        {
            "type": "insecureAcceptAnything"
        }
    ]
}
EOF

echo "🔧 Configuring Podman registries..."
if [ ! -f "$CONTAINERS_CONF_DIR/registries.conf" ]; then
cat <<EOF > "$CONTAINERS_CONF_DIR/registries.conf"
unqualified-search-registries = ["docker.io", "quay.io", "container-registry.oracle.com"]

[[registry]]
location = "docker.io"

[[registry]]
location = "container-registry.oracle.com"
EOF
fi

echo "✅ Podman configuration updated in $CONTAINERS_CONF_DIR"
echo "🚀 You can now run ./build-docker.sh"
