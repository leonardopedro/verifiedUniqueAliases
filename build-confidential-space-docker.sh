#!/bin/bash
set -ex

# Build the docker container
docker build -f Dockerfile.confidential-space -t paypal-rust-app:latest .

# Extract the SHA256 digest of the image
IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' paypal-rust-app:latest | cut -d'@' -f2)

if [ -z "$IMAGE_DIGEST" ]; then
    echo "Could not extract digest! Did you push the image to a registry?"
    echo "Wait, local images might not have RepoDigests. Let's use Id."
    IMAGE_DIGEST=$(docker inspect --format='{{.Id}}' paypal-rust-app:latest)
fi

echo "Successfully built paypal-rust-app:latest"
echo "Image Digest: $IMAGE_DIGEST"

echo "Updating deploy-confidential-space.sh with the container hash..."
sed -i "s/YOUR_CONTAINER_HASH/$IMAGE_DIGEST/g" deploy-confidential-space.sh

echo "Done! You can now run deploy-confidential-space.sh."
