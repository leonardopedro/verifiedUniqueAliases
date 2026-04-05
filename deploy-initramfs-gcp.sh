#!/bin/bash
set -ex

[ -z "$PROJECT_ID" ] && { echo "Set PROJECT_ID"; exit 1; }

LOCATION="europe-west4"
SA_NAME="paypal-auth-sa"

echo "Building custom glibc initramfs & kernel (via Docker)..."
# Build the initramfs via Docker
DOCKER_BUILDKIT=1 docker build -t paypal-builder -f Dockerfile .

echo "Extracting artifacts..."
mkdir -p output
docker ps -a | grep paypal-dummy && docker rm -f paypal-dummy || true
docker create --name paypal-dummy paypal-builder
docker cp paypal-dummy:/img/initramfs-paypal-auth.img ./output/
docker cp paypal-dummy:/img/vmlinuz ./output/
docker cp paypal-dummy:/img/initramfs-paypal-auth.img.sha256 ./output/
docker rm -f paypal-dummy

if [ ! -s "./output/vmlinuz" ] || [ ! -s "./output/initramfs-paypal-auth.img" ]; then
    echo "Failed to extract kernel or initramfs!"
    exit 1
fi

echo "Creating GCP environment secrets and VM..."
gcloud secrets create PAYPAL_TLS_CACHE --replication-policy="automatic" 2>/dev/null || true
gcloud iam service-accounts create $SA_NAME --display-name "PayPal Auth" 2>/dev/null || true
for ROLE in roles/secretmanager.secretAccessor roles/secretmanager.secretVersionAdder roles/publicca.externalAccountKeyCreator; do
    gcloud projects add-iam-policy-binding $PROJECT_ID \
        --member "serviceAccount:${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
        --role "$ROLE" --condition=None 2>/dev/null || true
done

gcloud compute instances delete paypal-auth-vm --zone=${LOCATION}-a --quiet 2>/dev/null || true

gcloud compute instances create paypal-auth-vm \
    --zone ${LOCATION}-a \
    --machine-type n2d-highcpu-2 \
    --confidential-compute-type=SEV_SNP \
    --image-family=ubuntu-2510-amd64 \
    --image-project=ubuntu-os-cloud \
    --service-account ${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com \
    --subnet=default \
    --address=34.7.107.227 \
    --tags http-server,https-server \
    --shielded-secure-boot \
    --maintenance-policy=TERMINATE \
    --metadata=tee-env-SECRET_NAME=projects/${PROJECT_ID}/secrets/PAYPAL_AUTH_CONFIG/versions/latest,tee-env-TLS_CACHE_SECRET=projects/${PROJECT_ID}/secrets/PAYPAL_TLS_CACHE,tee-env-RUST_LOG=trace

echo "Waiting for SSH..."
sleep 20

echo "Uploading custom OS components..."
gcloud compute scp --zone=${LOCATION}-a ./output/vmlinuz paypal-auth-vm:/tmp/vmlinuz
gcloud compute scp --zone=${LOCATION}-a ./output/initramfs-paypal-auth.img paypal-auth-vm:/tmp/initrd.img

echo "Configuring custom GRUB boot on VM..."
gcloud compute ssh --zone=${LOCATION}-a paypal-auth-vm --command="sudo bash -c '
mv /tmp/vmlinuz /boot/vmlinuz-custom
mv /tmp/initrd.img /boot/initrd.img-custom
chmod 644 /boot/vmlinuz-custom /boot/initrd.img-custom

cat << EOF >> /etc/grub.d/40_custom
menuentry \"Confidential Custom Initramfs\" {
    linux /boot/vmlinuz-custom console=ttyS0 quiet panic=1 ro ip=dhcp rd.neednet=1
    initrd /boot/initrd.img-custom
}
EOF

# Set default boot entry to the newly created menuentry name
sed -i \"s/GRUB_DEFAULT=0/GRUB_DEFAULT=\\\"Confidential Custom Initramfs\\\"/\" /etc/default/grub

update-grub
'"

echo "Rebooting into custom initramfs..."
gcloud compute instances reset paypal-auth-vm --zone=${LOCATION}-a --quiet || true

echo "Deployment complete! Service should boot directly into RAM from the custom initramfs in 1-2 minutes."
