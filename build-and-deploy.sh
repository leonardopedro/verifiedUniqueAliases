#!/bin/bash
set -e

# Configuration
PROJECT="project-ae136ba1-3cc9-42cf-a48"
ZONE="europe-west4-a"
BUILD_VM="build-vm-paypal-n2d"
VERSION="v48"

echo "=== Building and Deploying PayPal Auth VM ($VERSION) ==="
echo ""

# Step 1: Build Rust binary locally
echo "🔨 Step 1: Building Rust binary locally..."
export RUSTFLAGS="-C target-cpu=generic -C codegen-units=1 -C strip=symbols"
export CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_OPT_LEVEL=2
cargo build --release --target x86_64-unknown-linux-gnu
echo "✅ Rust binary built successfully"
echo ""

# Step 2: Copy binary to build VM
echo "📤 Step 2: Copying Rust binary to build VM ($BUILD_VM)..."
gcloud compute scp target/x86_64-unknown-linux-gnu/release/paypal-auth-vm \
    ${BUILD_VM}:/tmp/paypal-auth-vm-bin \
    --project=$PROJECT --zone=$ZONE
echo "✅ Binary copied to build VM"
echo ""

# Step 3: Copy updated build scripts to build VM
echo "📤 Step 3: Copying updated build scripts to build VM..."
gcloud compute scp build-initramfs-tools.sh build-gcp-gpt-image.sh hooks/paypal-auth hooks/zz-reproducible.sh \
    ${BUILD_VM}:~/ \
    --project=$PROJECT --zone=$ZONE

gcloud compute ssh ${BUILD_VM} --project=$PROJECT --zone=$ZONE --command="
    mkdir -p ~/hooks ~/scripts/init-premount
    cp ~/paypal-auth ~/hooks/
    cp ~/zz-reproducible.sh ~/hooks/
    chmod +x ~/build-initramfs-tools.sh ~/build-gcp-gpt-image.sh ~/hooks/*
"
echo "✅ Build scripts copied"
echo ""

# Step 4: Build initramfs and disk image on build VM
echo "🏗️  Step 4: Building initramfs and disk image on build VM..."
gcloud compute ssh ${BUILD_VM} --project=$PROJECT --zone=$ZONE --command="
    set -e
    export SOURCE_DATE_EPOCH=1712260800
    export TZ=UTC
    export LC_ALL=C.UTF-8
    
    # Copy binary to expected location
    cp /tmp/paypal-auth-vm-bin ~/paypal-auth-vm-bin
    chmod +x ~/paypal-auth-vm-bin
    
    # Build initramfs
    cd ~
    ./build-initramfs-tools.sh
    
    # Extract bootloader files
    mkdir -p ~/output
    cp /boot/vmlinuz-*gcp ~/output/vmlinuz 2>/dev/null || {
        echo '❌ Kernel not found!'
        exit 1
    }
    
    # Find and copy shim and grub
    SHIM_PATH=\$(find /usr/lib/shim/ -name 'shimx64.efi.signed' 2>/dev/null | head -1)
    GRUB_PATH=\$(find /usr/lib/grub/ -name 'grubx64.efi.signed' 2>/dev/null | head -1)
    
    if [ -n \"\$SHIM_PATH\" ]; then
        cp \"\$SHIM_PATH\" ~/output/shimx64.efi
    else
        echo '❌ Shim not found!'
        exit 1
    fi
    
    if [ -n \"\$GRUB_PATH\" ]; then
        cp \"\$GRUB_PATH\" ~/output/grubx64.efi
    else
        echo '❌ GRUB not found!'
        exit 1
    fi
    
    echo '✅ Initramfs and artifacts built successfully'
    
    # Build GPT disk image
    ./build-gcp-gpt-image.sh
    
    echo '✅ Disk image built successfully'
    ls -lh ~/disk.tar.gz ~/disk.raw ~/paypal-auth-vm-gcp.qcow2
"
echo "✅ Initramfs and disk image built on build VM"
echo ""

# Step 5: Copy disk image back from build VM
echo "📥 Step 5: Copying disk image back from build VM..."
gcloud compute scp ${BUILD_VM}:~/disk.tar.gz ./disk.tar.gz \
    --project=$PROJECT --zone=$ZONE
echo "✅ disk.tar.gz copied locally"
echo ""

# Step 6: Upload to GCS
echo "☁️  Step 6: Uploading disk image to GCS..."
gsutil cp disk.tar.gz gs://${PROJECT}-images/disk.tar.gz
echo "✅ Disk image uploaded to GCS"
echo ""

# Step 7: Clean up old resources
echo "🧹 Step 7: Cleaning up old instances and images..."
gcloud compute instances delete paypal-auth-vm-${VERSION} \
    --zone=$ZONE --project=$PROJECT --quiet || true
gcloud compute images delete paypal-auth-custom-${VERSION} \
    --project=$PROJECT --quiet || true

# Clean up previous version
PREV_VERSION="v47"
gcloud compute instances delete paypal-auth-vm-${PREV_VERSION} \
    --zone=$ZONE --project=$PROJECT --quiet || true
gcloud compute images delete paypal-auth-custom-${PREV_VERSION} \
    --project=$PROJECT --quiet || true

echo "⏳ Waiting for GCP to clear caches..."
sleep 15
echo "✅ Cleanup complete"
echo ""

# Step 8: Create new image from GCS
echo "💿 Step 8: Creating new GCP image..."
gcloud compute images create paypal-auth-custom-${VERSION} \
    --project=$PROJECT \
    --source-uri=gs://${PROJECT}-images/disk.tar.gz \
    --guest-os-features=UEFI_COMPATIBLE,SEV_SNP_CAPABLE,GVNIC \
    --storage-location=europe-west4 --quiet
echo "✅ Image created: paypal-auth-custom-${VERSION}"
echo ""

# Step 9: Launch confidential VM
echo "🚀 Step 9: Launching Confidential VM..."
gcloud compute instances create paypal-auth-vm-${VERSION} \
    --project=$PROJECT --zone=$ZONE \
    --machine-type=n2d-highcpu-2 \
    --confidential-compute-type=SEV_SNP \
    --maintenance-policy=TERMINATE \
    --image=paypal-auth-custom-${VERSION} \
    --service-account=paypal-auth-sa@${PROJECT}.iam.gserviceaccount.com \
    --subnet=default --address=34.7.107.227 \
    --scopes=cloud-platform \
    --tags http-server,https-server \
    --shielded-secure-boot \
    --metadata=tee-env-SECRET_NAME=projects/${PROJECT}/secrets/PAYPAL_AUTH_CONFIG/versions/latest,tee-env-TLS_CACHE_SECRET=projects/${PROJECT}/secrets/PAYPAL_TLS_CACHE,tee-env-RUST_LOG=trace --quiet
echo "✅ VM launched: paypal-auth-vm-${VERSION}"
echo ""

echo "=== Deployment Complete! ==="
echo "VM: paypal-auth-vm-${VERSION}"
echo "IP: 34.7.107.227"
echo "Zone: $ZONE"
echo ""
echo "Monitor boot logs:"
echo "gcloud compute instances get-serial-port-output paypal-auth-vm-${VERSION} --zone=$ZONE --project=$PROJECT"
