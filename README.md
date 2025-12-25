This is a specification of this project, to be implemented in Oracle Cloudl: I want to build a simple website using Rust for the backend, which has a real "Login with Paypal" button. After Logging in Paypal, Paypal redirects the user to a Oracle's confidential VM which is always on. This confidential VM will be always on (as much as possible), it uses Rust, receives the Paypal's code, uses it to access the User's info available in the Paypal's userinfo API and it returns to the user a webpage with this User's info (and an attestation from Oracle that the VM image running is the one in a public Github registry) signed with a public key whose private key is a secret environment variable. PAYPAL_CLIENT_ID: Pass as OCI Instance Metadata (plain text). The Rust app will read this, include it in the Attestation Report's REPORT_DATA, and the user will verify it. PAYPAL_SECRET: Store in OCI Vault. The Rust app will fetch it at runtime using Instance Principals. It will not include this in the Attestation Report. I want the VM to store in memory a list of Paypal's IDs which already used the service, and to only execute if the current Paypal's ID is not on the list. I want to terminate TLS in my confidential VM and use the HTTP challenge to get the certificate from Let's encrypt. I want to add DDos protection (through a Load balancer, for example), but only for free and that doesn't interfere with the TLS connection. I want to have a reserved IP also. We will assign a Static Private IP to the VM at creation time. This guarantees that even if the VM reboots, it keeps the exact same internal IP address (e.g., 10.0.1.50). The Load Balancer will be configured to point to this static IP once, and it will never need to "adapt" because the target never changes. Automation: We will use a initramfs which runs the Rust app at startup and this Rust app performs the Let's Encrypt handshake. Please move the "Identity of the App" into the initrd or initramfs (which is measured by hardware), to prevent the "Swapped Disk" attack. This minimal VM should be obtained in a reproducible way, So that any user can verify that the hash corresponds to such VM.The VM should be the minimal possible, no ssh, no tty, no user logins, no busybox.  The Dockerfile and all files related to it (including main.rs and Cargo.toml) create the initramfs.

In the remaining of this file, I will provide the step by step instructions to implement this project.


# Oracle Cloud Confidential VM with PayPal OAuth - Complete Implementation Guide

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Part 1: OCI Infrastructure Setup](#part-1-oci-infrastructure-setup)
4. [Part 2: PayPal OAuth Setup](#part-2-paypal-oauth-setup)
5. [Part 3: Rust Application](#part-3-rust-application)
6. [Part 4: Initramfs Boot System](#part-4-initramfs-boot-system)
7. [Part 5: Let's Encrypt Integration](#part-5-lets-encrypt-integration)
8. [Part 6: Attestation Implementation](#part-6-attestation-implementation)
9. [Part 7: Monitoring & Notifications](#part-7-monitoring--notifications)
10. [Part 8: Deployment](#part-8-deployment)
11. [Part 9: Verification](#part-9-verification)

---

## Architecture Overview

```
┌─────────────┐
│   User      │
└─────┬───────┘
      │ HTTPS
      ▼
┌─────────────────────┐
│  OCI Load Balancer  │ ← Free tier, passthrough mode
│  (DDoS Protection)  │
└─────────┬───────────┘
          │
          ▼
┌──────────────────────────────────────────┐
│   Confidential VM (E4 Flex)              │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  Initramfs (Measured Boot)         │ │
│  │  ✅ Rust Binary (statically linked)│ │
│  │  ✅ All dependencies               │ │
│  │  ✅ Init script                    │ │
│  │  ✅ Shutdown handlers              │ │
│  └────────────────────────────────────┘ │
│           ↓ Everything runs from here    │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  RAM (tmpfs)                       │ │
│  │  - Used PayPal IDs (HashSet)       │ │
│  │  - PAYPAL_SECRET (from Vault)      │ │
│  │  - Active TLS certificate          │ │
│  │  - ACME challenge responses        │ │
│  └────────────────────────────────────┘ │
└──────────────────────────────────────────┘
          │
          ▼
┌──────────────────────┐
│   PayPal OAuth API   │
└──────────────────────┘
```

### Key Security Features
- **Confidential Computing**: AMD SEV-SNP with remote attestation
- **Measured Boot**: Entire application in initramfs (measured by hardware)
- **No SSH/TTY**: Completely sealed system, no root filesystem mounted
- **In-Memory Secrets**: Private keys never touch disk
- **RAM-Only Operation**: Certificates and keys are stored purely in RAM
- **Statically Linked**: Single Rust binary with all dependencies (musl libc)
- **Minimal Dependencies**: curl, openssl tools in initramfs

---

## Prerequisites

### Required Accounts
1. Oracle Cloud Infrastructure account (Free Tier eligible)
2. PayPal Developer account
3. Domain name with DNS access
4. Email account for notifications


---

## Part 1: OCI Infrastructure Setup

### Step 1.1: Create VCN (Virtual Cloud Network)

```bash
# Using OCI CLI (install from: https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm)

# Set variables
export COMPARTMENT_ID="ocid1.compartment.oc1..your-compartment-id"
export REGION="us-ashburn-1"

# Create VCN
oci network vcn create \
    --compartment-id $COMPARTMENT_ID \
    --display-name "paypal-vcn" \
    --cidr-block "10.0.0.0/16" \
    --dns-label "paypalvcn"

# Save the VCN OCID
export VCN_ID="<output-vcn-id>"
```

### Step 1.2: Create Subnet with Static Private IP

```bash
# Create Internet Gateway
oci network internet-gateway create \
    --compartment-id $COMPARTMENT_ID \
    --vcn-id $VCN_ID \
    --is-enabled true \
    --display-name "paypal-igw"

export IGW_ID="<output-igw-id>"

# Create Route Table
oci network route-table create \
    --compartment-id $COMPARTMENT_ID \
    --vcn-id $VCN_ID \
    --display-name "paypal-rt" \
    --route-rules '[
        {
            "destination": "0.0.0.0/0",
            "destinationType": "CIDR_BLOCK",
            "networkEntityId": "'$IGW_ID'"
        }
    ]'

export RT_ID="<output-rt-id>"

# Create Security List
oci network security-list create \
    --compartment-id $COMPARTMENT_ID \
    --vcn-id $VCN_ID \
    --display-name "paypal-seclist" \
    --egress-security-rules '[
        {
            "destination": "0.0.0.0/0",
            "protocol": "all",
            "isStateless": false
        }
    ]' \
    --ingress-security-rules '[
        {
            "source": "0.0.0.0/0",
            "protocol": "6",
            "isStateless": false,
            "tcpOptions": {
                "destinationPortRange": {
                    "min": 443,
                    "max": 443
                }
            }
        },
        {
            "source": "0.0.0.0/0",
            "protocol": "6",
            "isStateless": false,
            "tcpOptions": {
                "destinationPortRange": {
                    "min": 80,
                    "max": 80
                }
            }
        }
    ]'

export SECLIST_ID="<output-seclist-id>"

# Create Subnet
oci network subnet create \
    --compartment-id $COMPARTMENT_ID \
    --vcn-id $VCN_ID \
    --cidr-block "10.0.1.0/24" \
    --display-name "paypal-subnet" \
    --dns-label "paypalsubnet" \
    --route-table-id $RT_ID \
    --security-list-ids '["'$SECLIST_ID'"]'

export SUBNET_ID="<output-subnet-id>"
```

### Step 1.3: Create OCI Vault for Secrets

```bash
# Create Vault
oci kms management vault create \
    --compartment-id $COMPARTMENT_ID \
    --display-name "paypal-vault" \
    --vault-type "DEFAULT"

export VAULT_ID="<output-vault-id>"

# Create Master Encryption Key
oci kms management key create \
    --compartment-id $COMPARTMENT_ID \
    --display-name "paypal-master-key" \
    --key-shape '{"algorithm": "AES", "length": 32}' \
    --endpoint "https://your-vault-endpoint"

export KEY_ID="<output-key-id>"

# Create Secret for PAYPAL_SECRET
# First, base64 encode your PayPal client secret
# Beaware that the PAYPAL_SECRET must be converted from BASE64_URL to BASE64
#echo -n "your-paypal-client-secret" | base64

oci vault secret create-base64 \
    --compartment-id $COMPARTMENT_ID \
    --secret-name "paypal-client-secret" \
    --vault-id $VAULT_ID \
    --key-id $KEY_ID \
    --secret-content-content "base64-encoded-secret"


export SECRET_ID="<output-secret-id>"
```

### Step 1.4: Create Dynamic Group and Policy for Instance Principals

```bash
# Create Dynamic Group for the instance
oci iam dynamic-group create \
    --name "paypal-vm-dynamic-group" \
    --description "Dynamic group for PayPal confidential VM" \
    --matching-rule "Any {instance.compartment.id = '$COMPARTMENT_ID'}"

export DYNAMIC_GROUP_ID="<output-dg-id>"

# Create Policy
oci iam policy create \
    --compartment-id $COMPARTMENT_ID \
    --name "paypal-vm-policy" \
    --description "Allow VM to read secrets from vault" \
    --statements '[
        "Allow dynamic-group paypal-vm-dynamic-group to read secret-bundles in compartment id '$COMPARTMENT_ID'",
        "Allow dynamic-group paypal-vm-dynamic-group to read secrets in compartment id '$COMPARTMENT_ID'",
        "Allow dynamic-group paypal-vm-dynamic-group to use keys in compartment id '$COMPARTMENT_ID'"
    ]'
```

### Step 1.5: Reserve Public IP Address

```bash
# Create Reserved Public IP
oci network public-ip create \
    --compartment-id $COMPARTMENT_ID \
    --lifetime "RESERVED" \
    --display-name "paypal-reserved-ip"

export RESERVED_IP="<output-ip-address>"
export PUBLIC_IP_ID="<output-public-ip-id>"

# Update your DNS A record to point to this IP
# Example: paypal-auth.yourdomain.com -> $RESERVED_IP
```

### Step 1.6: Create Load Balancer (Free Tier - Flexible Shape)

```bash
# Create Load Balancer with minimum shape (10 Mbps) - Free tier eligible
oci lb load-balancer create \
    --compartment-id $COMPARTMENT_ID \
    --display-name "paypal-lb" \
    --shape-name "flexible" \
    --shape-details '{"minimumBandwidthInMbps": 10, "maximumBandwidthInMbps": 10}' \
    --subnet-ids '["'$SUBNET_ID'"]' \
    --is-private false

export LB_ID="<output-lb-id>"

# Wait for LB to provision
oci lb load-balancer get --load-balancer-id $LB_ID --query 'data."lifecycle-state"'

# The Load Balancer will be configured AFTER the VM is created
# We'll use TCP passthrough mode to preserve TLS end-to-end
```

---

## Part 2: PayPal OAuth Setup

### Step 2.1: Create PayPal App

1. Go to https://developer.paypal.com/dashboard/
2. Click "Apps & Credentials"
3. Click "Create App"
4. Fill in:
   - **App Name**: `Confidential VM Auth`
   - **App Type**: Web
5. Click "Create App"
6. Note your **Client ID** and **Client Secret**

### Step 2.2: Configure OAuth Settings

In the PayPal app settings:

1. **Return URL**: `https://paypal-auth.yourdomain.com/callback`
2. **App feature options**: 
   - ✅ Log In with PayPal
3. **Advanced settings**:
   - Scopes: `openid`, `profile`, `email`
4. Click "Save"

---

## Part 3: Rust Application (Single File)

All application logic is contained in a single `main.rs` file for maximum clarity and ease of auditing.

### Step 3.3: src/main.rs (Updated for initramfs-only design)

See `src/main.rs` for the full implementation.

---

---

## Part 4: Reproducible Initramfs Build Options

You can build the initramfs and qcow2 image using one of three methods:

### Option A: Native Build (Firebase Studio - Recommended)

If you're using [Firebase Studio](https://firebase.studio) (formerly Project IDX), you can build the image directly without Docker or QEMU:

**Prerequisites:**
- Workspace with `.idx/dev.nix` configured (included in this repo)
- Packages will be installed automatically from NixOS stable-24.05 channel

**Steps:**

1. **Check Environment** (first time only):
   ```bash
   ./check-native-env.sh
   ```

2. **Build Everything**:
   ```bash
   ./build-native.sh
   ```

   This single command will:
   - Build the Rust binary with reproducibility flags
   - Create the dracut initramfs image
- Package everything into a bootable qcow2 disk image
   - Generate SHA256 checksums and build manifest

**Output Files:**
- `initramfs-paypal-auth.img` - The initramfs image  
- `paypal-auth-vm.qcow2` - Bootable VM image (ready for OCI upload)
- `build-manifest.json` - Build metadata for reproducibility
- `*.sha256` - Checksums for verification

**Advantages:**
- ✅ **Fastest**: No VM or container overhead
- ✅ **Simplest**: Runs directly in your workspace
- ✅ **Same Output**: Produces identical images (verify with SHA256)
- ✅ **Integrated**: Part of your development workflow

**See Also:** [`BUILD_NATIVE.md`](BUILD_NATIVE.md) for detailed documentation.

---

### Option B: Docker Build

This method ensures a bit-for-bit reproducible build by using a fixed environment (Fedora Minimal + specific Rust version).

1.  **Build and Export Artifacts**:
    Run the following command to build the initramfs and extract it to your local directory:

    ```bash
    DOCKER_BUILDKIT=1 docker build --output . .
    ```

    This will create the following files in your current directory:
    - `initramfs-paypal-auth.img`: The bootable initramfs.
    - `build-manifest.json`: Metadata about the build (versions, hashes).
    - `initramfs-paypal-auth.img.sha256`: Checksum for verification.

### Reproducible Builds

This project implements **bit-for-bit reproducible builds**, ensuring that anyone can independently verify that the initramfs matches the published hash.

#### Reproducibility Guarantees

The build process is deterministic through:

1. **Fixed Build Environment**:
   - Pinned Docker base image with SHA256 digest
   - Specific Rust version (1.91.1)
   - All dependencies locked in `Cargo.lock`

2. **Deterministic Compilation**:
   - `RUSTFLAGS="-C target-cpu=generic -C codegen-units=1 -C strip=symbols"`
   - `SOURCE_DATE_EPOCH=1640995200` (fixed timestamp)
   - Path remapping to remove build directory from binary

3. **Binary Normalization**:
   - [`add-determinism`](https://crates.io/crates/add-determinism) removes non-deterministic metadata (build IDs, timestamps)
   - Applied to all binaries before packaging

4. **Dracut Reproducibility**:
   - `dracut --reproducible` flag respects `SOURCE_DATE_EPOCH`
   - Gzip compression (more deterministic than zstd/lz4)
   - Normalized file timestamps and permissions

#### Tools Used

- **add-det**: Removes non-deterministic metadata from ELF binaries
- **diffoscope**: Analyzes differences between builds (installed in Docker)
- **cargo-reproduce**: Optional tool for testing Rust binary reproducibility

#### Verifying Reproducibility

**Test Binary Reproducibility** (locally):
```bash
./test-binary-reproducibility.sh
```

This script builds the Rust binary twice and compares SHA256 hashes. Expected output:
```
✅ SUCCESS: Binaries are IDENTICAL! 🎉
```

**Test Full Initramfs Reproducibility**:
```bash
# Build twice and compare hashes
DOCKER_BUILDKIT=1 docker build --output /tmp/build1 .
DOCKER_BUILDKIT=1 docker build --output /tmp/build2 .

sha256sum /tmp/build1/img/initramfs-paypal-auth.img
sha256sum /tmp/build2/img/initramfs-paypal-auth.img
# Hashes should be identical
```

**Compare with Published Hash**:
```bash
# Download published initramfs and manifest
curl -O https://objectstorage.<region>.oraclecloud.com/.../initramfs-paypal-auth.img
curl -O https://objectstorage.<region>.oraclecloud.com/.../build-manifest.json

# Verify hash matches manifest
sha256sum initramfs-paypal-auth.img
cat build-manifest.json | jq -r '.initramfs_sha256'
```

#### Debugging Non-Reproducibility

If builds differ, use `diffoscope` to analyze:

```bash
DOCKER_BUILDKIT=1 docker build --output /tmp/build1 .
DOCKER_BUILDKIT=1 docker build --output /tmp/build2 .

diffoscope /tmp/build1/img/initramfs-paypal-auth.img \
           /tmp/build2/img/initramfs-paypal-auth.img
```

This will show exactly which bytes differ and why.


---

## Part 5: Deploy VM to Oracle Cloud

### Step 5.1: Upload Initramfs to Object Storage

First, create a bucket and upload your initramfs:

```bash
# Create Object Storage bucket
oci os bucket create \
    --compartment-id $COMPARTMENT_ID \
    --name paypal-vm-images

# Upload the initramfs
oci os object put \
    --bucket-name paypal-vm-images \
    --file initramfs-paypal-auth.img \
    --name initramfs-paypal-auth.img

# Get the object URL for later use
export INITRAMFS_URL=$(oci os object list \
    --bucket-name paypal-vm-images \
    --name initramfs-paypal-auth.img \
    --query 'data[0]."name"' \
    --raw-output)

echo "Initramfs uploaded to: https://objectstorage.${REGION}.oraclecloud.com/n/<namespace>/b/paypal-vm-images/o/initramfs-paypal-auth.img"
```

### Step 5.2: Create Custom Image from Initramfs

### Step 5.2: Create Bootable Disk Image

Since OCI requires a bootable disk image (not just an initramfs), we need to package our kernel and initramfs into a `.qcow2` image.

```bash
# 1. Create a minimal bootable disk image
# We'll use a helper script (create-boot-image.sh) to:
# - Create a disk image with a single partition
# - Install GRUB bootloader
# - Copy the kernel (vmlinuz) and our initramfs
# - Configure GRUB to boot our initramfs

./create-boot-image.sh \
    --kernel /boot/vmlinuz-$(uname -r) \
    --initramfs img/initramfs-paypal-auth.img \
    --output paypal-auth-vm.qcow2

# 2. Upload the disk image to Object Storage
oci os object put \
    --bucket-name paypal-vm-images \
    --file paypal-auth-vm.qcow2 \
    --name paypal-auth-vm.qcow2

# 3. Import as a Custom Image
export IMAGE_OCID=$(oci compute image import from-object \
    --compartment-id $COMPARTMENT_ID \
    --display-name "paypal-auth-cvm-v10" \
    --launch-mode NATIVE \
    --source-image-type QCOW2 \
    --bucket-name paypal-vm-images \
    --namespace $NAMESPACE \
    --name paypal-auth-vm.qcow2 \
    --query 'data.id' --raw-output)

echo "Custom Image created with OCID: $IMAGE_OCID"

# 4. Configure Image for Confidential Computing (REQUIRED)
# These steps are critical to prevent firmware crashes on Flex shapes

# Add Shape Compatibility for E4 and E5 Flex
oci compute image-shape-compatibility-entry add \
    --image-id $IMAGE_OCID \
    --shape-name "VM.Standard.E4.Flex"

oci compute image-shape-compatibility-entry add \
    --image-id $IMAGE_OCID \
    --shape-name "VM.Standard.E5.Flex"

# Enable AMD SEV Capability (Corrected JSON format)
# Ensure variables are set
echo "Using Compartment: $COMPARTMENT_ID"
echo "Using Image:       $IMAGE_OCID"

export GLOBAL_VERSION_NAME=$(oci compute global-image-capability-schema list --all --query 'data[0]."current-version-name"' --raw-output)
echo "Global Schema:     $GLOBAL_VERSION_NAME"

if [ -z "$GLOBAL_VERSION_NAME" ]; then
    echo "❌ Error: GLOBAL_VERSION_NAME is empty. Check your OCI CLI login and region."
    exit 1
fi

# Create a temporary JSON file for the schema data
cat > schema-data.json <<EOF
{
  "Compute.AMD_SecureEncryptedVirtualization": {
    "descriptorType": "boolean",
    "source": "IMAGE",
    "defaultValue": true
  },
  "Compute.Firmware": {
    "descriptorType": "enumstring",
    "source": "IMAGE",
    "defaultValue": "UEFI_64",
    "values": ["BIOS", "UEFI_64"]
  }
}
EOF

oci compute image-capability-schema create \
    --compartment-id "$COMPARTMENT_ID" \
    --image-id "$IMAGE_OCID" \
    --global-image-capability-schema-version-name "$GLOBAL_VERSION_NAME" \
    --schema-data file://schema-data.json

rm schema-data.json
```

### Step 5.3: Create Confidential VM Instance

Create the VM with custom metadata for configuration:

```bash
# Set your PayPal credentials and domain
export PAYPAL_CLIENT_ID="your-paypal-client-id"
export DOMAIN="auth.yourdomain.com"
export SECRET_OCID="$SECRET_ID"  # From Part 1.3
export NOTIFICATION_TOPIC_ID="$TOPIC_ID"  # From Part 7

# Create instance with custom metadata
export INSTANCE_ID=$(oci compute instance launch \
    --compartment-id $COMPARTMENT_ID \
    --availability-domain "$(oci iam availability-domain list --query 'data[0].name' --raw-output)" \
    --shape "VM.Standard.E5.Flex" \
    --shape-config '{"ocpus": 1, "memoryInGBs": 8}' \
    --subnet-id $SUBNET_ID \
    --assign-public-ip false \
    --display-name "paypal-auth-vm" \
    --metadata '{
        "paypal_client_id": "'"$PAYPAL_CLIENT_ID"'",
        "domain": "'"$DOMAIN"'",
        "secret_ocid": "'"$SECRET_OCID"'",
        "notification_topic_id": "'"$NOTIFICATION_TOPIC_ID"'"
    }' \
    --image-id $IMAGE_OCID \
    --boot-volume-size-in-gbs 50 \
    --platform-config '{"type": "AMD_VM", "isMemoryEncryptionEnabled": true}'\
    --query 'data.id' --raw-output)

export INSTANCE_ID="<output-instance-id>"
```

**Important Notes:**
- Replace `<CONFIDENTIAL_VM_IMAGE_ID>` with the OCID of an OCI image that supports AMD SEV-SNP confidential computing
- The instance must be on a shape that supports confidential computing (E4 shapes with AMD processors)
- Custom metadata is passed to the VM and accessible via the metadata service

### Step 5.4: Configure Static Private IP

```bash
# Get the VNIC ID
export VNIC_ID=$(oci compute instance list-vnics \
    --instance-id $INSTANCE_ID \
    --query 'data[0].id' \
    --raw-output)

# The private IP is already assigned during instance creation
# Verify it:
export PRIVATE_IP=$(oci network vnic get \
    --vnic-id $VNIC_ID \
    --query 'data."private-ip"')

```

### Step 5.5: Configure Load Balancer

Now configure the load balancer to point to your VM:

```bash
# Create backend set (TCP passthrough for TLS termination at VM)
oci lb backend-set create \
    --load-balancer-id $LB_ID \
    --name "paypal-backend" \
    --policy "ROUND_ROBIN" \
    --health-checker-protocol "TCP" \
    --health-checker-port 443 \
    --health-checker-interval-in-ms 30000 \
    --health-checker-timeout-in-ms 3000 \
    --health-checker-retries 3

# Add the VM as a backend
oci lb backend create \
    --load-balancer-id $LB_ID \
    --backend-set-name "paypal-backend" \
    --ip-address $PRIVATE_IP \
    --port 443 \
    --weight 1 \
    --backup false \
    --drain false \
    --offline false

# Create TCP listener (passthrough mode for TLS)
oci lb listener create \
    --load-balancer-id $LB_ID \
    --name "https-listener" \
    --default-backend-set-name "paypal-backend" \
    --protocol "TCP" \
    --port 443

# Also create HTTP listener for ACME challenge (Let's Encrypt)
oci lb listener create \
    --load-balancer-id $LB_ID \
    --name "http-listener" \
    --default-backend-set-name "paypal-backend" \
    --protocol "TCP" \
    --port 80
```

### Step 5.6: Associate Reserved Public IP

```bash
# Get the load balancer's IP address
export LB_IP=$(oci lb load-balancer get \
    --load-balancer-id $LB_ID \
    --query 'data."ip-addresses"[0]."ip-address"' \
    --raw-output)

echo "Load Balancer IP: $LB_IP"

# Update DNS A record to point to this IP
# Example using Cloudflare API (adjust for your DNS provider):
# curl -X PUT "https://api.cloudflare.com/client/v4/zones/<zone-id>/dns_records/<record-id>" \
#   -H "Authorization: Bearer <api-token>" \
#   -H "Content-Type: application/json" \
#   --data '{"type":"A","name":"auth.yourdomain.com","content":"'$LB_IP'","proxied":false}'
```

**Manual DNS Configuration:**
1. Go to your DNS provider (e.g., Cloudflare, Route53, etc.)
2. Create/Update an A record:
   - **Name**: `auth` (or your subdomain)
   - **Type**: `A`
   - **Value**: `$LB_IP` (from above)
   - **TTL**: 300 (5 minutes)

### Step 5.7: Verify VM Boot and Metadata Access

```bash
# Check instance status
oci compute instance get \
    --instance-id $INSTANCE_ID \
    --query 'data."lifecycle-state"'

# View console output (for debugging)
oci compute console-history get-content \
    --instance-console-history-id $(oci compute console-history capture --instance-id $INSTANCE_ID --query data.id --raw-output) \
    --file console.log

# Test metadata endpoint (from another VM in the same VCN)
# curl http://<PRIVATE_IP>/.well-known/acme-challenge/test
```

---

## Part 6: Attestation Implementation

### Step 6.1: Install snpguest Tool

```bash
# On the host machine, compile snpguest
git clone https://github.com/virtee/snpguest.git
cd snpguest
cargo build --release

# Copy binary to initramfs
cp target/release/snpguest ../paypal-auth-vm/initramfs/bin/
```

### Step 6.2: Verify Attestation (Client-side)

```python
#!/usr/bin/env python3
# verify_attestation.py - Client tool to verify attestation

import json
import hashlib

def verify_report_data(attestation, client_id, user_id):
    """
    Verify that the attestation REPORT_DATA contains the SHA256 hash of:
    PAYPAL_CLIENT_ID=<client_id>|PAYPAL_USER_ID=<user_id>
    """
    report_data_hex = attestation.get('report_data', '')
    
    # Reconstruct the expected data string
    expected_data = f"PAYPAL_CLIENT_ID={client_id}|PAYPAL_USER_ID={user_id}"
    
    # Calculate SHA256 hash
    expected_hash = hashlib.sha256(expected_data.encode()).hexdigest()
    
    print(f"ℹ️  Expected Data: {expected_data}")
    print(f"ℹ️  Expected Hash: {expected_hash}")
    print(f"ℹ️  Report Data:   {report_data_hex}")
    
    if expected_hash in report_data_hex:
        print("✅ REPORT_DATA matches expected hash!")
        print("   This confirms the attestation is bound to this specific PayPal User and Client.")
        return True
    else:
        print("❌ REPORT_DATA mismatch!")
        return False

def check_vm_measurement(attestation, expected_hash):
    """Verify VM image measurement"""
    measurement = attestation.get('measurement', '')
    
    if measurement == expected_hash:
        print("✅ VM measurement matches expected hash!")
        return True
    else:
        print("⚠️  VM measurement does not match")
        print(f"   Expected: {expected_hash}")
        print(f"   Got: {measurement}")
        return False

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: verify_attestation.py <response.json>")
        sys.exit(1)
    
    with open(sys.argv[1], 'r') as f:
        response = json.load(f)
    
    # Extract components
    attestation = json.loads(response['attestation'])
    userinfo = response['userinfo']
    
    user_id = userinfo['user_id']
    print(f"👤 Verifying attestation for User ID: {user_id}")
    
    # Check REPORT_DATA binding
    expected_client_id = input("Enter expected PAYPAL_CLIENT_ID: ")
    verify_report_data(attestation, expected_client_id, user_id)
    
    # Check VM measurement
    expected_hash = input("Enter expected VM image hash: ")
    check_vm_measurement(attestation, expected_hash)
```

---

## Part 7: Monitoring & Notifications

### Step 7.1: Setup OCI Monitoring

```bash
# Create notification topic
oci ons topic create \
    --compartment-id $COMPARTMENT_ID \
    --name "paypal-vm-alerts"

export TOPIC_ID="<output-topic-id>"

# Subscribe email
oci ons subscription create \
    --compartment-id $COMPARTMENT_ID \
    --topic-id $TOPIC_ID \
    --protocol "EMAIL" \
    --subscription-endpoint "your-email@example.com"
```


### Step 7.2: Deploy Traffic Monitor ("Traffic Cop")

We have implemented a "Traffic Cop" function to automatically shut down the instance if egress traffic exceeds 9.5 TB (just under the 10 TB free tier limit).

**1. Configure Environment:**
```bash
export COMPARTMENT_ID="<your-compartment-id>"
export INSTANCE_ID="$INSTANCE_ID" # From Step 5.3
export SUBNET_ID="$SUBNET_ID"     # From Step 1.2
```

**2. Deploy the Function:**
We have provided a script to automate the deployment:

```bash
./deploy-monitor.sh
```

**3. Schedule the Function:**
The script will output specific instructions to schedule the function using OCI Events or specific `fn` commands if the automated part needs manual intervention. Ensure the function allows you to create a trigger that runs every 5-15 minutes.

The function logic is located in `oci-monitor/func.py` and performs the following:
- Calculates start of the current month.
- Queries `oci_internet_gateway` metrics for `BytesToIgw`.
- Checks if usage > 9.5 TB.
- Stops the Compute Instance if the limit is exceeded.