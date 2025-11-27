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
│  │  - Private signing key             │ │
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
    --management-endpoint "https://your-vault-endpoint"

export KEY_ID="<output-key-id>"

# Create Secret for PAYPAL_SECRET
# First, base64 encode your PayPal client secret
echo -n "your-paypal-client-secret" | base64

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

## Part 4: Reproducible Initramfs with Dracut

### Option A: Build with Docker (Recommended)

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

### Option B: Manual Build (For Development)

### Step 4.1: Install Dracut

```bash
# On your build machine (Debian/Ubuntu)
sudo apt-get update
sudo apt-get install -y dracut dracut-core

# On Fedora/RHEL
sudo dnf install -y dracut
```

### Step 4.2: Create Dracut Module

Create the directory structure for the custom module:

```bash
mkdir -p dracut-module/99paypal-auth-vm
cd dracut-module/99paypal-auth-vm
```

### Step 4.3: module-setup.sh

See `dracut-module/99paypal-auth-vm/module-setup.sh`.

### Step 4.4: parse-paypal-auth.sh

```bash
#!/bin/sh
# parse-paypal-auth.sh - Early boot configuration

type getarg >/dev/null 2>&1 || . /lib/dracut-lib.sh

# Fetch metadata from OCI
fetch_metadata() {
    local key=$1
    curl -sf -H "Authorization: Bearer Oracle" \
        "http://169.254.169.254/opc/v1/instance/metadata/$key"
}

# Wait for network
while ! curl -sf http://169.254.169.254/ >/dev/null 2>&1; do
    echo "Waiting for metadata service..."
    sleep 1
done

# Export configuration
export PAYPAL_CLIENT_ID=$(fetch_metadata paypal_client_id)
export DOMAIN=$(fetch_metadata domain)
export SECRET_OCID=$(fetch_metadata secret_ocid)
export OCI_REGION=$(curl -sf http://169.254.169.254/opc/v2/instance/region)
export NOTIFICATION_TOPIC_ID=$(fetch_metadata notification_topic_id)
export SIGNING_KEY=$(fetch_metadata signing_key)

# Persist for later stages
{
    echo "PAYPAL_CLIENT_ID=$PAYPAL_CLIENT_ID"
    echo "DOMAIN=$DOMAIN"
    echo "SECRET_OCID=$SECRET_OCID"
    echo "OCI_REGION=$OCI_REGION"
    echo "NOTIFICATION_TOPIC_ID=$NOTIFICATION_TOPIC_ID"
    echo "SIGNING_KEY=$SIGNING_KEY"
} > /run/paypal-auth.env
```

### Step 4.6: start-app.sh

```bash
#!/bin/sh
# start-app.sh - Start the Rust application

. /run/paypal-auth.env

# Create runtime directories
mkdir -p /run/certs
mkdir -p /tmp/acme-challenge

# The Rust application will handle ACME certificate acquisition
# We just need to exec into it
echo "Starting PayPal Auth application..."

# Execute application (this replaces init)
exec /bin/paypal-auth-vm
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
import base64
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519

def verify_attestation(response_json, signature_b64, public_key_pem):
    """Verify the signed attestation response"""
    
    # Parse public key
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=None
    )
    
    # Decode signature
    signature = base64.b64decode(signature_b64)
    
    # Verify signature
    try:
        public_key.verify(signature, response_json.encode())
        print("✅ Signature valid!")
        return True
    except Exception as e:
        print(f"❌ Signature invalid: {e}")
        return False

def check_paypal_client_id(attestation, expected_client_id):
    """Verify PAYPAL_CLIENT_ID in attestation report"""
    report_data = attestation.get('report_data', '')
    
    if f"PAYPAL_CLIENT_ID={expected_client_id}" in report_data:
        print("✅ PAYPAL_CLIENT_ID matches in attestation!")
        return True
    else:
        print("❌ PAYPAL_CLIENT_ID mismatch in attestation!")
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
    signature = response['signature']  # From the signed_data in the response
    public_key = response['public_key']
    
    # Verify
    print("🔍 Verifying attestation...")
    verify_attestation(
        json.dumps(response, indent=2),
        signature,
        public_key
    )
    
    # Check PAYPAL_CLIENT_ID
    expected_client_id = input("Enter expected PAYPAL_CLIENT_ID: ")
    check_paypal_client_id(attestation, expected_client_id)
    
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