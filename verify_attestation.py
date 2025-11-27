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
