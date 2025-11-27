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
    
    # Check if the report data matches (or contains) the hash
    # Note: REPORT_DATA is 64 bytes. If our hash is 32 bytes (64 hex chars), 
    # it should match the first 64 hex chars if the rest is zero-padded, 
    # or match exactly if the tool trims it.
    
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
