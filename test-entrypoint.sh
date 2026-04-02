#!/bin/bash
# Simple test to see what's happening in Confidential Space
echo "=== START ===" > /dev/kmsg 2>/dev/null || true
echo "START" > /tmp/test.txt
echo "ARGS: $@" >> /tmp/test.txt
echo "ENV PAYPAL_CLIENT_ID=$PAYPAL_CLIENT_ID" >> /tmp/test.txt
echo "ENV DOMAIN=$DOMAIN" >> /tmp/test.txt
echo "ENV PATH=$PATH" >> /tmp/test.txt
cat /tmp/test.txt

# Test if the binary can even execute
/usr/local/bin/paypal-auth-vm 2>&1 | head -20
echo "EXIT: $?" >> /tmp/test.txt
cat /tmp/test.txt > /dev/kmsg 2>/dev/null || true
