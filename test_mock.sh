#!/bin/bash
set -e
export MOCK_HARDWARE=true
export PAYPAL_CLIENT_ID=dummy
export PAYPAL_CLIENT_SECRET=dummy
export DOMAIN=localhost
export RUST_LOG=info
export HTTP_PORT=8080
export HTTPS_PORT=8443

echo "🚀 Starting server in MOCK mode..."
./paypal-auth-vm-bin-local > server.log 2>&1 &
PID=$!

# Give it time to start and (fail to) get cert
sleep 10

echo "🔍 Checking HTTP endpoint (port 8080)..."
RESPONSE=$(curl -v http://localhost:8080/login 2>&1)

if echo "$RESPONSE" | grep -q "Location: https://www.sandbox.paypal.com/signin/authorize"; then
    echo "✅ SUCCESS: Redirected to PayPal Sandbox"
else
    echo "❌ FAILURE: Unexpected response"
    echo "$RESPONSE"
    kill $PID
    exit 1
fi

if echo "$RESPONSE" | grep -q "set-cookie: oauth_state="; then
    echo "✅ SUCCESS: State cookie found"
else
    echo "❌ FAILURE: State cookie missing"
    kill $PID
    exit 1
fi

if echo "$RESPONSE" | grep -q "state="; then
    echo "✅ SUCCESS: State parameter found in URL"
else
    echo "❌ FAILURE: State parameter missing from redirect URL"
    kill $PID
    exit 1
fi

echo "✅ ALL TESTS PASSED (MOCK MODE)"
kill $PID
