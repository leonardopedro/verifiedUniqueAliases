#!/bin/bash
# TEST-ONLY fixture generator (zk/rsa-test) — two throwaway RSA-2048 keys
# that the security harness and the browser e2e use to exercise zk-rsa.html's
# PGP/X.509/raw parsing and escrow flow. Nothing here is a real identity.
# Regenerate: bash zk/rsa-test/gen-fixtures.sh  (needs openssl + node ≥ 18)
set -euo pipefail
cd "$(dirname "$0")"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out signer-key.pem 2>/dev/null
openssl req -new -x509 -key signer-key.pem -out signer-cert.pem -days 7300 \
    -subj "/CN=TEST-ONLY zk-rsa fixture/O=not a real identity"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out recipient-key.pem 2>/dev/null
chmod 600 signer-key.pem recipient-key.pem

node mk-pgp.mjs
echo "== fixtures regenerated (TEST-ONLY) =="
ls -la *.pem *.asc *.txt | awk '{print $5, $9}'
grep -m1 'BEGIN' *.pem