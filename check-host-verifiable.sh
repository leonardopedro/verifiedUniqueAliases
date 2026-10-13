#!/bin/bash
# =============================================================================
# check-host-verifiable.sh — is the physical host under this instance
# third-party verifiable via AMD KDS?
#
# OCI E5 hosts are MIXED (see AGENTS.md "OCI E5 PSP/KDS endorsement-key
# mismatch"): some PSPs sign SNP reports with the chip's KDS-published VCEK
# (verifiable — check-host-verifiable.sh prints KDS_SIG_OK), others with a
# vendor-loaded key that AMD KDS does not hold (unverifiable — the enclave
# then fails closed and verify.html shows "NO verifiable endorsement key").
# The enclave's boot-time v154 PSP probe logs the verdict to the serial
# console; this script drives the console (RSA key required — OCI console
# connections reject ed25519) and reports it.
#
# Usage:
#   bash check-host-verifiable.sh <instance-ocid>
#
# To roll a new instance onto a different host: terminate it and relaunch
# with deploy-oci.sh (each launch is a fresh host-allocation lottery; using
# a different --availability-domain spreads across the AD's host pools).
# =============================================================================
set -u
E="${1:-}"
[[ -z "$E" ]] && { echo "usage: $0 <instance-ocid>"; exit 2; }
command -v oci >/dev/null || { echo "oci CLI required"; exit 2; }

KEY=/tmp/console-rsa
if [[ ! -f "$KEY" ]]; then
    ssh-keygen -t rsa -b 2048 -N "" -f "$KEY" -q
    echo "generated console key $KEY.pub (RSA — OCI console requires it)"
fi

LOG=$(mktemp /tmp/hostcheck.XXXXXX.log)
CONN=$(oci compute instance-console-connection create --instance-id "$E" \
    --ssh-public-key-file "$KEY.pub" --query 'data.id' --raw-output 2>/dev/null)
[[ -z "$CONN" ]] && CONN=$(oci compute instance-console-connection list \
    --instance-id "$E" --query 'data[0].id' --raw-output 2>/dev/null)
[[ -z "$CONN" || "$CONN" == "None" ]] && { echo "NO_CONN"; exit 1; }
for _ in $(seq 1 30); do
    S=$(oci compute instance-console-connection get --instance-console-connection-id "$CONN" \
        --query 'data."lifecycle-state"' --raw-output 2>/dev/null)
    [[ "$S" == "ACTIVE" ]] && break
    sleep 3
done

# The SOFTRESET tears the console session down; loop reattach to catch the
# boot stream (the v154 probe logs a few seconds into enclave init).
( for _ in $(seq 1 40); do
    ssh -tt -i "$KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 \
        -o ProxyCommand="ssh -i $KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -W %h:%p -p 443 $CONN@instance-console.eu-frankfurt-1.oci.oraclecloud.com" \
        "$E" >> "$LOG" 2>&1
    sleep 2
done ) &
LOOP=$!
sleep 5
oci compute instance action --instance-id "$E" --action SOFTRESET --query 'data."lifecycle-state"' --raw-output >/dev/null 2>&1
sleep 95
kill $LOOP 2>/dev/null

grep -a "v154: PSP diag" "$LOG" | tr -d '\r'
if   grep -aq "KDS VCEK sig_ok=true"  "$LOG"; then echo "RESULT: KDS_SIG_OK   (reports from this host verify in verify.html)"
elif grep -aq "KDS VCEK sig_ok=false" "$LOG"; then echo "RESULT: KDS_SIG_BAD  (unverifiable host — relaunch for a different host)"
else echo "RESULT: NO_DATA (boot window missed — re-run)"; fi
rm -f "$LOG"
