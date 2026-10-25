#!/bin/bash
# =============================================================================
# build-zk.sh — reproducible build of the identity-escrow proving artifacts
# (circom.md §4). Produces the three files committed to the repo:
#
#   zk/identity_escrow.wasm        witness calculator (circom 2.2.3 output)
#   zk/identity_escrow_final.zkey  Groth16 proving key (after local ceremony)
#   zk/identity_escrow_final.zkey.part{0,1}
#                                 the same key SPLIT for publishing (F5: GitHub
#                                 refuses git objects >100 MB — the browser
#                                 reassembles the parts and hashes them as one)
#   zk/identity_escrow_vkey.json   verification key (EMBEDDED in verify.html)
#
# Ceremony honesty (documented in circom.md §4): this is a SINGLE-PARTY local
# powers-of-tau + phase-2 contribution whose entropy comes from openssl rand
# at run time and is NEVER committed (committing it would let anyone forge
# credentials). What the toxic waste buys an attacker who kept it: forged
# CREDENTIALS — but a credential is only useful together with an Intel-signed
# TDX quote whose SEC-02 nonce binds the SAME identity hash, so forging still
# requires the enclave/hardware. Re-run with additional contributors for a
# multi-party ceremony: the snarkjs commands are appended to the transcript.
#
# Requirements: node_modules (snarkjs, circomlib), a circom 2.2.x binary
# (build-scripts/bin/circom — copied from nixpkgs#circom — or $CIRCOM/PATH),
# openssl, ~2 GB free disk (power-18 ptau), ~600 MB RAM.
#
# Usage: bash scripts/build-zk.sh
# =============================================================================
set -eo pipefail
cd "$(dirname "$0")/.."

CIRCOM_BIN="${CIRCOM:-}"
if [[ -z "$CIRCOM_BIN" ]]; then
    if [[ -x build-scripts/bin/circom ]]; then CIRCOM_BIN=build-scripts/bin/circom
    elif command -v circom >/dev/null 2>&1; then CIRCOM_BIN=circom
    else echo "❌ circom not found (set CIRCOM= or run nix build nixpkgs#circom)"; exit 1; fi
fi
SNARKJS_CLI="$PWD/node_modules/snarkjs/build/cli.cjs"
[[ -f $SNARKJS_CLI ]] || { echo "❌ snarkjs missing — npm install"; exit 1; }
run_snarkjs() { node "$SNARKJS_CLI" "$@"; }
$CIRCOM_BIN --version | grep -q "circom compiler 2.2" || echo "⚠️ unexpected circom version (pinned: 2.2.3)"

CONSTRAINTS_EXPECTED=200818
POWER=18   # 262,144 ≥ 200,818 constraints (power 17 would be too small)

mkdir -p zk/build zk/work

echo "== 1/4 circom compile (r1cs + witness wasm) =="
"$CIRCOM_BIN" zk/identity_escrow.circom --r1cs --wasm --sym -l node_modules -o zk/build
run_snarkjs r1cs info zk/build/identity_escrow.r1cs | tee zk/work/r1cs-info.txt
grep -q "# of Constraints: $CONSTRAINTS_EXPECTED" zk/work/r1cs-info.txt \
    || { echo "❌ constraint count drifted from $CONSTRAINTS_EXPECTED — review the circuit diff, then update CONSTRAINTS_EXPECTED deliberately"; exit 1; }

cd zk/work

echo "== 2/4 powers of tau (phase 1, local, power $POWER) =="
run_snarkjs powersoftau new bn128 $POWER pot18_0000.ptau
run_snarkjs powersoftau contribute pot18_0000.ptau pot18_0001.ptau \
    --name="pav local builder (1)" -e="$(openssl rand -hex 64)"
rm -f pot18_0000.ptau
run_snarkjs powersoftau prepare phase2 pot18_0001.ptau pot18_final.ptau
rm -f pot18_0001.ptau

echo "== 3/4 groth16 setup + phase 2 contribution + beacon =="
run_snarkjs groth16 setup ../build/identity_escrow.r1cs pot18_final.ptau identity_escrow_0000.zkey
run_snarkjs zkey contribute identity_escrow_0000.zkey identity_escrow_0001.zkey \
    --name="pav local builder (1)" -e="$(openssl rand -hex 64)"
rm -f identity_escrow_0000.zkey
# Beacon (public, reproducible) as the final permutation marker.
run_snarkjs zkey beacon identity_escrow_0001.zkey identity_escrow_final.zkey \
    7665726966795f61747465737465645f763138385f626561636f6e0a 10
rm -f identity_escrow_0001.zkey
run_snarkjs zkey verify ../build/identity_escrow.r1cs pot18_final.ptau identity_escrow_final.zkey

echo "== 4/4 export artifacts =="
run_snarkjs zkey export verificationkey identity_escrow_final.zkey ../identity_escrow_vkey.jsoncp identity_escrow_final.zkey ../identity_escrow_final.zkey
cp ../build/identity_escrow_js/identity_escrow.wasm ../identity_escrow.wasm
rm -f pot18_final.ptau          # regenerable; never committed (see header)
cd ../..

# F5 (deployability): publish the proving key as parts under GitHub's
# 100 MB per-object limit. verify.html's zkFetchZkey() fetches them IN THIS
# ORDER and pins the concatenation, so one sha256 covers every byte.
rm -f zk/identity_escrow_final.zkey.part*
split -b 60000000 -d -a 1 zk/identity_escrow_final.zkey zk/identity_escrow_final.zkey.part
for p in zk/identity_escrow_final.zkey.part?; do
    sz=$(wc -c < "$p")
    [[ $sz -lt 104857600 ]] || { echo "❌ $p is ≥100 MB — GitHub will refuse it"; exit 1; }
done

echo "== artifacts =="
sha256sum zk/identity_escrow.wasm zk/identity_escrow_final.zkey zk/identity_escrow_final.zkey.part? zk/identity_escrow_vkey.json
cat zk/identity_escrow_final.zkey.part? | sha256sum | grep -q "$(sha256sum zk/identity_escrow_final.zkey | cut -d' ' -f1)" \
    || { echo "❌ parts do not reassemble to the zkey"; exit 1; }
node zk/test-witness.mjs | tail -5
echo "✅ build-zk done"
