// ZK circuit correctness gate (standalone now, called by the security
// harness later — see circom.md §8 / Test 38):
//   1. builds REAL witness inputs from a captured attestation report;
//   2. `snarkjs wtns calculate` over the compiled wasm;
//   3. `snarkjs wtns check` against the R1CS — this exercises EVERY
//      constraint, i.e. proves the in-circuit hand-rolled SHA-256 padding
//      reproduces the hardware-bound paypal_user_info_raw_hash, the byte-tail
//      zeroing holds, and the verified-bit window search math is consistent;
//   4. decrypts the escrow ciphertext OUTSIDE the circuit (circomlibjs
//      BabyJubjub + Poseidon) and asserts it round-trips to the exact
//      canonical identity JSON with verified bit = 1.
//
// Usage: node zk/test-witness.mjs [path/to/report.json]   (default: /tmp/claimed-report.json)
import { readFileSync, writeFileSync, rmSync } from 'fs';
import { createHash } from 'crypto';
import { execFileSync } from 'child_process';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const { buildBabyjub, buildPoseidon } = require('circomlibjs');

const repo = new URL('..', import.meta.url).pathname;
const reportPath = process.argv[2] || '/tmp/claimed-report.json';
const MAX = 300;
const N_CHUNKS = 10;

const report = JSON.parse(readFileSync(reportPath, 'utf8'));
const rep = report.attestation_report || report.report || report;
const p = rep.paypal_user_info;
if (!p) { console.error('FAIL: no paypal_user_info in', reportPath); process.exit(1); }

// Canonical identity JSON — byte-identical to the enclave's serde struct
// serialization and to verify.html's identityJson rebuild.
const D = JSON.stringify({
  user_id: p.user_id,
  sub: p.sub ?? null,
  verified_account: p.verified_account,
  payer_id: p.payer_id ?? null,
});
const H = createHash('sha256').update(D).digest();
const declared = String(rep.paypal_user_info_raw_hash || '').toLowerCase();
console.log('identity bytes:', D.length, '| sha256:', H.toString('hex').slice(0, 16),
  '| declared:', declared.slice(0, 16), '| match:', H.toString('hex') === declared);
if (H.toString('hex') !== declared) { console.error('FAIL: preimage does not match declared hash'); process.exit(1); }
if (D.length < 248 || D.length > MAX) { console.error('FAIL: identity outside circuit band [248,300]'); process.exit(1); }

// Deterministic test keys (the harness must reproduce the same values).
const babyJub = await buildBabyjub();
const poseidon = await buildPoseidon();
const ESCROW_SK = BigInt('75834567890123456789012345678901234567890123456789') % babyJub.subOrder;
const EPHEMERAL_R = BigInt('98765432109876543210987654321098765432109876543210') % (1n << 252n);
const escrowPub = babyJub.mulPointEscalar(babyJub.Base8, ESCROW_SK);
// circomlibjs may return point coords as field byte arrays → BigInt via F.
const toBig = (x) => typeof x === 'bigint' ? x : babyJub.F.toObject(x);
const escrowPubX = toBig(escrowPub[0]), escrowPubY = toBig(escrowPub[1]);

const raw = new Array(MAX).fill(0);
for (const [i, b] of [...Buffer.from(D, 'utf8')].entries()) raw[i] = b;

const hashBits = [];
for (const b of H) for (let t = 7; t >= 0; t--) hashBits.push((b >> t) & 1);

const inputs = {
  identity_hash_bits: hashBits,
  escrow_pubkey_x: escrowPubX.toString(),
  escrow_pubkey_y: escrowPubY.toString(),
  raw_json_bytes: raw,
  msg_len: D.length,
  ephemeral_private_key: EPHEMERAL_R.toString(),
};

const wIn = '/tmp/zk-test-inputs.json';
const wOut = '/tmp/zk-test.wtns';
const wJson = '/tmp/zk-test-witness.json';
writeFileSync(wIn, JSON.stringify(inputs));

const snarkjs = [process.execPath, [join_modules('snarkjs/build/cli.cjs')]];
function join_modules(...p) { return repo + 'node_modules/' + p.join('/'); }

try {
  execFileSync(snarkjs[0], [...snarkjs[1], 'wtns', 'calculate',
    repo + 'zk/build/identity_escrow_js/identity_escrow.wasm', wIn, wOut], { stdio: 'inherit' });
  console.log('✓ witness calculated');
  execFileSync(snarkjs[0], [...snarkjs[1], 'wtns', 'check',
    repo + 'zk/build/identity_escrow.r1cs', wOut], { stdio: 'inherit' });
  console.log('✓ ALL R1CS CONSTRAINTS SATISFIED (in-circuit SHA-256 == hardware-bound hash)');
} catch (e) {
  console.error('FAIL: constraint check', e.message.slice(0, 400));
  process.exit(1);
}

// Export outputs: [R.x, R.y, verified, C0..C9] then the 256 hash bits + pub.
execFileSync(snarkjs[0], [...snarkjs[1], 'wtns', 'export', 'json', wOut, wJson]);
const w = JSON.parse(readFileSync(wJson, 'utf8'));
// witness[0] is the constant-1 wire; outputs follow in declaration order:
// [R.x, R.y, verified, C0..C9], then the 256 public hash bits, then pubkeys.
if (Number(w[0]) !== 1) { console.error('FAIL: witness[0] is not the constant 1'); process.exit(1); }
const Rx = BigInt(w[1]), Ry = BigInt(w[2]);
const verified = Number(w[3]);
const chunks = w.slice(4, 4 + N_CHUNKS).map(BigInt);

if (verified !== 1) { console.error('FAIL: verified_account_bit =', verified); process.exit(1); }
console.log('✓ verified_account_bit = 1 (in-circuit pattern found)');

// public-input placement pin: the 256 hash bits sit right after the outputs.
const hb = w.slice(4 + N_CHUNKS, 4 + N_CHUNKS + 256).map(Number);
if (JSON.stringify(hb) !== JSON.stringify(hashBits)) {
  console.error('FAIL: public identity-hash bits not at witness slots 14..269'); process.exit(1);
}
console.log('✓ public signal order: [R.x, R.y, verified, C0..9, hash bits(256), escrow x, escrow y]');

// Outside-circuit decrypt: S = escrow_sk · R, keystream Poseidon(Sx, Sy+i+1).
const S = babyJub.mulPointEscalar([babyJub.F.e(Rx), babyJub.F.e(Ry)], ESCROW_SK);
const Sx = toBig(S[0]), Sy = toBig(S[1]);
let out = Buffer.alloc(0);
for (let c = 0; c < N_CHUNKS; c++) {
  const k = poseidon.F.toObject(poseidon([poseidon.F.e(Sx), poseidon.F.e(Sy + BigInt(c + 1))]));
  const chunk = ((chunks[c] - k) % babyJub.p + babyJub.p) % babyJub.p;
  const nb = 31;
  const bytes = [];
  let x = chunk;
  for (let b = 0; b < nb; b++) { bytes.push(Number(x & 0xffn)); x >>= 8n; }
  if (x !== 0n) { console.error('FAIL: chunk', c, 'not < 2^248 after decrypt'); process.exit(1); }
  out = Buffer.concat([out, Buffer.from(bytes)]);
}
const dec = out.subarray(0, D.length).toString('utf8');
if (dec !== D) {
  console.error('FAIL: decrypted identity mismatch\n got:', dec.slice(0, 200), '\nwant:', D.slice(0, 200));
  process.exit(1);
}
console.log('✓ escrow ciphertext decrypts outside the circuit to the exact identity JSON');
console.log('ZK WITNESS TEST: PASS');
rmSync(wIn, { force: true }); rmSync(wOut, { force: true }); rmSync(wJson, { force: true });
