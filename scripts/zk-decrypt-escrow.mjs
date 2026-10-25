#!/usr/bin/env node
// zk-decrypt-escrow.mjs — open a `pav-circom-escrow/v1` credential with the
// escrow private scalar (circom.md §7). Pure circomlibjs: S = sk·R,
// k_i = Poseidon(S_x, S_y + i + 1), chunk_i = C_i − k_i (mod BN254 scalar
// field), little-endian 31-byte unpack, then SHA-256 must equal the
// credential's identity_hash_hex (fail closed — a tampered credential or the
// wrong scalar can never print an identity).
//
// Usage:
//   node scripts/zk-decrypt-escrow.mjs <credential.json> <scalar>
//       <scalar> = decimal or 0x-hex escrow private key
//   node scripts/zk-decrypt-escrow.mjs --example
//       prints the EXAMPLE keypair the verifier UI prefills.
//       ⚠️ THE EXAMPLE SCALAR IS PUBLIC — it provides ZERO secrecy. It exists
//       so the prove→verify→decrypt round trip can be tested end-to-end.
//       For a real recipient generate your own:
//         const bj = await buildBabyjub();
//         const sk = F.random();  pub = bj.mulPointEscalar(bj.Base8, sk)
import { readFileSync } from 'fs';
import { createHash } from 'crypto';
import { createRequire } from 'module';
import { pathToFileURL } from 'url';

const require2 = createRequire(import.meta.url);
const { buildBabyjub, buildPoseidon } = require2('circomlibjs');

// The deterministic EXAMPLE keypair (circom.md §7, harness Test 38 pins it).
export const EXAMPLE_ESCROW_SK = 75834567890123456789012345678901234567890123456789n;
export const EXAMPLE_ESCROW_X = 11827016509543949437935786885560076471997317080052058790160140017360929764098n;
export const EXAMPLE_ESCROW_Y = 16893061115786568867716241603005123395306176793643233966794415383620167560086n;

const N_CHUNKS = 10;
const CHUNK_BYTES = 31;

function parseScalar(s) {
    const t = String(s).trim();
    return t.startsWith('0x') || t.startsWith('0X') ? BigInt(t) : BigInt(t);
}

export async function decryptCredential(cred, scalar) {
    const bj = await buildBabyjub();
    const poseidon = await buildPoseidon();
    const ps = cred.public_signals || {};
    if (cred.schema !== 'pav-circom-escrow/v1') throw new Error('unsupported schema: ' + cred.schema);
    const R = ps.ephemeral_pubkey.map(BigInt);
    const chunks = ps.ciphertext.map(BigInt);
    if (chunks.length !== N_CHUNKS) throw new Error('expected ' + N_CHUNKS + ' ciphertext chunks, got ' + chunks.length);

    const S = bj.mulPointEscalar([bj.F.e(R[0]), bj.F.e(R[1])], scalar % bj.subOrder);
    const Sx = typeof S[0] === 'bigint' ? S[0] : bj.F.toObject(S[0]);
    const Sy = typeof S[1] === 'bigint' ? S[1] : bj.F.toObject(S[1]);

    const bytes = [];
    for (let c = 0; c < N_CHUNKS; c++) {
        const k = poseidon.F.toObject(poseidon([poseidon.F.e(Sx), poseidon.F.e(Sy + BigInt(c + 1))]));
        const chunk = ((chunks[c] - k) % bj.p + bj.p) % bj.p;
        let x = chunk;
        for (let b = 0; b < CHUNK_BYTES; b++) { bytes.push(Number(x & 0xffn)); x >>= 8n; }
        if (x !== 0n) throw new Error('chunk ' + c + ' ≥ 2^248 after subtraction — wrong scalar or tampered ciphertext');
    }
    // The plaintext is D ‖ zeros to 300 bytes; strip trailing NULs, then the
    // SHA-256 check decides truth.
    let end = bytes.length;
    while (end > 0 && bytes[end - 1] === 0) end--;
    const D = Buffer.from(bytes.slice(0, end));
    const h = createHash('sha256').update(D).digest('hex');
    if (h !== String(ps.identity_hash_hex || '').toLowerCase()) {
        throw new Error('decrypted SHA-256 (' + h.slice(0, 24) + '…) ≠ identity_hash_hex — wrong escrow scalar or tampered credential');
    }
    return { identityJson: D.toString('utf8'), sha256: h };
}

// CLI
const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
    try {
        const args = process.argv.slice(2);
        if (args[0] === '--example') {
            const bj = await buildBabyjub();
            const P = bj.mulPointEscalar(bj.Base8, EXAMPLE_ESCROW_SK);
            const t = (x) => (typeof x === 'bigint' ? x : bj.F.toObject(x));
            console.log('EXAMPLE escrow keypair (PUBLIC — zero secrecy, testing only):');
            console.log('  private scalar (dec): ' + EXAMPLE_ESCROW_SK);
            console.log('  public  x (dec):      ' + t(P[0]));
            console.log('  public  y (dec):      ' + t(P[1]));
            console.log('verify.html prefills these exact x/y values as the example recipient.');
            process.exit(0);
        }
        if (args.length < 2) {
            console.error('usage: zk-decrypt-escrow.mjs <credential.json> <scalar>  |  --example');
            process.exit(2);
        }
        const cred = JSON.parse(readFileSync(args[0], 'utf8'));
        const { identityJson, sha256 } = await decryptCredential(cred, parseScalar(args[1]));
        console.log('✓ identity recovered and hash-verified:');
        console.log(identityJson);
        console.log('sha256: ' + sha256);
    } catch (e) {
        console.error('DECRYPT FAILED: ' + e.message);
        process.exit(1);
    }
}
