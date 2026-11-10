#!/usr/bin/env node
// =============================================================================
// check-zk-pins.mjs - release gate for the ZK prover artifacts.
//
// Every release ships verify.html/zk.html, and zk.html refuses to prove unless
// the bytes it downloads hash to the constants baked into the page. Those
// constants live in the page; the bytes live in the repo and are served from
// raw.githubusercontent.com. Nothing at runtime compares the pin with the
// COMMITTED file — a rotated artifact (or a rotated pin) that forgot the other
// half would compile, pass every other check, and fail only in a browser, in
// front of a user trying to prove their identity.
//
// So: before every release, hash the committed wasm and the concatenation of
// the committed split zkey parts (the browser's fetch order), and fail if
// either disagrees with the page. Also asserts the artifacts are actually
// tracked by git — a gitignored wasm/zkey part would never reach raw, however
// correct the digest is.
//
// Why parts: identity_escrow_final.zkey is ~105 MB, above GitHub's 100 MB
// object limit, so it ships split; the pin covers the assembled key.
//
// Usage: node scripts/check-zk-pins.mjs [--quiet]
// Exit:  0 pins match, 1 mismatch/missing artifact
// =============================================================================
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const quiet = process.argv.includes('--quiet');

let failed = 0;
const check = (label, ok, detail = '') => {
  if (!quiet) console.log(`${ok ? '✅' : '❌'} ${label}${detail ? ` — ${detail}` : ''}`);
  if (!ok) failed += 1;
};

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const read = (rel) => readFileSync(join(repoRoot, rel));

let page;
try {
  page = read('zk.html').toString('utf8');
} catch (e) {
  console.error(`❌ cannot read zk.html: ${e.message}`);
  process.exit(1);
}

// The constants are plain `var NAME = '...';` declarations. Parse the whole
// page (a helper block may follow the declaration) but require exactly one
// definition of each, so a duplicate cannot shadow the one being checked.
const constant = (name) => {
  const all = [...page.matchAll(new RegExp(`var\\s+${name}\\s*=\\s*'([0-9a-f]{64})'`, 'g'))];
  return all.length === 1 ? all[0][1] : null;
};

const wasmPin = constant('ZK_WASM_SHA256');
const zkeyPin = constant('ZK_ZKEY_SHA256');

const partsMatch = page.match(/var\s+ZK_ZKEY_PARTS\s*=\s*\[([^\]]*)\]/);
const parts = partsMatch
  ? [...partsMatch[1].matchAll(/'([^']+)'/g)].map((m) => m[1])
  : [];

check('zk.html declares exactly one ZK_WASM_SHA256 pin', Boolean(wasmPin), wasmPin || 'missing/duplicated');
check('zk.html declares exactly one ZK_ZKEY_SHA256 pin', Boolean(zkeyPin), zkeyPin || 'missing/duplicated');
check('zk.html declares the split zkey part list',
  parts.length === 2 && parts.every((p) => /^[A-Za-z0-9_.-]+\.zkey\.part\d$/.test(p)),
  parts.join(' + ') || 'missing');

// The artifacts must ship the way the page expects: committed, not ignored.
// (`git check-ignore` exits 1 when nothing matched, which is what we want.)
const tracked = (rel) => spawnSync('git', ['ls-files', '--error-unmatch', rel],
  { cwd: repoRoot, stdio: 'ignore' }).status === 0;

let wasm = null;
try {
  wasm = read('zk/identity_escrow.wasm');
} catch (e) {
  check('zk/identity_escrow.wasm exists', false, e.code || e.message);
}
if (wasm) {
  const wasmSha = sha256(wasm);
  check('wasm pin matches zk/identity_escrow.wasm', wasmSha === wasmPin,
    wasmSha === wasmPin ? `${wasm.length} B ${wasmSha.slice(0, 16)}…`
      : `pin=${String(wasmPin).slice(0, 16)}… file=${wasmSha.slice(0, 16)}…`);
  check('zk/identity_escrow.wasm is tracked by git', tracked('zk/identity_escrow.wasm'));
}

if (parts.length) {
  const bufs = [];
  let missing = '';
  for (const p of parts) {
    try {
      const buf = read(join('zk', p));
      check(`part ${p} is committed and under GitHub's 100 MB limit`,
        buf.length > 0 && buf.length < 100 * 1024 * 1024, `${buf.length} B`);
      check(`part ${p} is tracked by git`, tracked(`zk/${p}`));
      bufs.push(buf);
    } catch (e) {
      missing = p;
      check(`part ${p} exists in the repo`, false, e.code || e.message);
      check(`part ${p} is tracked by git`, false, 'missing');
    }
  }
  if (!missing) {
    const assembled = sha256(Buffer.concat(bufs));
    check('zkey pin matches the ASSEMBLED split parts (browser fetch order)',
      assembled === zkeyPin,
      assembled === zkeyPin
        ? `${bufs.reduce((n, b) => n + b.length, 0)} B ${assembled.slice(0, 16)}…`
        : `pin=${String(zkeyPin).slice(0, 16)}… assembled=${assembled.slice(0, 16)}…`);
  }
}

// The page may only fetch prover bytes from raw — Pages is for the legal
// pages (v234 boundary), and a CDN or Pages base would make the pin cover
// bytes nobody reviewed.
const baseMatch = page.match(/var\s+ZK_BASE\s*=\s*'([^']+)'/);
check('ZK_BASE is raw.githubusercontent.com', Boolean(baseMatch)
  && /^https:\/\/raw\.githubusercontent\.com\//.test(baseMatch[1]), baseMatch ? baseMatch[1] : 'missing');

if (failed) {
  console.error(`\nRESULT: FAIL — ${failed} ZK pin check(s) failed; rotating the wasm/zkey requires updating BOTH the artifact and the pin in zk.html (circom.md §4)`);
  process.exit(1);
}
if (!quiet) console.log('\nRESULT: OK — zk.html pins match the committed prover artifacts');
