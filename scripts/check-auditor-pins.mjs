#!/usr/bin/env node
// =============================================================================
// check-auditor-pins.mjs - the boot-chain pins in verify.html must describe a
// real, self-consistent release before anything is built or deployed.
//
// Why this exists (v234 pass 5, 2026-11-10): shipping a new binary rotates
// RTMR2, and the auditor's silicon row is a HARD gate — a visitor with the page
// from that release would have failed the audit while the service looked
// perfectly healthy. Nothing compared the shipped page with the boot it claims
// to describe, so the release was caught only by reading the live quote by
// hand, after the swap.
//
// Two modes:
//   (default)  static: the page, its mirror and the README digest agree, and
//              every pin has the shape a real measurement has (a TDX RTMR is
//              48 bytes = 96 hex, MRTD is 48 bytes, RTMR3 is zero by design).
//              Deterministic, no network — this is what CI runs.
//   --live URL live: fetch /debug/envelope, recompute the measurements from the
//              TDX quote and require them to equal the pins; with --binary SHA
//              also require EXPECTED_ENCLAVE_SHA256 to be that binary. This is
//              the gate the rotation runs, and the only one that can prove the
//              page describes the box actually serving.
//
// Usage:
//   node scripts/check-auditor-pins.mjs
//   node scripts/check-auditor-pins.mjs --live https://login.airma.de --binary <sha256>
// Exit: 0 consistent, 1 disagree
// =============================================================================
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2);
const liveUrl = argv.includes('--live') ? argv[argv.indexOf('--live') + 1] : '';
const wantBinary = argv.includes('--binary') ? argv[argv.indexOf('--binary') + 1] : '';

let failed = 0;
const check = (label, ok, detail = '') => {
  console.log(`${ok ? '✅' : '❌'} ${label}${detail ? ` — ${detail}` : ''}`);
  if (!ok) failed += 1;
};

const read = (rel) => readFileSync(join(repoRoot, rel), 'utf8');

let page;
try {
  page = read('verify.html');
} catch (e) {
  console.error(`❌ cannot read verify.html: ${e.message}`);
  process.exit(1);
}

// A pin is `var NAME = '<hex>';` — one definition, exact length.
const pin = (name, hexLen) => {
  const all = [...page.matchAll(new RegExp(`var\\s+${name}\\s*=\\s*'([0-9a-f]+)'`, 'g'))];
  if (all.length !== 1) return { value: '', why: all.length ? `defined ${all.length}×` : 'missing' };
  const value = all[0][1];
  if (value.length !== hexLen) return { value, why: `${value.length} hex chars, expected ${hexLen}` };
  return { value, why: '' };
};

const pins = {
  MRTD: pin('EXPECTED_MRTD', 96),
  RTMR0: pin('EXPECTED_RTMR0', 96),
  RTMR1: pin('EXPECTED_RTMR1', 96),
  RTMR2: pin('EXPECTED_RTMR2', 96),
  RTMR3: pin('EXPECTED_RTMR3', 96),
  BINARY: pin('EXPECTED_ENCLAVE_SHA256', 64),
};
for (const [name, p] of Object.entries(pins)) {
  check(`EXPECTED_${name === 'BINARY' ? 'ENCLAVE_SHA256' : name} is a single, well-formed pin`,
    Boolean(p.value) && !p.why, p.why || `${p.value.slice(0, 16)}…`);
}

check('RTMR3 is zero (this platform extends no RTMR3)',
  pins.RTMR3.value === '0'.repeat(96), pins.RTMR3.value.slice(0, 16) + '…');
check('MRTD/RTMR0-2 are not placeholder zeros',
  [pins.MRTD, pins.RTMR0, pins.RTMR1, pins.RTMR2].every((p) => p.value && /[1-9a-f]/.test(p.value)));

// The ESP ships verify.html; index.html is the reader-facing mirror. A digest
// row that disagrees is how an auditor ends up checking a stale page.
const mirror = read('index.html');
check('verify.html and index.html are byte-identical', page === mirror,
  `${createHash('sha256').update(page).digest('hex').slice(0, 16)}… vs ${createHash('sha256').update(mirror).digest('hex').slice(0, 16)}…`);

const pageSha = createHash('sha256').update(page).digest('hex');
const pageSize = Buffer.byteLength(page);
const readme = read('README.md');
check('README carries this verify.html digest', readme.includes(pageSha), pageSha.slice(0, 16) + '…');
check('README carries this verify.html size', readme.includes(pageSize.toLocaleString('en-US')), `${pageSize} B`);

if (liveUrl) {
  const envelopeUrl = new URL('/debug/envelope', liveUrl).toString();
  let envelope = '';
  try {
    const res = await fetch(envelopeUrl, { signal: AbortSignal.timeout(20000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    envelope = await res.text();
  } catch (e) {
    console.error(`❌ could not fetch ${envelopeUrl}: ${e.message}`);
    process.exit(1);
  }

  const dir = mkdtempSync(join(tmpdir(), 'pav-pins-'));
  const envPath = join(dir, 'envelope.json');
  writeFileSync(envPath, envelope);
  let out = '';
  try {
    out = execFileSync('node', [join(repoRoot, 'scripts/calculate-golden-rtmr.mjs'), '--report', envPath],
      { encoding: 'utf8' });
  } catch (e) {
    console.error(`❌ could not read measurements from the live quote: ${e.message}`);
    process.exit(1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  const live = Object.fromEntries([...out.matchAll(/^(MRTD|RTMR[0-3])\s*=\s*([0-9a-f]+)$/gm)]
    .map((m) => [m[1], m[2]]));
  for (const name of ['MRTD', 'RTMR0', 'RTMR1', 'RTMR2', 'RTMR3']) {
    check(`live ${name} == shipped pin`, live[name] === pins[name].value,
      live[name] === pins[name].value ? `${String(live[name]).slice(0, 16)}…`
        : `live=${String(live[name]).slice(0, 16)}… pin=${pins[name].value.slice(0, 16)}…`);
  }

  let env = {};
  try { env = JSON.parse(envelope); } catch { /* reported below */ }
  const liveBin = env?.attestation_report?.enclave_config?.boot_measurements?.binary_sha256
    || env?.binary_sha256 || '';
  check('envelope carries a binary_sha256', Boolean(liveBin), liveBin.slice(0, 16) + '…');
  if (wantBinary) {
    check('running binary is the one just built', liveBin === wantBinary,
      `${liveBin.slice(0, 16)}… vs ${String(wantBinary).slice(0, 16)}…`);
    check('EXPECTED_ENCLAVE_SHA256 names the running binary', pins.BINARY.value === wantBinary,
      `${pins.BINARY.value.slice(0, 16)}… vs ${String(wantBinary).slice(0, 16)}…`);
  }
}

if (failed) {
  console.error(`\nRESULT: FAIL — ${failed} auditor pin check(s) failed. Rotate with `
    + '`node scripts/calculate-golden-rtmr.mjs --report <envelope> --update`, mirror verify.html to '
    + 'index.html, update the README digest, and redeploy (two-cycle procedure, HANDOVER §0.51).');
  process.exit(1);
}
console.log(`\nRESULT: OK — auditor pins are consistent${liveUrl ? ' with the live quote' : ''}`);
