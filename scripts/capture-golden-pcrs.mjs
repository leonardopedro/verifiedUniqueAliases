#!/usr/bin/env node
// capture-golden-pcrs.mjs — audit VULN-04 remediation tooling.
//
// The signed TPM composite digest only proves a quote is SELF-consistent; a
// tampered kernel quotes its own PCRs and still passes. verify.html closes
// this by pinning the boot-chain PCRs (0/4/8/9) against GOLDEN_PCRS
// constants captured from a KNOWN-GOOD deployment — one whose artifacts all
// passed the GitHub provenance gate.
//
// Usage:
//   node scripts/capture-golden-pcrs.mjs <https://host>          # print
//   node scripts/capture-golden-pcrs.mjs <https://host> --update # patch verify.html
//
// Run --update ONLY against an instance you have just proven honest
// (provenance gate + a clean verify.html audit of its live report). The
// captured values then enter the audited git history — that commit IS the
// pin. Re-capture deliberately when the boot chain legitimately changes
// (kernel/shim/grub update).
import { readFileSync, writeFileSync } from 'fs';

const host = (process.argv[2] || '').replace(/\/$/, '');
const update = process.argv.includes('--update');
if (!/^https?:\/\//.test(host)) {
  console.error('usage: node scripts/capture-golden-pcrs.mjs <https://host> [--update]');
  process.exit(2);
}

const resp = await fetch(`${host}/debug/attestation`);
if (!resp.ok) {
  console.error(`GET ${host}/debug/attestation → HTTP ${resp.status}`);
  process.exit(1);
}
const body = await resp.json();

// Walk the report for the object carrying pcr_* keys (shape differs between
// the GCP TPM report and envelope wrappers).
function findPcrs(node, depth = 0) {
  if (!node || typeof node !== 'object' || depth > 6) return null;
  if (node.pcr_0 && node.pcr_9) return node;
  for (const v of Object.values(node)) {
    const hit = findPcrs(v, depth + 1);
    if (hit) return hit;
  }
  return null;
}
const pcrs = findPcrs(body);
if (!pcrs) {
  console.error('no pcr_* values in the report — this is a TPM-less (OCI/SEV-SNP) instance, or it has no vTPM evidence. Golden pins apply to the GCP/vTPM path only.');
  process.exit(1);
}
const hasTpm = !!(JSON.stringify(body).match(/ak_pub_pem/) && String(JSON.stringify(body)).length > 0);

const captured = { pcr_0: pcrs.pcr_0, pcr_4: pcrs.pcr_4, pcr_8: pcrs.pcr_8, pcr_9: pcrs.pcr_9 };
for (const [k, v] of Object.entries(captured)) {
  if (!v || !/^[0-9a-f]{64}$/i.test(v)) {
    console.error(`bad ${k}: ${v} — expected a sha256 hex digest`);
    process.exit(1);
  }
}
console.log('Captured boot-chain PCRs:');
for (const [k, v] of Object.entries(captured)) console.log(`  ${k} = ${v}`);
if (!hasTpm) console.log('⚠️  report JSON does not mention ak_pub_pem — double-check this report actually carries TPM evidence before pinning.');

if (!update) {
  console.log('\nDry run. Re-run with --update to patch verify.html GOLDEN_PCRS, then commit.');
  process.exit(0);
}

const path = new URL('../verify.html', import.meta.url);
const html = readFileSync(path, 'utf8');
const blockRe = /var GOLDEN_PCRS = \{[\s\S]*?\};/;
if (!blockRe.test(html)) {
  console.error('GOLDEN_PCRS block not found in verify.html');
  process.exit(1);
}
const next = html.replace(blockRe, `var GOLDEN_PCRS = {\n        pcr_0: '${captured.pcr_0}', // firmware — captured ${new Date().toISOString().slice(0, 10)} from a provenance-gated deployment\n        pcr_4: '${captured.pcr_4}', // bootloader\n        pcr_8: '${captured.pcr_8}', // kernel cmdline\n        pcr_9: '${captured.pcr_9}', // kernel + initramfs\n    };`);
writeFileSync(path, next);
console.log(`\n✅ verify.html GOLDEN_PCRS updated. Review the diff and COMMIT — the pin only\n   takes effect for auditors once it is in the reviewed git history.`);
