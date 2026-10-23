#!/usr/bin/env node
// check-manifest-parity.mjs — assert that the report's self-reported
// `disk_manifest` matches the ACTUAL file hashes of the deployed ESP.
//
// The manifest is self-reported by the enclave, so a deploy can drift (stale
// file, wrong disk swapped in, a file the enclave never re-measured) while the
// report keeps claiming whatever it measured at boot. This closes that gap at
// deploy time: extract the ESP from the disk image that was deployed and
// compare every manifest entry byte-for-byte.
//
// Usage:
//   node scripts/check-manifest-parity.mjs <report.json | https://host[/debug/envelope]> <disk.raw>
//
// Notes:
//   * `NvVars` is EXCLUDED by design — the firmware rewrites it on every boot
//     (the same reason verify.html's provenance row never looks it up), so the
//     deployed image's copy can never match a post-boot manifest.
//   * Exit code 0 = exact parity (every compared entry SAME). Any DIFF or
//     MISSING entry exits 1.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [reportSrc, diskPath] = process.argv.slice(2);
if (!reportSrc || !diskPath) {
  console.error('usage: node scripts/check-manifest-parity.mjs <report.json | https://host[/debug/envelope]> <disk.raw>');
  process.exit(2);
}

// ---- 1. load the report (URL or saved file) -------------------------------
let envelope;
if (/^https?:\/\//.test(reportSrc)) {
  const url = /\/debug\/envelope/.test(reportSrc) ? reportSrc
    : reportSrc.replace(/\/+$/, '') + '/debug/envelope';
  const res = await fetch(url);
  if (!res.ok) { console.error(`fetch ${url} -> HTTP ${res.status}`); process.exit(2); }
  envelope = await res.json();
} else {
  envelope = JSON.parse(readFileSync(reportSrc, 'utf8'));
}
const report = (typeof envelope.attestation_report === 'string')
  ? JSON.parse(envelope.attestation_report)
  : (envelope.attestation_report || envelope);
const manifest = report?.enclave_config?.boot_measurements?.disk_manifest;
if (!manifest || typeof manifest !== 'object') {
  console.error('report carries no disk_manifest — nothing to compare');
  process.exit(2);
}

// ---- 2. locate + extract the ESP partition (GPT) --------------------------
const disk = readFileSync(diskPath);
// GPT header signature is "EFI PART" at LBA 1 (two little-endian dwords).
if (disk.length < 4096
    || disk.readUInt32LE(512) !== 0x20494645 /* "EFI " */
    || disk.readUInt32LE(516) !== 0x54524150 /* "PART" */) {
  console.error(`${diskPath}: no GPT header at LBA 1 — not a GPT disk image`);
  process.exit(2);
}
const entriesLba = Number(disk.readBigUInt64LE(512 + 72));
const entry0 = entriesLba * 512;
const firstLba = Number(disk.readBigUInt64LE(entry0 + 32));
const lastLba = Number(disk.readBigUInt64LE(entry0 + 40));
if (!(firstLba > 0 && lastLba >= firstLba)) {
  console.error(`${diskPath}: GPT partition 1 has an implausible LBA range`);
  process.exit(2);
}

const tmp = mkdtempSync(join(tmpdir(), 'esp-parity-'));
const espFile = join(tmp, 'esp.img');
const mtoolsrc = join(tmp, 'mt.rc');
writeFileSync(espFile, disk.subarray(firstLba * 512, (lastLba + 1) * 512));
writeFileSync(mtoolsrc, `mtools_skip_check=1\ndrive x: file="${espFile}"\n`);

const mtype = (path) => execFileSync('mtype', [`x:/${path}`], {
  env: { ...process.env, MTOOLSRC: mtoolsrc },
  maxBuffer: 96 * 1024 * 1024,
});
const sha256Hex = (b) => createHash('sha256').update(b).digest('hex');

// ---- 3. compare every manifest entry -------------------------------------
// NvVars: firmware-rewritten every boot — can never match an image copy.
const SKIP = new Set(['NvVars']);
let diff = 0, same = 0, excluded = 0;
console.log(`report      : ${reportSrc}`);
console.log(`disk image  : ${diskPath} (ESP @ LBA ${firstLba}..${lastLba})`);
for (const [path, expected] of Object.entries(manifest).sort()) {
  if (SKIP.has(path)) {
    excluded++;
    console.log(`EXCLUDED ${path} — firmware rewrites it every boot (uncomparable by design)`);
    continue;
  }
  let actual;
  try {
    actual = sha256Hex(mtype(path));
  } catch {
    diff++;
    console.log(`MISSING  ${path} — in the report's manifest but NOT on the deployed ESP`);
    continue;
  }
  if (actual === String(expected).toLowerCase()) {
    same++;
    console.log(`SAME     ${path}`);
  } else {
    diff++;
    console.log(`DIFF     ${path}\n         report=${expected}\n         esp   =${actual}`);
  }
}
rmSync(tmp, { recursive: true, force: true });

console.log(`\n${same} same, ${diff} mismatched/missing, ${excluded} excluded`);
if (diff > 0) {
  console.log('RESULT: PARITY FAILURE — the report does not describe the deployed ESP');
  process.exit(1);
}
console.log('RESULT: PARITY OK — the report describes the deployed ESP exactly');
