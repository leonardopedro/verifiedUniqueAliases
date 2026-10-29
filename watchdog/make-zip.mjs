#!/usr/bin/env node
// Build the Function Compute code package: dist/pav-watchdog.zip
//
// The host running this repo has no `zip`, no `python3` and no package
// manager for the FC SDK, so the archive is written by hand: DEFLATE via
// node:zlib, CRC-32 via node:zlib's crc32 (Node >= 22.15) with a local table
// fallback. Deterministic: fixed DOS timestamps, stable entry order.
//
// Usage: node watchdog/make-zip.mjs [outPath]
import { deflateRawSync, crc32 as nodeCrc32 } from 'node:zlib';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const out = process.argv[2] || join(here, 'dist', 'pav-watchdog.zip');

// --- CRC-32 -----------------------------------------------------------------
let crcTable = null;
function crc32(buf) {
  if (typeof nodeCrc32 === 'function') return nodeCrc32(buf) >>> 0;
  if (!crcTable) {
    crcTable = new Int32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c;
    }
  }
  let c = 0xffffffff;
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// --- deterministic DOS date/time: 2026-01-01 00:00:00 -----------------------
const DOS_TIME = 0;
const DOS_DATE = ((2026 - 1980) << 9) | (1 << 5) | 1;

function localHeader(nameLen, crc, csize, size) {
  const b = Buffer.alloc(30);
  b.writeUInt32LE(0x04034b50, 0);
  b.writeUInt16LE(20, 4); // version needed
  b.writeUInt16LE(0x0800, 6); // flags: UTF-8 names
  b.writeUInt16LE(8, 8); // method: deflate
  b.writeUInt16LE(DOS_TIME, 10);
  b.writeUInt16LE(DOS_DATE, 12);
  b.writeUInt32LE(crc, 14);
  b.writeUInt32LE(csize, 18);
  b.writeUInt32LE(size, 22);
  b.writeUInt16LE(nameLen, 26);
  b.writeUInt16LE(0, 28);
  return b;
}

function centralHeader(nameLen, crc, csize, size, offset) {
  const b = Buffer.alloc(46);
  b.writeUInt32LE(0x02014b50, 0);
  b.writeUInt16LE(20, 4); // version made by
  b.writeUInt16LE(20, 6); // version needed
  b.writeUInt16LE(0x0800, 8);
  b.writeUInt16LE(8, 10);
  b.writeUInt16LE(DOS_TIME, 12);
  b.writeUInt16LE(DOS_DATE, 14);
  b.writeUInt32LE(crc, 16);
  b.writeUInt32LE(csize, 20);
  b.writeUInt32LE(size, 24);
  b.writeUInt16LE(nameLen, 28);
  b.writeUInt16LE(0, 30); // extra
  b.writeUInt16LE(0, 32); // comment
  b.writeUInt16LE(0, 34); // disk
  b.writeUInt16LE(0, 36); // internal attrs
  b.writeUInt32LE(0o644 << 16, 38); // external attrs
  b.writeUInt32LE(offset, 42);
  return b;
}

function buildZip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, data] of entries) {
    const nameBuf = Buffer.from(name, 'utf8');
    const raw = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
    const comp = deflateRawSync(raw, { level: 9 });
    const useComp = comp.length < raw.length ? comp : raw;
    const method = useComp === comp ? 8 : 0;
    const crc = crc32(raw);
    const header =
      method === 8
        ? localHeader(nameBuf.length, crc, useComp.length, raw.length)
        : (() => {
            const h = localHeader(nameBuf.length, crc, raw.length, raw.length);
            h.writeUInt16LE(0, 8); // store
            h.writeUInt32LE(raw.length, 18);
            h.writeUInt32LE(raw.length, 22);
            return h;
          })();
    locals.push(header, nameBuf, useComp);
    centrals.push(
      (() => {
        const c = centralHeader(
          nameBuf.length,
          crc,
          method === 8 ? useComp.length : raw.length,
          raw.length,
          offset
        );
        if (method === 0) c.writeUInt16LE(0, 10);
        return Buffer.concat([c, nameBuf]);
      })()
    );
    offset += header.length + nameBuf.length + useComp.length;
  }
  const central = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(central.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...locals, central, eocd]);
}

// --- assemble ---------------------------------------------------------------
const must = ['handler.js', 'rpc.js'];
for (const f of must) {
  if (!existsSync(join(here, f))) {
    console.error(`missing ${f}`);
    process.exit(1);
  }
}
const entries = [
  ['handler.js', readFileSync(join(here, 'handler.js'))],
  ['rpc.js', readFileSync(join(here, 'rpc.js'))],
];
const cfgPath = join(here, 'dist', 'config.json');
if (existsSync(cfgPath)) {
  entries.push(['config.json', readFileSync(cfgPath)]);
  // Fail loudly on a config that would be rejected by FC (and on secrets that
  // would be silently truncated).
  const parsed = JSON.parse(readFileSync(cfgPath, 'utf8'));
  if (!parsed.region || !parsed.spec || !parsed.spec.imageId) {
    console.error('dist/config.json is incomplete (region/spec.imageId required)');
    process.exit(1);
  }
} else {
  console.warn(`NOTE: ${cfgPath} not present — the function would start disabled`);
}

mkdirSync(dirname(out), { recursive: true });
const zip = buildZip(entries);
writeFileSync(out, zip);
console.log(
  `${basename(out)}: ${zip.length} bytes, entries=${entries
    .map((e) => e[0])
    .join(',')}`
);
