#!/usr/bin/env node
// TEST-ONLY fixture builder — builds OpenPGP v4 transferable key packets from
// the openssl keys in this directory, so the repo's PGP parsing (zk-rsa.html)
// has committed fixtures WITHOUT gpg being installed. The keys are throwaway
// test material (see README.md here) — never used for anything real.
//
// Format notes (RFC 4880): old-format packet header byte =
// 0x80 | (tag << 2) | length-type   (length-type 1 = two-octet length),
// fingerprint = SHA1(0x99 ‖ uint16be(len) ‖ public material), secret-key
// packet = public material ‖ 0x00 (s2k usage: cleartext) ‖ d,p,q,u MPIs.
// Outputs: signer-pub.asc signer-sec.asc recipient-pub.asc signer-raw.txt
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = dirname(fileURLToPath(import.meta.url));

// ---- minimal DER -----------------------------------------------------------
function derLen(buf, off) {
  const l = buf[off];
  if (l < 0x80) return { len: l, start: off + 1 };
  const n = l & 0x7f;
  let len = 0;
  for (let i = 0; i < n; i++) len = (len << 8) | buf[off + 1 + i];
  return { len, start: off + 1 + n };
}
function derSeq(buf, off) {
  if (buf[off] !== 0x30) throw new Error(`expected SEQUENCE at ${off}, got 0x${buf[off].toString(16)}`);
  const { len, start } = derLen(buf, off + 1);
  return { s: start, e: start + len, next: start + len };
}
function derOctet(buf, off) {
  if (buf[off] !== 0x04) throw new Error(`expected OCTET STRING at ${off}`);
  const { len, start } = derLen(buf, off + 1);
  return { s: start, e: start + len };
}
function derInt(buf, off) {
  if (buf[off] !== 0x02) throw new Error(`expected INTEGER at ${off}`);
  const { len, start } = derLen(buf, off + 1);
  let v = 0n;
  for (let i = 0; i < len; i++) v = (v << 8n) | BigInt(buf[start + i]);
  return { v, next: start + len };
}
function pemDer(text, wantLabel) {
  const m = new RegExp(`-----BEGIN ([A-Z0-9 ]+)-----([\\s\\S]*?)-----END \\1-----`).exec(text);
  if (!m) throw new Error('no PEM block');
  if (wantLabel && !m[1].includes(wantLabel)) throw new Error(`expected ${wantLabel}, got ${m[1]}`);
  return { label: m[1], der: Buffer.from(m[2].replace(/\s+/g, ''), 'base64') };
}
function rsaNumbers(pemText) {
  const { label, der } = pemDer(pemText);
  if (label.includes('PKCS8') || label === 'PRIVATE KEY') {
    // PKCS#8: SEQ { 0, AlgId, OCTET STRING { PKCS#1 } }
    const outer = derSeq(der, 0);
    let i = outer.s;
    i = derInt(der, i).next;                       // version
    i = derSeq(der, i).next;                       // AlgId
    const oct = derOctet(der, i);
    return rsaNumbers(`-----BEGIN RSA PRIVATE KEY-----\n${der.subarray(oct.s, oct.e).toString('base64')}\n-----END RSA PRIVATE KEY-----`);
  }
  // PKCS#1: SEQ { v, n, e, d, p, q, dp, dq, qi }
  const outer = derSeq(der, 0);
  let i = outer.s;
  i = derInt(der, i).next;
  const out = {};
  for (const k of ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi']) {
    const r = derInt(der, i);
    out[k] = r.v;
    i = r.next;
  }
  return out;
}

// ---- OpenPGP packing -------------------------------------------------------
const CREATED = 1793000000; // fixed → deterministic fixtures
function mpi(v) {
  const hex = v.toString(16);
  const bitLen = v === 0n ? 0 : v.toString(2).length;
  const bytes = Buffer.from(hex.length % 2 ? '0' + hex : hex, 'hex');
  const out = Buffer.alloc(2 + bytes.length);
  out.writeUInt16BE(bitLen, 0);
  bytes.copy(out, 2);
  return out;
}
function pubMaterial(n, e) {
  const t = Buffer.alloc(4);
  t.writeUInt32BE(CREATED, 0);
  return Buffer.concat([Buffer.from([4]), t, Buffer.from([1]), mpi(n), mpi(e)]);
}
function oldPacket(tag, body) {
  if (body.length > 0xffff) throw new Error('packet too big for 2-octet length');
  const h = Buffer.alloc(3);
  h[0] = 0x80 | (tag << 2) | 1; // length-type 1 → two-octet length
  h.writeUInt16BE(body.length, 1);
  return Buffer.concat([h, body]);
}
function armor(kind, bytes) {
  const b64 = bytes.toString('base64');
  const lines = b64.match(/.{1,64}/g).join('\n');
  let crc = 0xb704ce;
  for (const b of bytes) {
    crc ^= b << 16;
    for (let i = 0; i < 8; i++) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= 0x1864cfb;
    }
  }
  const crcB64 = Buffer.from([(crc >> 16) & 255, (crc >> 8) & 255, crc & 255]).toString('base64');
  return `-----BEGIN PGP ${kind} BLOCK-----\nVersion: TEST-ONLY fixture (zk/rsa-test)\n\n${lines}\n=${crcB64}\n-----END PGP ${kind} BLOCK-----\n`;
}
function pgpFingerprint(material) {
  const pre = Buffer.concat([Buffer.from([0x99]), Buffer.from([(material.length >> 8) & 255, material.length & 255]), material]);
  return createHash('sha1').update(pre).digest('hex').toUpperCase();
}

// ---- build -----------------------------------------------------------------
const signer = rsaNumbers(readFileSync(join(dir, 'signer-key.pem'), 'utf8'));
const recip = rsaNumbers(readFileSync(join(dir, 'recipient-key.pem'), 'utf8'));

function secBody(k) {
  const u = modInv(k.p, k.q); // p^-1 mod q (RFC 4880 §5.5.1.3)
  const secret = Buffer.concat([mpi(k.d), mpi(k.p), mpi(k.q), mpi(u)]);
  // RFC 4880 §5.5.3: with s2k usage 0 a two-octet checksum (sum mod 65536 of
  // ALL algorithm-specific octets, MPI prefix + data) follows the secret MPIs —
  // gpg REJECTS the packet without it ("read error: Invalid packet").
  let sum = 0;
  for (const b of secret) sum = (sum + b) & 0xffff;
  const csum = Buffer.alloc(2);
  csum.writeUInt16BE(sum);
  return Buffer.concat([pubMaterial(k.n, k.e), Buffer.from([0]), secret, csum]);
}
const modInv = (a, m) => { let [old_r, r] = [a % m, m]; let [old_s, s] = [1n, 0n]; while (r !== 0n) { const q = old_r / r; [old_r, r] = [r, old_r - q * r]; [old_s, s] = [s, old_s - q * s]; } return ((old_s % m) + m) % m; };

writeFileSync(join(dir, 'signer-pub.asc'), armor('PUBLIC KEY', oldPacket(6, pubMaterial(signer.n, signer.e))));
writeFileSync(join(dir, 'signer-sec.asc'), armor('SECRET KEY', oldPacket(5, secBody(signer))));
writeFileSync(join(dir, 'recipient-pub.asc'), armor('PUBLIC KEY', oldPacket(6, pubMaterial(recip.n, recip.e))));
writeFileSync(join(dir, 'signer-raw.txt'),
  `# TEST-ONLY raw RSA public key (same key as signer-key.pem)\nn=${signer.n.toString(16)}\ne=${signer.e}\n`);

const fp = pgpFingerprint(pubMaterial(signer.n, signer.e));
console.log(`signer    fp=${fp} bits=${signer.n.toString(2).length} d bits=${signer.d.toString(2).length}`);
console.log(`recipient fp=${pgpFingerprint(pubMaterial(recip.n, recip.e))} bits=${recip.n.toString(2).length}`);
console.log('wrote signer-pub.asc signer-sec.asc recipient-pub.asc signer-raw.txt');