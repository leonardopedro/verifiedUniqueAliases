#!/usr/bin/env node
// =============================================================================
// calculate-golden-rtmr.mjs — offline golden RTMR/MRTD pin calculator
// (plan.md Phase 5 / independent audit v168).
//
// The EXPECTED_MRTD / EXPECTED_RTMR0..3 constants in verify.html are the HARD
// code-identity gates of the whole system: the auditor fails closed unless the
// Intel-signed TD Quote carries exactly these bytes. This tool produces those
// constants from PRIMARY evidence instead of hand-copied strings:
//
//   * --ccel <file|->      replay a captured TCG crypto-agile CC Event Log
//                          (ACPI CCEL log area) onto RTMR0..3, byte-compatible
//                          with src/intel_tdx.rs::replay_ccel, and print a
//                          per-event breakdown showing WHICH artifact extends
//                          WHICH register (coverage proof for the audit).
//   * --report <file|->    extract MRTD + RTMR0..3 straight out of the Intel-
//                          signed quote inside a live attestation report
//                          (GET https://<enclave>/debug/envelope) — byte-
//                          compatible with src/intel_tdx.rs::quote_measurements.
//   * --ccel X --report Y  cross-check: the log replay must reproduce the
//                          quoted RTMRs EXACTLY (the in-guest ccel_replay_vs_
//                          quote gate, performed offline).
//   * --update             rewrite the pins in verify.html (rotating pins is a
//                          DELIBERATE, reviewed action — same discipline as
//                          scripts/capture-golden-pcrs.mjs on the GCP path).
//   * --json               machine-readable output.
//   * --selftest           verify the replay parser against the shared golden
//                          vector (identical bytes asserted by
//                          security_tests::ccel_replay_selftest_v168 in Rust —
//                          all three implementations must agree).
//
// Rotation procedure (boot-chain change ⇒ pins rotate, deliberately):
//   1. boot a KNOWN-GOOD instance of the new image (provenance gate green);
//   2. curl -s https://<enclave>/debug/envelope > report.json
//   3. node scripts/calculate-golden-rtmr.mjs --report report.json --update
//   4. commit verify.html in the reviewed commit that changed the boot chain.
// =============================================================================
import { readFileSync, writeFileSync } from 'fs';
import { createHash } from 'crypto';

const sha384 = (b) => createHash('sha384').update(b).digest();

// -----------------------------------------------------------------------------
// TCG crypto-agile event-log replay. MIRRORS src/intel_tdx.rs::replay_ccel
// byte-for-byte (initial state SHA-384 over 1024 zero bytes; extend =
// SHA-384(prev || event SHA-384 digest); EV_NO_ACTION / specialty PCRs never
// extend; the "Spec ID Event03" header event harvests the digest-size table).
// Keep the two implementations in lockstep — security_tests and --selftest pin
// both to the same golden vector.
// -----------------------------------------------------------------------------
function tcgDigestSize(alg) {
  switch (alg) {
    case 0x0004: return 20;  // SHA-1
    case 0x000B: return 32;  // SHA-256
    case 0x000C: return 48;  // SHA-384
    case 0x000D: return 64;  // SHA-512
    case 0x0012: return 32;  // SHA3-256
    case 0x0013: return 48;  // SHA3-384
    case 0x0014: return 64;  // SHA3-512
    default: return null;
  }
}

function replayCcel(log, initRtmr = null) {
  const rd32 = (o) => {
    if (o + 4 > log.length) throw new Error(`ccel: truncated u32 @${o} (log ${log.length} bytes)`);
    return log.readUInt32LE(o);
  };
  // Initial RTMR state: ZERO — "The RTMR array is initialized to zero on
  // build" (Intel TDX Module Base Arch spec). Mirror of replay_ccel() in
  // src/intel_tdx.rs — keep the two byte-identical in behavior.
  const init0 = initRtmr ? Buffer.from(initRtmr) : Buffer.alloc(48);
  const rtmr = [Buffer.from(init0), Buffer.from(init0), Buffer.from(init0), Buffer.from(init0)];
  const algSizes = [];
  const events = [];
  let off = 0;
  let evCount = 0;

  // TCG PC Client PFP: the FIRST event of a crypto-agile log is laid out in
  // the LEGACY TCG_PCR_EVENT fixed format (pcr u32, type u32, digest[20],
  // eventSize u32, event) — normally the EV_NO_ACTION "Spec ID Event03"
  // header. Parsing it as an EVENT2 misreads the SHA-1 digest field as
  // digestCount/eventSize and drifts the stream (live-verified against
  // Alibaba's real CCEL log, 2026-10-22: "implausible digestCount
  // 4294967295 @1626").
  // Legacy layout: pcr u32 @0 | type u32 @4 | digest[20] @8..28 |
  // eventSize u32 @28 | event @32.
  if (log.length >= 32) {
    const lType = log.readUInt32LE(4);
    const lSize = log.readUInt32LE(28);
    if (32 + lSize <= log.length) {
      const ev = log.subarray(32, 32 + lSize);
      if (lType === 0x3 && ev.length >= 28 && ev.subarray(0, 16).toString('latin1') === 'Spec ID Event03\u0000') {
        const n = ev.readUInt32LE(24);
        for (let i = 0; i < Math.min(n, 8); i++) {
          const base = 28 + i * 4;
          if (base + 4 <= ev.length) algSizes.push([ev.readUInt16LE(base), ev.readUInt16LE(base + 2)]);
        }
        off = 32 + lSize; // EV_NO_ACTION header never extends
        events.push({ pcrIndex: '0x0', eventType: '0x3', digestCount: 0, digestSha384: null,
          eventSize: lSize, action: 'legacy spec-id header (alg table, not extended)', dataPreview: 'Spec ID Event03' });
        evCount++;
      }
      // else: no legacy spec-id header → parse the whole log as EVENT2
    }
  }

  while (off + 12 <= log.length) {
    const pcrIndex = rd32(off);
    const eventType = rd32(off + 4);
    const digestCount = rd32(off + 8);
    if (digestCount > 16) {
      // Fixed-size firmware log areas are commonly padded with 0x00 or 0xFF
      // after the last real event (live Alibaba CCEL: 1626 real bytes in a
      // 65536-byte area). A tail of 0x00/0xFF bytes in any mix is padding —
      // a clean end-of-log (mirror of replay_ccel in src/intel_tdx.rs).
      const rest = log.subarray(off);
      if (rest.every((b) => b === 0x00 || b === 0xff)) break;
      throw new Error(`ccel: implausible digestCount ${digestCount} @${off}`);
    }
    let pos = off + 12;
    let sha384Digest = null;
    for (let i = 0; i < digestCount; i++) {
      if (pos + 2 > log.length) throw new Error(`ccel: truncated algId @${pos}`);
      const alg = log.readUInt16LE(pos);
      pos += 2;
      let size = algSizes.find(([a]) => a === alg)?.[1] ?? tcgDigestSize(alg);
      if (size === null || size === undefined) throw new Error(`ccel: unknown digest alg 0x${alg.toString(16)} @${pos - 2}`);
      if (pos + size > log.length) throw new Error(`ccel: truncated digest @${pos} (need ${size})`);
      if (alg === 0x000C && size === 48 && sha384Digest === null) sha384Digest = Buffer.from(log.subarray(pos, pos + 48));
      pos += size;
    }
    if (pos + 4 > log.length) throw new Error(`ccel: truncated eventSize @${pos}`);
    const eventSize = log.readUInt32LE(pos);
    pos += 4;
    if (digestCount === 0 && eventSize === 0 && log.subarray(off).every((b) => b === 0x00 || b === 0xff)) break; // trailing 0x00/0xFF padding
    if (pos + eventSize > log.length) throw new Error(`ccel: event data overruns log @${pos} (size ${eventSize})`);
    const ev = log.subarray(pos, pos + eventSize);
    let action = 'skipped';
    if (eventType === 0x00000003 && algSizes.length === 0 &&
        ev.length >= 28 && ev.subarray(0, 16).toString('latin1') === 'Spec ID Event03\u0000') {
      // Spec ID Event03 header written as an EVENT2 (some firmware; the
      // legacy fixed-layout form is handled before the loop): harvest the
      // declared digest-size table. EV_NO_ACTION never extends — and
      // eventType 1 is EV_POST_CODE, a REAL extending event, so only type 3
      // with the spec-id body counts as a header.
      const n = ev.readUInt32LE(24);
      for (let i = 0; i < Math.min(n, 8); i++) {
        const base = 28 + i * 4;
        if (base + 4 <= ev.length) algSizes.push([ev.readUInt16LE(base), ev.readUInt16LE(base + 2)]);
      }
      action = 'spec-id header (alg table, not extended)';
    } else if (eventType !== 0x00000003 && pcrIndex >= 1 && pcrIndex <= 4 && !(pcrIndex >= 0x80000000)) {
      // TCG/UEFI "CC Measurement" log convention — live-verified against
      // Alibaba's real CCEL log AND the Intel-signed quote (2026-10-23): the
      // event's register field is the MrIndex — 0 = MRTD (never an RTMR),
      // 1..4 = RTMR0..3. The earlier "0..3 == RTMR0..3" assumption replayed
      // every register one bank off and tripped the in-guest CCEL-vs-quote
      // mismatch gate on every boot.
      const reg = pcrIndex - 1;
      if (sha384Digest) {
        rtmr[reg] = sha384(Buffer.concat([rtmr[reg], sha384Digest]));
        action = `EXTENDED RTMR${reg} (MrIndex ${pcrIndex})`;
      } else {
        action = `no SHA-384 digest in event — RTMR${reg} NOT extended`;
      }
    } else if (eventType !== 0x00000003 && pcrIndex === 0) {
      action = 'MRTD event (MrIndex 0 — not an RTMR, never replayed)';
    } else if (eventType === 0x00000003) {
      action = 'EV_NO_ACTION (never extends)';
    } else {
      action = 'specialty PCR (never extends)';
    }
    events.push({ pcrIndex: `0x${pcrIndex.toString(16)}`, eventType: `0x${eventType.toString(16)}`,
      digestCount, digestSha384: sha384Digest ? sha384Digest.toString('hex') : null,
      eventSize, action, dataPreview: ev.subarray(0, 24).toString('latin1').replace(/[^\x20-\x7e]/g, '.') });
    off = pos + eventSize;
    evCount++;
  }
  if (evCount === 0) throw new Error('ccel: no events parsed (empty or non-TCG log)');
  return { rtmr, events };
}

// -----------------------------------------------------------------------------
// Quote measurement extraction — MIRRORS src/intel_tdx.rs::quote_measurements.
// v4: body @48; v5: 6-byte preamble (body_type u16 + body_size u32) → body @54.
// Body: mr_td (MRTD) 136..184, RTMR0..3 328..520 (48 B each).
// -----------------------------------------------------------------------------
function quoteMeasurements(quote) {
  if (quote.length < 48) throw new Error('quote truncated (<48 B header)');
  const version = quote.readUInt16LE(0);
  const teeType = quote.readUInt32LE(4);
  if (teeType !== 0x81) throw new Error(`tee_type 0x${teeType.toString(16)} is not TDX`);
  const bodyOff = version === 4 ? 48 : version === 5 ? 54 : (() => { throw new Error(`unsupported quote version ${version}`); })();
  if (quote.length < bodyOff + 584) throw new Error(`quote truncated before TDREPORT body (${quote.length} bytes)`);
  const body = quote.subarray(bodyOff, bodyOff + 584);
  return {
    version,
    mrtd: Buffer.from(body.subarray(136, 184)),
    rtmr: [0, 1, 2, 3].map((i) => Buffer.from(body.subarray(328 + i * 48, 376 + i * 48))),
  };
}

// -----------------------------------------------------------------------------
// Input handling: accept raw binary, hex, or base64 (auto-detected).
// -----------------------------------------------------------------------------
function readBytes(path) {
  const buf = path === '-' ? readFileSync(0) : readFileSync(path);
  const t = buf.toString('utf8').trim();
  if (/^[0-9a-fA-F\s]+$/.test(t) && t.replace(/\s/g, '').length % 2 === 0) {
    return Buffer.from(t.replace(/\s/g, ''), 'hex');
  }
  if (/^[A-Za-z0-9+/=\s]+$/.test(t) && t.replace(/\s/g, '').length % 4 === 0 && t.length > 0) {
    return Buffer.from(t.replace(/\s/g, ''), 'base64');
  }
  return buf;
}

// decode a base64/hex quote string straight to bytes
function b64OrHex(s) {
  const t = s.trim();
  if (/^[0-9a-fA-F]+$/.test(t) && t.length % 2 === 0) return Buffer.from(t, 'hex');
  return Buffer.from(t.replace(/\s/g, ''), 'base64');
}

// -----------------------------------------------------------------------------
// verify.html pin rewriting (--update)
// -----------------------------------------------------------------------------
function updateVerifyHtml(mrtdHex, rtmrHexes) {
  const path = new URL('../verify.html', import.meta.url).pathname;
  let src = readFileSync(path, 'utf8');
  const changes = [];
  const setPin = (name, value) => {
    if (!value) return;
    const re = new RegExp(`(var ${name} = ')[0-9a-f]*(';)`);
    if (!re.test(src)) throw new Error(`verify.html: pin ${name} not found — refusing to update`);
    const old = src.match(re)[0];
    src = src.replace(re, `$1${value}$2`);
    changes.push(`${name}: ${old.slice(old.indexOf("'") + 1, -2) || '(empty)'} → ${value}`);
  };
  setPin('EXPECTED_MRTD', mrtdHex);
  if (rtmrHexes) rtmrHexes.forEach((h, i) => setPin(`EXPECTED_RTMR${i}`, h));
  writeFileSync(path, src);
  return changes;
}

// -----------------------------------------------------------------------------
// CLI
// -----------------------------------------------------------------------------
const args = process.argv.slice(2);
const flag = (f) => args.includes(f);
const opt = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : null; };

if (flag('--selftest')) {
  // The shared golden vector (identical bytes asserted by
  // security_tests::ccel_replay_selftest_v168 in src/main.rs). Spec ID
  // Event03 header + multi-digest event + EV_NO_ACTION + one extension per
  // MrIndex 0..3 (0 = MRTD, not replayed; 1..3 extend RTMR0..2 — the real
  // TCG/UEFI CC-log convention, live-verified 2026-10-23).
  // Any parser drift in EITHER implementation fails one of the two suites.
  // The header is the LEGACY TCG_PCR_EVENT fixed layout the spec mandates
  // for the first event of a crypto-agile log (regenerate with
  // /tmp/gen-vectors.mjs).
  const logHex =
    '0000000003000000000000000000000000000000000000000000000025000000' +
    '53706563204944204576656e743033000000000000000000020000000b002000' +
    '0c003000000000000005000000020000000b0033d30b8c9c1d527af7444096d2' +
    'b224043288d17f4cf5dbe0ee08e5bf298cd6240c0091ade0d63b78f8cb3163a5' +
    'f7d379803d28736d8750a81a426e5de3e00881102f3272b2f9043d30a096b6f3' +
    'c5329921010c0000006576656e742d412d646174610100000003000000010000' +
    '000c009600d212482f5fed7c434809b63b80169bea1512b2a1489c5cc4285fdd' +
    '778df105b240fbb073c16dda5f85a5b16f29910700000069676e6f7265640100' +
    '000004000000010000000c0079109388ed26aa95abbba22ba7e6ec7e7b1bb6a9' +
    '5d1c0fe5fee15bfb79d308193b795f188399d1686d5d7b50c34965a80c000000' +
    '6576656e742d422d646174610200000006000000010000000c00ff337190a80a' +
    '44f709bbb0bb74ddd96c78bdc55cc05db46d2ab151cc1e413737fcf0cf4b27ea' +
    'd87aae6b767f0ec49cdc0c0000006576656e742d432d64617461030000000400' +
    '0080010000000c00eca41f8a750a060cc532afd0a6f016c9f61e5da3f116d21f' +
    '39b5e7493e8fe6ac108b59d8e68c06a401a32bf0a0daa2070c0000006576656e' +
    '742d442d64617461';
  const expected = [
    'eebd6b944d3c5aa23713edd5d40ca48affc1293b88889884c27fb683cb5531564d65db8c442738fda0f2bf122deea144',
    '4a7aaec7d4d007acc2857e15a6515dcfbf5cbc659932b1cd08ea00fd5835f788ea553202f642bc405f44c7d86211cf5c',
    '5ff9199110228b30594d6d62215ba34d933f7de43ae402f5ab1d531a09b511bd2e82107879730afd7292caefe83584ae',
    '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
  ];
  const { rtmr, events } = replayCcel(Buffer.from(logHex, 'hex'));
  let fail = 0;
  for (let i = 0; i < 4; i++) {
    const got = rtmr[i].toString('hex');
    const ok = got === expected[i];
    if (!ok) fail++;
    console.log(`  ${ok ? '✅' : '❌'} RTMR${i}: ${got}${ok ? '' : ` ≠ expected ${expected[i]}`}`);
  }
  console.log(`  events parsed: ${events.length} (spec-id + multi-digest + EV_NO_ACTION + 3 extensions)`);
  // trailing-padding tolerance (mirror of the Rust test): the live Alibaba
  // CCEL holds 1626 real bytes in a 65536-byte area, 0xFF/0x00 padded.
  const padded = Buffer.concat([Buffer.from(logHex, 'hex'), Buffer.alloc(512, 0xff), Buffer.alloc(512, 0x00)]);
  const r2 = replayCcel(padded).rtmr;
  const padOk = r2.every((b, i) => b.equals(rtmr[i]));
  console.log(`  ${padOk ? '✅' : '❌'} trailing 0xFF/0x00 padding tolerated (replay unchanged)`);
  if (!padOk) fail++;
  console.log(fail ? `SELFTEST FAILED (${fail}/4 registers drifted)` : 'SELFTEST OK — replay matches the Rust security_tests vector');
  process.exit(fail ? 1 : 0);
}

const ccelPath = opt('--ccel');
const reportPath = opt('--report');
if (!ccelPath && !reportPath) {
  console.log(`Usage:
  node scripts/calculate-golden-rtmr.mjs --selftest
  node scripts/calculate-golden-rtmr.mjs --ccel <ccel.bin|hex|b64|-> [--json]
  node scripts/calculate-golden-rtmr.mjs --report <live-report.json|-> [--json]
  node scripts/calculate-golden-rtmr.mjs --report <live-report.json> --ccel <ccel.bin>   # cross-check
  node scripts/calculate-golden-rtmr.mjs --report <live-report.json> --update   # rotate verify.html pins`);
  process.exit(flag('--help') ? 0 : 1);
}

const out = {};
if (ccelPath) {
  const log = readBytes(ccelPath);
  const { rtmr, events } = replayCcel(log);
  // Dual-convention replay (mirror of ccel_replay_vs_quote in src/intel_tdx.rs):
  // also replay from the legacy SHA-384(1024×0x00) reset state so the
  // cross-check can accept either and record which one the platform used.
  const altInit = sha384(Buffer.alloc(1024));
  out.ccel = {
    rtmr: rtmr.map((b) => b.toString('hex')),
    rtmr_alt_init: replayCcel(log, altInit).rtmr.map((b) => b.toString('hex')),
    events,
  };
  if (!flag('--json')) {
    console.log(`CCEL replay: ${events.length} events`);
    for (const [i, e] of events.entries()) {
      console.log(`  #${i} pcr=${e.pcrIndex} type=${e.eventType} digests=${e.digestCount} → ${e.action}` +
        (e.digestSha384 ? ` [sha384 ${e.digestSha384.slice(0, 16)}…]` : '') + ` "${e.dataPreview}"`);
    }
    out.ccel.rtmr.forEach((h, i) => console.log(`RTMR${i} = ${h}`));
  }
}
if (reportPath) {
  const raw = (reportPath === '-' ? readFileSync(0) : readFileSync(reportPath)).toString('utf8').trim();
  let quoteBytes;
  if (raw.startsWith('{')) {
    const j = JSON.parse(raw);
    const quoteB64 = j?.hardware_level_attestation?.tdx_quote_b64
      || j?.attestation_report?.hardware_level_attestation?.tdx_quote_b64
      || j?.attestation_envelope?.attestation_report?.hardware_level_attestation?.tdx_quote_b64 || null;
    if (!quoteB64) { console.error('FAIL: no tdx_quote_b64 in the report — nothing hardware-signed to pin'); process.exit(1); }
    quoteBytes = b64OrHex(quoteB64);
  } else {
    quoteBytes = b64OrHex(raw);
  }
  const m = quoteMeasurements(quoteBytes);
  out.quote = { version: m.version, mrtd: m.mrtd.toString('hex'), rtmr: m.rtmr.map((b) => b.toString('hex')) };
  if (!flag('--json')) {
    console.log(`TD Quote v${m.version} measurements:`);
    console.log(`MRTD   = ${out.quote.mrtd}`);
    out.quote.rtmr.forEach((h, i) => console.log(`RTMR${i} = ${h}`));
  }
}

// cross-check: CCEL replay must reproduce the quoted RTMRs exactly under one
// of the two RTMR reset conventions (mirror of ccel_replay_vs_quote in
// src/intel_tdx.rs; the silicon quote is ground truth either way)
if (out.ccel && out.quote) {
  const tryMatch = (rtmrs, conv) => {
    const mism = [];
    for (let i = 0; i < 4; i++) if (rtmrs[i] !== out.quote.rtmr[i]) mism.push(`RTMR${i}`);
    return { conv, mism };
  };
  let best = tryMatch(out.ccel.rtmr, 'zero-init (TDX spec)');
  if (best.mism.length) {
    const alt = tryMatch(out.ccel.rtmr_alt_init, 'sha384(1024×0x00)-init');
    if (!alt.mism.length) {
      best = alt;
    } else {
      out.crosscheck = `FAIL (zero-init: ${best.mism.join(', ')} differ; sha384-init: ${alt.mism.join(', ')} differ)`;
      if (!flag('--json')) console.log(`CCEL ↔ quote cross-check: ${out.crosscheck}`);
      if (flag('--json')) console.log(JSON.stringify(out, null, 2));
      process.exit(1);
    }
  }
  out.crosscheck = `OK (log replay reproduces the quoted RTMR0..3 exactly; convention: ${best.conv})`;
  if (!flag('--json')) console.log(`CCEL ↔ quote cross-check: ${out.crosscheck}`);
}

if (flag('--update')) {
  // Pins are SILICON values: prefer the quote's measurements over replay output
  const changes = updateVerifyHtml(out.quote ? out.quote.mrtd : null, out.quote ? out.quote.rtmr : (out.ccel ? out.ccel.rtmr : null));
  console.log('verify.html pins rotated:');
  for (const c of changes) console.log('  ' + c);
  console.log('Commit verify.html in the reviewed commit that changed the boot chain.');
}
if (flag('--json')) console.log(JSON.stringify(out, null, 2));
