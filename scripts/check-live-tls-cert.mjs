#!/usr/bin/env node
// =============================================================================
// check-live-tls-cert.mjs — prove that the certificate a visitor downloads is
// the certificate the connection actually used, and the one the report names.
//
// Why this exists (2026-11-09, v227): the landing stopped recommending a GitHub
// Pages copy of the auditor and now offers `GET /tls-cert.pem` instead, with the
// instruction "compare its fingerprint with the padlock". That instruction is
// only worth anything if three things are the same certificate:
//
//   1. the PEM body served by /tls-cert.pem (what the visitor saves),
//   2. the leaf the TLS handshake to the enclave actually presented (what the
//      browser padlock shows), and
//   3. `session_context.tls_certificate_pem` inside the attestation report
//      (what a sealed `code_enc` is bound to).
//
// A rotation that swaps the image but leaves stale bytes in the report copy, or
// a proxy that terminates TLS in front of the enclave, breaks that equality
// silently — the page still renders, the button still downloads a valid PEM, and
// nothing anywhere says it is the wrong one. This check fails loudly instead.
//
// It also guards the landing itself: the certificate link must exist and the
// page must still name the enclave's own callback as the return leg. A future
// edit that quietly points users back at a third-party auditor origin trips
// here as well as in the offline suite.
//
// Usage:
//   node scripts/check-live-tls-cert.mjs [--url https://login.airma.de]
//                                        [--report <saved-envelope.json>]
//                                        [--quiet]
//
// Exit: 0 all equal, 1 mismatch, 2 could not fetch/connect.
// =============================================================================
import { readFileSync } from 'fs';
import { createHash } from 'crypto';
import { connect } from 'tls';

const argv = process.argv.slice(2);
const argOf = (name, fallback = null) => {
  const i = argv.indexOf(name);
  return i === -1 ? fallback : argv[i + 1];
};
const BASE = (argOf('--url', 'https://login.airma.de') || '').replace(/\/+$/, '');
const REPORT_FILE = argOf('--report');
const QUIET = argv.includes('--quiet');

const fail = [];
const say = (...a) => { if (!QUIET) console.log(...a); };
const ok = (m) => { if (!QUIET) console.log(`✅ ${m}`); };
const bad = (m) => { fail.push(m); console.log(`❌ ${m}`); };

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

// ---- PEM <-> DER -----------------------------------------------------------
function pemToDer(pem, label = 'CERTIFICATE') {
  const m = String(pem || '').match(
    new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`),
  );
  if (!m) return null;
  const b64 = m[1].replace(/[^A-Za-z0-9+/=]/g, '');
  if (!b64) return null;
  const der = Buffer.from(b64, 'base64');
  return der.length > 0 ? der : null;
}

function countPems(pem) {
  return (String(pem || '').match(/-----BEGIN CERTIFICATE-----/g) || []).length;
}

// ---- peer certificate ------------------------------------------------------
function peerLeafDer(host) {
  return new Promise((resolve, reject) => {
    const sock = connect({ host, port: 443, servername: host });
    const done = (fn, val) => { try { sock.destroy(); } catch { /* ignore */ } fn(val); };
    sock.setTimeout(20000, () => done(reject, new Error(`TLS handshake to ${host}:443 timed out`)));
    sock.once('error', (e) => done(reject, e));
    sock.once('secureConnect', () => {
      const cert = sock.getPeerCertificate(true);
      if (!cert || !cert.raw) return done(reject, new Error('peer presented no certificate'));
      done(resolve, Buffer.from(cert.raw));
    });
  });
}

// ---- main ------------------------------------------------------------------
async function get(path) {
  const url = `${BASE}${path}`;
  const res = await fetch(url, { redirect: 'follow' });
  const body = Buffer.from(await res.arrayBuffer());
  return { url, status: res.status, headers: res.headers, body };
}

async function main() {
  const host = new URL(BASE).hostname;
  say(`live TLS certificate binding — ${BASE}`);

  // 1. landing still offers the download and names the enclave callback
  let landing;
  try {
    landing = await get('/');
  } catch (e) {
    console.error(`❌ cannot fetch ${BASE}/ — ${e.message}`);
    process.exit(2);
  }
  if (landing.status !== 200) bad(`GET / returned ${landing.status}, expected 200`);
  const html = landing.body.toString('utf8');
  const hasCertLink = /href="(?:https:\/\/[^"]+)?\/tls-cert\.pem"/.test(html)
    || /href="\/tls-cert\.pem"/.test(html);
  if (!hasCertLink) bad('landing has no link to /tls-cert.pem — a visitor cannot save the certificate');
  else ok('landing links /tls-cert.pem');
  if (!html.includes(`${host}/callback`)) bad(`landing no longer names ${host}/callback as the return leg`);
  else ok(`landing names ${host}/callback as the return leg`);
  if (/Open verify\.html in this browser/.test(html) || /leonardopedro\.github\.io\/[^"]*verify\.html/.test(html)) {
    bad('landing links a third-party (Pages) copy of the auditor again');
  }

  // 2. the served PEM
  let certRes;
  try {
    certRes = await get('/tls-cert.pem');
  } catch (e) {
    console.error(`❌ cannot fetch ${BASE}/tls-cert.pem — ${e.message}`);
    process.exit(2);
  }
  if (certRes.status !== 200) {
    bad(`GET /tls-cert.pem returned ${certRes.status}, expected 200`);
  } else {
    ok(`/tls-cert.pem served (${certRes.body.length} B)`);
  }
  const servedPem = certRes.body.toString('utf8');
  const served = pemToDer(servedPem);
  if (!served) {
    console.error('❌ /tls-cert.pem body is not a PEM certificate — nothing to compare');
    process.exit(2);
  }
  // The download is the chain the browser was offered (leaf first): a visitor
  // can then run `openssl verify -CAfile` on it. Only the leaf is comparable
  // with the handshake and the report, which is what matters here.
  const chainLen = countPems(servedPem);
  if (chainLen < 1) bad('/tls-cert.pem carries no complete PEM block');
  else ok(`/tls-cert.pem carries ${chainLen} certificate${chainLen === 1 ? '' : 's'} (leaf first)`);
  const ctype = String(certRes.headers.get('content-type') || '');
  if (!/application\/(x-pem-file|pkix-cert)/i.test(ctype)) {
    bad(`/tls-cert.pem content-type is "${ctype}", expected application/x-pem-file`);
  } else {
    ok(`content-type ${ctype}`);
  }

  // 3. the report's copy — live envelope, or a saved report when one is given
  let report;
  let reportLabel;
  if (REPORT_FILE) {
    try {
      report = JSON.parse(readFileSync(REPORT_FILE, 'utf8'));
    } catch (e) {
      console.error(`❌ cannot read --report ${REPORT_FILE} — ${e.message}`);
      process.exit(2);
    }
    reportLabel = REPORT_FILE;
  } else {
    let env;
    try {
      env = await get('/debug/envelope');
    } catch (e) {
      console.error(`❌ cannot fetch ${BASE}/debug/envelope — ${e.message}`);
      process.exit(2);
    }
    if (env.status !== 200) {
      console.error(`❌ GET /debug/envelope returned ${env.status}`);
      process.exit(2);
    }
    const parsed = JSON.parse(env.body.toString('utf8'));
    report = parsed.attestation_report || parsed;
    reportLabel = 'live envelope';
  }
  const reportPem = report?.session_context?.tls_certificate_pem;
  const reportDer = pemToDer(reportPem);
  if (!reportDer) {
    bad(`${reportLabel} carries no session_context.tls_certificate_pem — a sealed code could not name the certificate the user downloaded`);
  } else {
    ok(`${reportLabel} carries tls_certificate_pem (${reportDer.length} B DER)`);
  }

  // 4. the certificate the handshake really presented
  let peer = null;
  let peerErr = null;
  try {
    peer = await peerLeafDer(host);
  } catch (e) {
    peerErr = e;
  }

  // 5. compare
  const servedSha = sha256(served);
  if (reportDer) {
    const reportSha = sha256(reportDer);
    if (servedSha === reportSha) ok(`/tls-cert.pem == report (sha256 ${servedSha})`);
    else bad(`/tls-cert.pem (${servedSha}) != report tls_certificate_pem (${reportSha})`);
  }
  if (peer) {
    const peerSha = sha256(peer);
    if (peerSha === servedSha) ok(`live handshake leaf == /tls-cert.pem (sha256 ${peerSha})`);
    else bad(`live handshake leaf (${peerSha}) != /tls-cert.pem (${servedSha}) — the download is not the certificate your browser saw`);
    if (reportDer && peerSha !== sha256(reportDer)) {
      bad(`live handshake leaf (${peerSha}) != report tls_certificate_pem (${sha256(reportDer)})`);
    }
  } else {
    bad(`could not read the live leaf certificate from ${host}:443 — ${peerErr?.message || 'unknown error'}`);
  }

  console.log('');
  if (fail.length) {
    console.log(`RESULT: ${fail.length} mismatch${fail.length === 1 ? '' : 'es'} — FAIL`);
    process.exit(1);
  }
  console.log('RESULT: certificate download, live handshake and report agree — OK');
}

main().catch((e) => {
  console.error(`❌ ${e.stack || e.message}`);
  process.exit(2);
});
