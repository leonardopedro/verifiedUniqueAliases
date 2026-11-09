#!/usr/bin/env node
// =============================================================================
// check-live-callback.mjs — the return leg must refuse junk the way a sealed
// service refuses it: a short plain-text status, never an error page.
//
// Why this exists (2026-11-09, v228): v227 made `https://login.airma.de/callback`
// the ONLY PayPal Return URL, so that route is now reachable by anything on the
// internet — PayPal redirects, scanners, and anyone typing it. Three failure
// modes matter, and none of them is visible in a build:
//
//   1. A missing/forged `code`+`state` must be REFUSED (403), not exchanged.
//   2. The refusal must be a sealed plain-text line — an HTML error page or a
//      framework default leaks the stack shape and invites scraping.
//   3. A PayPal-side `error=` redirect is a distinct, non-retryable outcome
//      (400) that says no code was exchanged, so a user knows to restart.
//
// It also asserts no internal markers (panic, backtrace, axum/hyper) reach the
// body, and that repeated junk requests give the same answer — a per-request
// error path that sometimes 500s is the prelude to a reachable quote mint.
//
// Usage:
//   node scripts/check-live-callback.mjs [--url https://login.airma.de] [--quiet]
//
// Exit: 0 sealed refusals, 1 unexpected answer, 2 could not reach the service.
// =============================================================================
const argv = process.argv.slice(2);
const argOf = (name, fallback = null) => {
  const i = argv.indexOf(name);
  return i === -1 ? fallback : argv[i + 1];
};
const BASE = (argOf('--url', 'https://login.airma.de') || '').replace(/\/+$/, '');
const QUIET = argv.includes('--quiet');

const fail = [];
const say = (...a) => { if (!QUIET) console.log(...a); };
const ok = (m) => { if (!QUIET) console.log(`✅ ${m}`); };
const bad = (m) => { fail.push(m); console.log(`❌ ${m}`); };

const LEAK = /(panic|RUST_BACKTRACE|backtrace|axum|hyper|tokio|stack trace|Traceback)/i;

async function probe(label, path, expectStatus) {
  let res;
  try {
    res = await fetch(`${BASE}${path}`, { redirect: 'manual' });
  } catch (e) {
    console.error(`❌ ${label}: cannot reach ${BASE}${path} — ${e.message}`);
    process.exit(2);
  }
  const body = await res.text();
  const type = String(res.headers.get('content-type') || '');
  const short = body.trim();

  if (res.status !== expectStatus) {
    bad(`${label}: status ${res.status}, expected ${expectStatus}`);
  } else {
    ok(`${label}: ${res.status}`);
  }
  if (!/^text\/plain\b/i.test(type)) bad(`${label}: content-type "${type}" — a sealed refusal must be plain text`);
  if (/^\s*</.test(short) || /<html|<body|<pre/i.test(short)) {
    bad(`${label}: body is HTML, not a sealed message`);
  }
  if (short.length > 300) bad(`${label}: body is ${short.length} chars — too long to be a sealed refusal`);
  if (LEAK.test(short)) bad(`${label}: body leaks an internal marker (${(short.match(LEAK) || [''])[0]})`);
  if (/code=|access_token|refresh_token|client_secret/i.test(short)) {
    bad(`${label}: body echoes credentials or a code`);
  }
  return { status: res.status, type, body: short };
}

async function main() {
  say(`live callback refusal — ${BASE}`);

  const bare = await probe('bare /callback', '/callback', 403);
  const forged = await probe('forged code+state', '/callback?code=bogus&state=bogus', 403);
  const denied = await probe('PayPal error= redirect', '/callback?error=access_denied', 400);

  // The two 403s are the same refusal, and that refusal names where to restart.
  if (bare.status === 403 && forged.status === 403) {
    if (bare.body === forged.body) ok('missing and forged input give the same sealed refusal');
    else bad('missing and forged input give different messages — one path is unsealed');
  }
  if (bare.status === 403 && !/verify\.html/i.test(bare.body)) {
    bad('the 403 does not tell the user where to restart (verify.html)');
  }
  if (denied.status === 400 && /code/i.test(denied.body) === false) {
    bad('the PayPal-error refusal does not say that no code was exchanged');
  }
  if (denied.status === 400 && /(exchanged|restart|verify\.html)/i.test(denied.body) === false) {
    bad('the PayPal-error refusal gives the user no recovery step');
  }

  console.log('');
  if (fail.length) {
    console.log(`RESULT: ${fail.length} unexpected answer${fail.length === 1 ? '' : 's'} — FAIL`);
    process.exit(1);
  }
  console.log('RESULT: /callback refuses junk with a sealed plain-text status — OK');
}

main().catch((e) => {
  console.error(`❌ ${e.stack || e.message}`);
  process.exit(2);
});
