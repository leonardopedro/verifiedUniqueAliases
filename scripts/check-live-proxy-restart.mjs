// Live test: the envelope cache follows the notary's key across a restart.
//
// Why this exists: `/debug/envelope` is served from a 15-minute RAM cache so no
// request path can mint TD quotes at line rate (v180). Until v232 that cache was
// keyed on time alone, so a notary restart left it publishing the PREVIOUS
// boot's signing key and every auditor's (fail-closed) binding check failed
// until the window ran out. v232 stores the published fingerprint and re-mints
// when the live key differs; v233 adds the operator-only `POST /proxy/restart`
// that makes the restart happen on demand, which is what makes this provable
// from outside the enclave without rebooting it.
//
// What it proves, in order:
//   1. two fetches inside the window are byte-identical — the cache really is a
//      cache (no quote per request);
//   2. `POST /proxy/restart` with the operator token cycles the child and is
//      reported by `/proxy/health` (`restarts` increments, `running` returns);
//   3. the very next fetch — still inside the 15-minute window of the first
//      body — names the NEW key, has a NEW `timestamp_ms` and a NEW enclave
//      signature: it was re-minted, not served stale;
//   4. the unnamed-but-real check: the new body's key matches the notary's live
//      key, read straight from the child through the new report.
//
// Usage:
//   PROXY_RESTART_TOKEN=… node scripts/check-live-proxy-restart.mjs [--url https://login.airma.de]
//
// Env: PROD_URL (default https://login.airma.de), PROXY_RESTART_TOKEN (required —
// the token from the instance's `services.tls_proxy.restart_token`), and
// RESTART_SETTLE_MS (default 90000: how long to wait for the new child).

import { setTimeout as sleep } from 'timers/promises';

const args = process.argv.slice(2);
const argUrl = args.includes('--url') ? args[args.indexOf('--url') + 1] : null;
const base = (argUrl || process.env.PROD_URL || 'https://login.airma.de').replace(/\/+$/, '');
const token = process.env.PROXY_RESTART_TOKEN || '';
const settleMs = Number(process.env.RESTART_SETTLE_MS || 90000);

const fail = (msg) => {
  console.error(`  ❌ ${msg}`);
  console.log(`RESULT: envelope cache does NOT follow the notary key — ${msg}`);
  process.exit(1);
};
const ok = (msg) => console.log(`  ✅ ${msg}`);

if (!token) {
  fail('PROXY_RESTART_TOKEN is not set — this test needs the operator token from the instance config ' +
       '(services.tls_proxy.restart_token). The route answers 404 without it, by design.');
}

const envelope = async (label) => {
  const res = await fetch(base + '/debug/envelope', { signal: AbortSignal.timeout(30000) });
  const text = await res.text();
  if (res.status !== 200) fail(`${label}: /debug/envelope → HTTP ${res.status}: ${text.slice(0, 200)}`);
  let body;
  try { body = JSON.parse(text); } catch { fail(`${label}: /debug/envelope is not JSON`); }
  const key = body?.attestation_report?.session_context?.proxy_signing_key;
  if (!key || key.available !== true || !key.pubkey_sha256) {
    fail(`${label}: the report names no notary key (${JSON.stringify(key).slice(0, 160)}) — ` +
         'is the notary enabled in this deployment?');
  }
  return {
    raw: text,
    key: key.pubkey_sha256,
    pem: key.pubkey_pem,
    reported: key.reported_sha256,
    certMintedAt: body?.attestation_report?.timestamp_ms,
    signature: body?.enclave_signature_b64,
  };
};

const health = async () => {
  const res = await fetch(base + '/proxy/health', { signal: AbortSignal.timeout(20000) });
  const text = await res.text();
  if (res.status !== 200) fail(`/proxy/health → HTTP ${res.status}: ${text.slice(0, 200)}`);
  try { return JSON.parse(text); } catch { return fail('/proxy/health is not JSON'); }
};

console.log(`Live envelope-cache / notary-restart test against ${base}\n`);

// 1. The cache is a cache: same bytes twice, well inside the window.
const before = await envelope('before restart');
const again = await envelope('before restart (second fetch)');
if (again.raw !== before.raw) {
  fail('two fetches 2 s apart returned different bodies — the 15-minute envelope cache is not working ' +
       '(every request would mint a TD quote)');
}
ok(`two fetches inside the window are byte-identical (key ${before.key.slice(0, 16)}…)`);

const hBefore = await health();
if (hBefore.running !== true) fail(`the notary is not running before the restart: ${JSON.stringify(hBefore.last)}`);

// 2. Cycle the child through the supervised path.
console.log('\n  → POST /proxy/restart');
const rr = await fetch(base + '/proxy/restart', {
  method: 'POST',
  headers: { 'x-proxy-restart': token },
  signal: AbortSignal.timeout(20000),
});
const rtext = await rr.text();
if (rr.status === 404) {
  fail('POST /proxy/restart → 404: either no restart token is configured on this instance ' +
       '(services.tls_proxy.restart_token) or the token presented is wrong — the route does not ' +
       'distinguish the two, by design');
}
if (rr.status !== 202) fail(`POST /proxy/restart → HTTP ${rr.status}: ${rtext.slice(0, 200)}`);
ok('the supervisor accepted the restart request (202)');

// Wait for the cycle: `restarts` must move, `running` must come back true.
const deadline = Date.now() + settleMs;
let hAfter = null;
let sawGap = false;
while (Date.now() < deadline) {
  const h = await health();
  if (h.restarts > hBefore.restarts) sawGap = true;
  if (sawGap && h.running === true) { hAfter = h; break; }
  await sleep(2000);
}
if (!hAfter) {
  fail(`the notary did not come back within ${Math.round(settleMs / 1000)} s after the restart ` +
       `(restarts was ${hBefore.restarts}; last=${JSON.stringify(hAfter?.last)})`);
}
ok(`the notary cycled and is running again (restarts ${hBefore.restarts} → ${hAfter.restarts})`);

// 3. The next fetch — inside the 15-minute window of the first body — must be
//    re-minted, not the stale cache.
const after = await envelope('after restart');
if (after.key === before.key) {
  fail(`the report still names ${before.key.slice(0, 16)}… after the notary restarted — ` +
       'the cache served a body naming the dead key (this is the v231 defect)');
}
ok(`the report names the NEW key ${after.key.slice(0, 16)}… (was ${before.key.slice(0, 16)}…)`);
if (after.raw === before.raw) fail('the body is byte-identical but the key changed — impossible unless the probe is ignored');
if (!(after.certMintedAt > before.certMintedAt)) {
  fail(`the body was not re-minted (timestamp_ms ${before.certMintedAt} → ${after.certMintedAt})`);
}
if (after.signature === before.signature) {
  fail('the enclave signature did not change although the body did — a cached body was served with a fresh key spliced in?');
}
ok(`re-minted, not spliced: timestamp +${after.certMintedAt - before.certMintedAt} ms, new enclave signature`);

// 4. The key the report names is the key the child actually holds, and its own
//    self-report agrees (a report that names an old key would pass none of this).
if (after.pem === before.pem) fail('the notary PEM did not change across the restart — the child was not replaced');
if (after.reported !== after.key) {
  fail(`the report's own key hash disagrees with the PEM: named ${after.reported} ≠ ${after.key}`);
}
ok('the named key, its PEM and the report\'s self-reported hash all agree');

// 5. And a second fetch after the restart is cached again: the re-mint did not
//    disable the cache.
const cachedAgain = await envelope('after restart (second fetch)');
if (cachedAgain.raw !== after.raw) {
  fail('the post-restart body is not cached — re-minting every request would hammer TDX');
}
ok('the re-minted body is cached again (no quote per request)');

console.log(`RESULT: OK — the envelope cache follows the notary key across a live restart ` +
            `(${before.key.slice(0, 16)}… → ${after.key.slice(0, 16)}…)`);
