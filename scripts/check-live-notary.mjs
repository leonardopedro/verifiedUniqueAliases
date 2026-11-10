// Live check for the TLSNotary notary — the enclave's second webservice.
//
// Why this exists: v227–v229 rotated a disk built with `TLS_PROXY=0` onto an
// instance whose config still says `services.tls_proxy.enabled: true`, so the
// supervisor logged `spawn failed: No such file or directory` and the notary was
// silently absent for three releases. `enabled` in the config is only a wish;
// this asserts the service PID 1 actually spawned, that its session port accepts
// connections, and that its API answers instead of failing closed with 503.
//
// Usage:
//   node scripts/check-live-notary.mjs [--url https://login.airma.de]
//
// Env: PROD_URL (default https://login.airma.de)
//
// Exit 0 = enabled, running, session port listening, attestation list readable.
import { connect } from 'net';
import { setTimeout as sleep } from 'timers/promises';

const args = process.argv.slice(2);
const argUrl = args.includes('--url') ? args[args.indexOf('--url') + 1] : null;
const base = (argUrl || process.env.PROD_URL || 'https://login.airma.de').replace(/\/+$/, '');
const host = new URL(base).hostname;
const fail = (msg) => { console.error(`  ❌ ${msg}`); console.log(`RESULT: notary NOT healthy — ${msg}`); process.exit(1); };
const ok = (msg) => console.log(`  ✅ ${msg}`);

const get = async (path) => {
  try {
    const res = await fetch(base + path, { signal: AbortSignal.timeout(20000) });
    const text = await res.text();
    return { status: res.status, text };
  } catch (e) {
    fail(`GET ${path} failed — ${e.message}`);
  }
};

const health = await get('/proxy/health');
if (health.status !== 200) fail(`/proxy/health → HTTP ${health.status}: ${health.text.slice(0, 200)}`);
let h;
try { h = JSON.parse(health.text); } catch { fail('/proxy/health is not JSON'); }
if (h.service !== 'tls-proxy') fail(`/proxy/health names service "${h.service}", expected "tls-proxy"`);
if (h.enabled !== true) fail('config has the notary disabled (services.tls_proxy.enabled=false) — the newest webservice is off');
if (h.running !== true) {
  fail(`supervisor has NOT spawned the notary (running=${h.running}; last=${JSON.stringify(h.last)}). ` +
       'The usual cause is a disk built with TLS_PROXY=0: check that /tls-proxy exists in the image.');
}
ok(`supervisor reports the notary running (restarts=${h.restarts}, last=${JSON.stringify(h.last)})`);
if (!Number.isInteger(h.session_port) || h.session_port < 1 || h.session_port > 65535) {
  fail(`/proxy/health has no usable session_port (${JSON.stringify(h.session_port)})`);
}
ok(`api_port ${h.api_port}, session_port ${h.session_port}`);

// The session port is a raw TLSNotary listener, so a TCP connect is the whole
// assertion: if PID 1 spawned a dead child, the port refuses.
const connected = await new Promise((resolve) => {
  let done = false;
  const finish = (v) => { if (!done) { done = true; sock.destroy(); resolve(v); } };
  const sock = connect({ host, port: h.session_port });
  sock.setTimeout(12000);
  sock.once('connect', () => finish(true));
  sock.once('timeout', () => finish(false));
  sock.once('error', () => finish(false));
});
if (!connected) fail(`${host}:${h.session_port} does not accept connections`);
ok(`${host}:${h.session_port} accepts a session connection`);

// A running child that refuses every proof is still a dead service: the list
// route is the one the prover uses to find their own record. The shape is the
// documented one — { service, running, count, sessions[], redaction } — not a
// bare array.
const list = await get('/proxy/attestations');
if (list.status !== 200) fail(`/proxy/attestations → HTTP ${list.status}: ${list.text.slice(0, 200)}`);
let l;
try { l = JSON.parse(list.text); } catch { fail('/proxy/attestations is not JSON'); }
if (l.service !== 'tls-proxy' || l.running !== true) {
  fail(`/proxy/attestations reports service=${JSON.stringify(l.service)} running=${JSON.stringify(l.running)}`);
}
if (!Array.isArray(l.sessions)) fail(`/proxy/attestations has sessions: ${typeof l.sessions}, expected an array`);
if (l.count !== l.sessions.length) fail(`/proxy/attestations count=${l.count} but lists ${l.sessions.length}`);
ok(`/proxy/attestations answers 200 with ${l.count} record(s)`);

// Give the health counters a moment to reflect the connect above; the numbers
// are informational (a bare connect-and-close is counted as a failed session by
// design), so they are reported, never asserted.
await sleep(1500);
const after = await get('/proxy/health');
try {
  const a = JSON.parse(after.text);
  ok(`counters: sessions_ok=${a.sessions_ok}, sessions_failed=${a.sessions_failed}, active=${a.active_sessions}`);
} catch { /* informational only */ }

console.log('RESULT: notary is enabled, spawned, listening and serving its attestation list — OK');
