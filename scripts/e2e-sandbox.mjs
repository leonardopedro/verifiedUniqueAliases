// Live sandbox end-to-end driver: runs the REAL enclave + PayPal sandbox login
// through a headless browser and leaves one report JSON per flow for the
// offline auditor (REAL_REPORT=…).
//
// The flow itself lives in scripts/e2e-login-download.mjs, which this script
// drives once per flow. That split is deliberate: the login path changed under
// this file once already. It used to GET /login?flow=…, an enclave route that
// v180 removed (the login now starts in the auditor page with a POST to
// /attest/login-session, hands off to PayPal through a second click, and the
// /callback page auto-downloads the sealed ciphertext back into the trusted
// tab). The old copy kept asking for a 404 and reported the failure as a
// product problem. Delegating means one file owns the browser choreography.
//
// Which service this driver tests (learned the hard way, 2026-11-09): there are
// TWO webservices. The login/attestation enclave talks to PRODUCTION paypal.com
// only; the TLS-notary proxy is the one that reaches sandbox.paypal.com, and its
// e2e is tls-proxy/tests/live.rs (LIVE_SERVER=www.sandbox.paypal.com), NOT this
// script. So a sandbox account cannot complete a login here unless the enclave
// was booted with `staging: true`.
//
// Hence the preflight below: before opening a browser it asks the enclave what
// environment it is configured for (the signed login-session response carries
// `paypal_environment` and `authorize_base` — the only place the boot-time
// `staging` flag is observable, since no route exposes the config itself) and
// refuses to drive a production-configured host. Without it, the run reaches
// the production authorize page, the sandbox identity is refused, and the
// automation retries the credentials three times before failing with a message
// that looks like a product defect instead of a wrong target.
//
// Usage:
//   node scripts/e2e-sandbox.mjs [verified|full|both]
//
// Env:
//   PPEMAIL / PPPASS — PayPal sandbox account (defaults in the flow script)
//   CHROMIUM_PATH    — system Chromium (playwright's own build needs distro libs)
//   PAV_ENCLAVE_HOST — enclave to test (default https://login.airma.de)
//   PAV_ALLOW_PRODUCTION=1 — drive a production-configured enclave on purpose
//                      (needs a REAL production account, not the sb-… default)
//
// Exit: 0 flows passed · 1 a flow failed · 2 refused (wrong environment)
//
// Outputs:
//   /tmp/report-<flow>.json  — decrypted report, usable as REAL_REPORT
//   /tmp/claimed-report.json — the flow script's own copy (last flow wins)
import { spawnSync } from 'child_process';
import { copyFileSync, existsSync } from 'fs';
import { generateKeyPairSync, randomBytes } from 'crypto';

const arg = (process.argv[2] || 'both').toLowerCase();
const FLOWS = arg === 'both' ? ['verified', 'full'] : [arg === 'full' ? 'full' : 'verified'];
const log = (...a) => console.log(...a);

const ENCLAVE_HOST = (process.env.PAV_ENCLAVE_HOST || 'https://login.airma.de').replace(/\/+$/, '');

// Ask the enclave which PayPal environment it was booted for. Costs one pending
// login-session (state token + escrow slot, TTL-bound) — cheaper than the browser
// run it prevents, and the answer is signed, so it describes the deployed config
// rather than anything this script could have made up.
async function enclaveEnvironment() {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const body = JSON.stringify({
    client_ecdh_pub_b64: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    client_nonce_hex: randomBytes(32).toString('hex'),
    flow: 'verified',
  });
  const res = await fetch(`${ENCLAVE_HOST}/attest/login-session`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
    signal: AbortSignal.timeout(20000),
  });
  if (!res.ok) {
    throw new Error(`${ENCLAVE_HOST}/attest/login-session → HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
  }
  const j = await res.json();
  return {
    environment: j?.signed_fields?.paypal_environment,
    authorizeBase: j?.signed_fields?.authorize_base,
  };
}

if (process.env.PAV_ALLOW_PRODUCTION !== '1') {
  let env;
  try {
    env = await enclaveEnvironment();
  } catch (e) {
    console.error(`\n❌ PREFLIGHT FAILED — cannot ask ${ENCLAVE_HOST} which environment it is configured for.`);
    console.error(`   ${e.message}`);
    console.error('   Nothing was launched. Check the host (PAV_ENCLAVE_HOST) and that it is reachable.');
    process.exit(2);
  }
  if (env.environment !== 'sandbox') {
    console.error(`\n❌ REFUSING TO RUN — ${ENCLAVE_HOST} is configured for ${env.environment ?? 'an unknown environment'}, not sandbox.`);
    console.error(`   authorize_base: ${env.authorizeBase ?? '(not reported)'}`);
    console.error('');
    console.error('   This driver logs a PayPal SANDBOX account in through the login enclave, so it');
    console.error('   needs an enclave booted with staging: true. The production login enclave talks');
    console.error('   to paypal.com only, and a sandbox identity is refused there — the run would');
    console.error('   reach the production authorize page and fail looking like a product defect.');
    console.error('');
    console.error('   Sandbox coverage of the OTHER service is the notary relay test:');
    console.error('     LIVE_NOTARY=<ip>:8443 LIVE_SERVER=www.sandbox.paypal.com LIVE_PATH=/signin \\');
    console.error('       cargo test --test live -- --ignored --nocapture      # in tls-proxy/');
    console.error('');
    console.error('   To drive production deliberately (real account): PAV_ALLOW_PRODUCTION=1');
    process.exit(2);
  }
  log(`preflight: ${ENCLAVE_HOST} → paypal_environment=${env.environment} (${env.authorizeBase})`);
}

const results = [];
for (const flow of FLOWS) {
  if (results.length) await new Promise((r) => setTimeout(r, 15000));
  log(`\n===== FLOW: ${flow} =====`);
  const r = spawnSync(process.execPath, ['scripts/e2e-login-download.mjs', flow], {
    stdio: 'inherit',
    env: process.env,
  });
  const ok = r.status === 0;
  const src = '/tmp/claimed-report.json';
  const dst = `/tmp/report-${flow}.json`;
  let hasReport = false;
  if (ok && existsSync(src)) {
    try {
      copyFileSync(src, dst);
      hasReport = true;
    } catch { /* reported below */ }
  }
  results.push({ flow, ok, hasReport });
}

log('\n===== E2E SUMMARY =====');
for (const r of results) {
  log(` ${r.flow}: ${r.ok ? '✅' : '❌'} report=${r.hasReport ? `/tmp/report-${r.flow}.json` : 'no'}`);
}
const first = results.find((r) => r.hasReport);
if (first) log(`\nOffline audit of the captured report:\n  REAL_REPORT=/tmp/report-${first.flow}.json npm test`);
process.exit(results.every((r) => r.ok && r.hasReport) ? 0 : 1);
