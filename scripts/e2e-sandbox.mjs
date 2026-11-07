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
// Usage:
//   node scripts/e2e-sandbox.mjs [verified|full|both]
//
// Env:
//   PPEMAIL / PPPASS — PayPal sandbox account (defaults in the flow script)
//   CHROMIUM_PATH    — system Chromium (playwright's own build needs distro libs)
//
// Outputs:
//   /tmp/report-<flow>.json  — decrypted report, usable as REAL_REPORT
//   /tmp/claimed-report.json — the flow script's own copy (last flow wins)
import { spawnSync } from 'child_process';
import { copyFileSync, existsSync } from 'fs';

const arg = (process.argv[2] || 'both').toLowerCase();
const FLOWS = arg === 'both' ? ['verified', 'full'] : [arg === 'full' ? 'full' : 'verified'];
const log = (...a) => console.log(...a);

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
