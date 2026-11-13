// Logged-in end-to-end for the BROWSER notarisation path: a real PayPal sandbox
// login, then a TLSNotary session driven from the extension's Notary page, then
// the signed record fetched straight from the notary.
//
// What this proves that the enclave-side e2e cannot: the prover runs in the
// user's browser, the cookies come from the browser's own cookie store, and the
// record published at /proxy/attestations reveals only the chosen ranges. It is
// the check behind "no CLI is needed": nothing here types a tlsn command, it
// clicks the same page a user would.
//
// It is deliberately built on the DevTools protocol with Node built-ins only —
// no npm install — because the extension needs a Chromium launched with
// --load-extension, and Playwright's bundled *headless shell* cannot load
// extensions at all (see HANDOVER 0.61). Set CHROMIUM_PATH to a full Chromium.
//
// Usage:
//   CHROMIUM_PATH=$(command -v chromium) node scripts/e2e-login-notarize.mjs
//   CHROMIUM_PATH=... EXT_BUILD=../primus-kaito/build ATTEST_PATH=/myaccount/summary \
//     node scripts/e2e-login-notarize.mjs
//
// Env:
//   CHROMIUM_PATH  full Chromium binary (default: `chromium` on PATH)
//   EXT_BUILD      unpacked extension build dir (default: ../primus-kaito/build)
//   NOTARY_WS      session WebSocket (default: ws://101.200.178.251:8443/ — the
//                  EIP, because ws://login.airma.de:8443 is answered by the ICP
//                  interceptor; HANDOVER 0.65)
//   NOTARY_ORIGIN  where records are read from (default: https://login.airma.de)
//   ATTEST_HOST    host to notarise (default: www.sandbox.paypal.com)
//   ATTEST_PATH    path that answers 200 while logged in (default:
//                  /myaccount/summary — `/` is a 302 and cannot carry a needle)
//   PPEMAIL/PPPASS PayPal sandbox user (default: the project test buyer)
//   MODES          comma list of reveal modes to exercise
//                  (default: headers,match,all)
//   NEEDLE         search string for the match mode (default: User-agent — a
//                  REQUEST header on purpose: it only became usable once the
//                  match search covered the request too)
//   KEEP_PROFILE   keep the throwaway browser profile for debugging
//
// Exit code 0 = login completed, cookies were forwarded, every mode produced a
// signed record, and no credential reached the revealed request. 1 = an
// assertion failed (the failing one is named). 2 = the environment is unusable
// (no Chromium, no extension build).
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CHROMIUM = process.env.CHROMIUM_PATH || 'chromium';
const BUILD = process.env.EXT_BUILD
  || new URL('../../primus-kaito/build', import.meta.url).pathname;
const NOTARY_WS = process.env.NOTARY_WS || 'ws://101.200.178.251:8443/';
const NOTARY_ORIGIN = (process.env.NOTARY_ORIGIN || 'https://login.airma.de').replace(/\/+$/, '');
const HOST = process.env.ATTEST_HOST || 'www.sandbox.paypal.com';
const PATH = process.env.ATTEST_PATH || '/myaccount/summary';
const EMAIL = process.env.PPEMAIL || 'sb-fuobx47090577@personal.example.com';
const PASSWORD = process.env.PPPASS || '4&itWr>M';
const MODES = (process.env.MODES || 'headers,match,all').split(',').map((m) => m.trim()).filter(Boolean);
const NEEDLE = process.env.NEEDLE || 'User-agent';
const PORT = Number(process.env.CDP_PORT || 9336);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log(...a);

if (!existsSync(join(BUILD, 'manifest.json'))) {
  console.error(`no extension build at ${BUILD} — build ../primus-kaito first (npm run build)`);
  process.exit(2);
}

const failures = [];
const check = (ok, what) => {
  log(`  ${ok ? 'ok  ' : 'FAIL'} ${what}`);
  if (!ok) failures.push(what);
};

/** Minimal DevTools client: one WebSocket, promise per command id. */
class CDP {
  constructor(url) {
    this.ws = new WebSocket(url);
    this.id = 0;
    this.pending = new Map();
    this.ready = new Promise((res, rej) => {
      this.ws.onopen = () => res();
      this.ws.onerror = () => rej(new Error('the DevTools socket refused to open'));
    });
    this.ws.onmessage = (ev) => {
      const m = JSON.parse(ev.data);
      const slot = m.id && this.pending.get(m.id);
      if (!slot) return;
      this.pending.delete(m.id);
      m.error ? slot.rej(new Error(JSON.stringify(m.error))) : slot.res(m.result);
    };
  }

  send(method, params = {}) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((res, rej) => this.pending.set(id, { res, rej }));
  }

  async evaluate(expression) {
    const r = await this.send('Runtime.evaluate', {
      expression,
      returnByValue: true,
      userGesture: true,
      awaitPromise: true,
    });
    if (r.exceptionDetails) {
      throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
    }
    return r.result.value;
  }

  async open(url) {
    const target = await (await fetch(`http://127.0.0.1:${PORT}/json/new?${encodeURI(url)}`, {
      method: 'PUT',
    })).json();
    const client = new CDP(target.webSocketDebuggerUrl);
    await client.ready;
    await client.send('Page.enable');
    return client;
  }

  close() {
    try { this.ws.close(); } catch { /* already gone */ }
  }
}

const profile = mkdtempSync(join(tmpdir(), 'notarize-e2e-'));
const chrome = spawn(CHROMIUM, [
  '--headless=new',
  '--no-sandbox',
  '--disable-gpu',
  '--disable-dev-shm-usage',
  '--window-size=1280,900',
  `--user-data-dir=${profile}`,
  `--remote-debugging-port=${PORT}`,
  `--disable-extensions-except=${BUILD}`,
  `--load-extension=${BUILD}`,
  '--no-first-run',
  '--no-default-browser-check',
  '--lang=en-US',
  'about:blank',
], { stdio: 'ignore' });

let browser, loginPage, notaryPage;

try {
  let version;
  for (let i = 0; i < 120 && !version; i++) {
    try {
      version = await (await fetch(`http://127.0.0.1:${PORT}/json/version`)).json();
    } catch {
      await sleep(500);
    }
  }
  if (!version) throw new Error(`Chromium never opened a DevTools port on ${PORT}`);

  browser = new CDP(version.webSocketDebuggerUrl);
  await browser.ready;

  let extensionId = null;
  for (let i = 0; i < 40 && !extensionId; i++) {
    const { targetInfos } = await browser.send('Target.getTargets');
    const hit = targetInfos.find((t) => t.url?.startsWith('chrome-extension://'));
    if (hit) extensionId = new URL(hit.url).host;
    else await sleep(500);
  }
  if (!extensionId) throw new Error('the extension did not register a target — is the build complete?');
  log(`extension ${extensionId}, profile ${profile}`);

  // ---- 1. a real sandbox login in the same browser profile -----------------
  loginPage = await browser.open('about:blank');
  await loginPage.send('Page.navigate', { url: `https://${HOST}/signin` });

  const typeInto = async (id, text) => {
    const found = await loginPage.evaluate(
      `(() => { const n = document.getElementById(${JSON.stringify(id)}); if (!n) return false; n.focus(); return true; })()`
    );
    if (!found) return false;
    for (const ch of text) {
      await loginPage.send('Input.dispatchKeyEvent', { type: 'char', text: ch });
      await sleep(25);
    }
    return true;
  };
  const click = (id) => loginPage.evaluate(
    `(() => { const n = document.getElementById(${JSON.stringify(id)}); if (!n) return false; n.click(); return true; })()`
  );

  for (let i = 0; i < 60; i++) {
    if (await loginPage.evaluate(
      `!!document.getElementById('email') || !!document.getElementById('password')`
    )) break;
    await sleep(1000);
  }
  if (await loginPage.evaluate(`!!document.getElementById('email')`)) {
    await typeInto('email', EMAIL);
    await click('btnNext');
    await sleep(2500);
  }
  if (!await typeInto('password', PASSWORD)) throw new Error('the sign-in form never rendered a password field');
  await click('btnLogin');

  let landed = '';
  for (let i = 0; i < 60; i++) {
    landed = await loginPage.evaluate('location.href');
    if (landed && !/\/signin/.test(landed)) break;
    await sleep(1000);
  }
  log(`logged in, landed on ${landed}`);
  check(!/\/signin/.test(landed) && /^https:/.test(landed), 'login left /signin');

  // ---- 2. drive the extension's Notary page, exactly as a user would ------
  notaryPage = await browser.open(`chrome-extension://${extensionId}/notary.html`);
  await sleep(2500);

  const jar = await notaryPage.evaluate(
    `chrome.cookies.getAll({ url: 'https://${HOST}/' }).then((cs) => cs.map((c) => ({ name: c.name, value: c.value })))`
  );
  const distinctive = jar.filter((c) => c.value && c.value.length > 6);
  log(`cookies readable for ${HOST}: ${jar.length}`);
  check(jar.length > 0, 'the extension can read the logged-in cookie jar');

  async function notarize(reveal) {
    await notaryPage.evaluate(`(() => {
      document.getElementById('host').value = ${JSON.stringify(HOST)};
      document.getElementById('path').value = ${JSON.stringify(PATH)};
      document.getElementById('notary').value = ${JSON.stringify(NOTARY_WS)};
      document.getElementById('useCookies').checked = true;
      const sel = document.getElementById('reveal');
      sel.value = ${JSON.stringify(reveal.mode)};
      sel.dispatchEvent(new Event('change'));
      document.getElementById('needle').value = ${JSON.stringify(reveal.needle || '')};
      document.getElementById('log').innerText = '';
      document.getElementById('run').click();
      return true;
    })()`);

    let text = '';
    for (let i = 0; i < 240; i++) {
      await sleep(1000);
      text = await notaryPage.evaluate(`document.getElementById('log').innerText`);
      if (/signed record found|signed record:|none accepts this transcript|failed:/.test(text)) break;
    }
    const link = await notaryPage.evaluate(`document.querySelector('#resultLink a')?.href || ''`);
    return {
      text,
      link,
      sent: /notarised (\d+) byte/.exec(text)?.[1],
      revealed: /revealed (\d+) request and (\d+) response/.exec(text),
    };
  }

  // ---- 3. every mode: a signed record, and only the chosen ranges ---------
  for (const mode of MODES) {
    log(`\n=== reveal=${mode}${mode === 'match' ? ` needle=${JSON.stringify(NEEDLE)}` : ''} ===`);
    const reveal = mode === 'match' ? { mode, needle: NEEDLE } : { mode };
    let run = await notarize(reveal);
    // The PayPal edge closes some handshakes outright (HANDOVER 0.55/0.61); a
    // refusal is not a notary fault, so retry before judging the mode.
    for (let attempt = 1; attempt <= 3 && /failed:/.test(run.text) && !/signed record/.test(run.text); attempt++) {
      const why = (/(failed:.*)/.exec(run.text) || [])[1] || 'failed';
      log(`  retry ${attempt} after: ${why.slice(0, 120)}`);
      await sleep(4000);
      run = await notarize(reveal);
    }
    for (const line of run.text.split('\n')) {
      if (/sending \d|notarised|revealed \d|warning|withheld|record|failed/.test(line)) {
        log(`  | ${line.trim()}`);
      }
    }
    check(/signed record found/.test(run.text), `${mode}: the notary published a signed record for this session`);
    if (!run.link) continue;

    const record = await (await fetch(run.link)).json();
    const sent = Buffer.from(record.sent_b64, 'base64');
    const recv = Buffer.from(record.received_b64, 'base64');
    const sentText = sent.toString('latin1');
    const recvText = recv.toString('latin1');
    const leaked = distinctive.filter((c) => sentText.includes(c.value)).map((c) => c.name);
    // Withheld bytes are zero-filled rather than dropped, so collapse the runs
    // before printing or the line-length numbers bury the evidence.
    const disclosedRequestLines = sentText
      .split('\r\n')
      .slice(0, 6)
      .map((line) => line.replace(/\u0000+/g, (run) => `<zeroed ${run.length}B>`));

    log(`  record ${record.session_id}: ${record.sent_len} sent / ${record.received_len} received`);
    log(`  request lines disclosed: ${JSON.stringify(disclosedRequestLines)}`);

    check(record.sent_len === sent.length && record.received_len === recv.length,
      `${mode}: the record's declared lengths match the transcripts it serves`);
    check(/^HTTP\/1\.1 200/.test(recvText), `${mode}: the target answered 200 (a logged-in page)`);
    check(!/\bcookie:/i.test(sentText), `${mode}: no cookie header in the revealed request`);
    check(leaked.length === 0, `${mode}: no live cookie value in the revealed request${leaked.length ? ` (${leaked})` : ''}`);
    if (mode !== 'all') {
      check(sentText.includes('\u0000'), `${mode}: the withheld request bytes are zero-filled, not dropped`);
    }
    // The response may legitimately echo a preference cookie into its own HTML
    // (PayPal sends ts_c/LANG straight back), so only the request is judged.
    if (mode === 'match') {
      log(`  ${/warning: the response does not contain/.test(run.text)
        ? 'note: the needle was request-only and the warning fired'
        : 'note: the needle matched inside the response'}`);
    }
  }
} catch (error) {
  failures.push(error?.message || String(error));
  console.error(`\nHARNESS ERROR: ${error?.message || error}`);
} finally {
  try { notaryPage?.close(); } catch { /* gone */ }
  try { loginPage?.close(); } catch { /* gone */ }
  try { browser?.close(); } catch { /* gone */ }
  chrome.kill('SIGKILL');
  if (!process.env.KEEP_PROFILE) {
    await sleep(500);
    try { rmSync(profile, { recursive: true, force: true }); } catch { /* best effort */ }
  }
}

if (failures.length) {
  console.error(`\n${failures.length} check(s) FAILED:`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
log('\nPASS — logged-in session notarised through the extension; records disclose only the chosen ranges.');
