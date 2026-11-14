// Logged-in end-to-end for the MINIMAL (cookie-blind) extension variant.
//
// Unlike e2e-login-notarize.mjs, this harness never calls chrome.cookies:
// the minimal extension has no cookie permission. Instead it reads the session
// cookie from the PayPal page's own document.cookie (exactly what a user copies
// from devtools) and pastes it into the Notary page's textarea. This exercises
// the manual-paste path exclusively.
//
// Usage:
//   CHROMIUM_PATH=$(command -v chromium) node scripts/e2e-minimal-notary.mjs
//   CHROMIUM_PATH=... EXT_BUILD=../primus-kaito/minimal-notary ATTEST_PATH=/myaccount/summary \\
//     node scripts/e2e-minimal-notary.mjs
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CHROMIUM = process.env.CHROMIUM_PATH || 'chromium';
const BUILD = process.env.EXT_BUILD
  || new URL('../../primus-kaito/minimal-notary', import.meta.url).pathname;
const NOTARY_WS = process.env.NOTARY_WS || 'ws://101.200.178.251:8443/';
const NOTARY_ORIGIN = (process.env.NOTARY_ORIGIN || 'https://login.airma.de').replace(/\/+$/, '');
const HOST = process.env.ATTEST_HOST || 'www.sandbox.paypal.com';
const PATH = process.env.ATTEST_PATH || '/myaccount/summary';
const EMAIL = process.env.PPEMAIL || 'sb-fuobx47090577@personal.example.com';
const PASSWORD = process.env.PPPASS || '4&itWr>M';
const MODES = (process.env.MODES || 'headers,match,all').split(',').map((m) => m.trim()).filter(Boolean);
const NEEDLE = process.env.NEEDLE || 'User-agent';
const PORT = Number(process.env.CDP_PORT || 9337);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (...a) => console.log(...a);

if (!existsSync(join(BUILD, 'manifest.json'))) {
  console.error(`no extension build at ${BUILD}`);
  process.exit(2);
}

const failures = [];
const check = (ok, what) => {
  log(`  ${ok ? 'ok  ' : 'FAIL'} ${what}`);
  if (!ok) failures.push(what);
};

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
    const r = await this.send('Runtime.evaluate', { expression, returnByValue: true, userGesture: true, awaitPromise: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
    return r.result.value;
  }
  async open(url) {
    const target = await (await fetch(`http://127.0.0.1:${PORT}/json/new?${encodeURI(url)}`, { method: 'PUT' })).json();
    const client = new CDP(target.webSocketDebuggerUrl);
    await client.ready;
    await client.send('Page.enable');
    return client;
  }
  close() { try { this.ws.close(); } catch { /* already gone */ } }
}

const profile = mkdtempSync(join(tmpdir(), 'minimal-notary-e2e-'));
const chrome = spawn(CHROMIUM, [
  '--headless=new', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage',
  '--window-size=1280,900', `--user-data-dir=${profile}`,
  `--remote-debugging-port=${PORT}`,
  `--disable-extensions-except=${BUILD}`, `--load-extension=${BUILD}`,
  '--no-first-run', '--no-default-browser-check', '--lang=en-US', 'about:blank',
], { stdio: 'ignore' });

let browser, loginPage, notaryPage;
try {
  let version;
  for (let i = 0; i < 120 && !version; i++) {
    try { version = await (await fetch(`http://127.0.0.1:${PORT}/json/version`)).json(); }
    catch { await sleep(500); }
  }
  if (!version) throw new Error(`Chromium never opened a DevTools port on ${PORT}`);
  browser = new CDP(version.webSocketDebuggerUrl);
  await browser.ready;

  let extensionId = null;
  for (let i = 0; i < 40 && !extensionId; i++) {
    const { targetInfos } = await browser.send('Target.getTargets');
    const hit = targetInfos.find((t) => t.type === 'service_worker' && t.url?.startsWith('chrome-extension://'));
    if (hit) extensionId = new URL(hit.url).host;
    else await sleep(500);
  }
  if (!extensionId) throw new Error('the extension did not register a target');
  log(`extension ${extensionId}, profile ${profile}`);

  // ---- 1. real sandbox login -------------------------------------------
  loginPage = await browser.open('about:blank');
  await loginPage.send('Page.navigate', { url: `https://${HOST}/signin` });
  const typeInto = async (id, text) => {
    const found = await loginPage.evaluate(`(() => { const n = document.getElementById(${JSON.stringify(id)}); if (!n) return false; n.focus(); return true; })()`);
    if (!found) return false;
    for (const ch of text) { await loginPage.send('Input.dispatchKeyEvent', { type: 'char', text: ch }); await sleep(25); }
    return true;
  };
  const click = (id) => loginPage.evaluate(`(() => { const n = document.getElementById(${JSON.stringify(id)}); if (!n) return false; n.click(); return true; })()`);

  for (let i = 0; i < 60; i++) {
    if (await loginPage.evaluate(`!!document.getElementById('email') || !!document.getElementById('password')`)) break;
    await sleep(1000);
  }
  if (await loginPage.evaluate(`!!document.getElementById('email')`)) {
    await typeInto('email', EMAIL);
    await click('btnNext');
    await sleep(2500);
  }
  if (!await typeInto('password', PASSWORD)) throw new Error('no password field');
  await click('btnLogin');
  let landed = '';
  for (let i = 0; i < 60; i++) {
    landed = await loginPage.evaluate('location.href');
    if (landed && !/\/signin/.test(landed)) break;
    await sleep(1000);
  }
  log(`logged in, landed on ${landed}`);
  check(!/\/signin/.test(landed) && /^https:/.test(landed), 'login left /signin');

  // Obtain the FULL cookie header including HttpOnly cookies, the way a user
  // copies it from the Network tab (document.cookie excludes HttpOnly, which
  // would make the session anonymous). Use CDP Network.getCookies.
  await loginPage.send('Network.enable');
  const cookieRes = await loginPage.send('Network.getCookies', { urls: [`https://${HOST}/`] });
  const cookies = cookieRes.cookies || [];
  const cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join('; ');
  const distinctive = cookies.filter((c) => c.value && c.value.length > 6);
  log(`cookies available for ${HOST}: ${cookies.length} (via CDP, incl. HttpOnly)`);
  check(cookies.length > 0, 'the logged-in session has cookies');

  // ---- 2. drive the Notary page ---------------------------------------
  notaryPage = await browser.open(`chrome-extension://${extensionId}/notary.html`);
  await sleep(2500);

  async function notarize(reveal) {
    await notaryPage.evaluate(`(() => {
      document.getElementById('host').value = ${JSON.stringify(HOST)};
      document.getElementById('path').value = ${JSON.stringify(PATH)};
      document.getElementById('notary').value = ${JSON.stringify(NOTARY_WS)};
      const ta = document.getElementById('manualCookie');
      ta.value = ${JSON.stringify(cookieHeader)};
      ta.dispatchEvent(new Event('input'));
      ta.dispatchEvent(new Event('change'));
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
    return { text, link, sent: /notarised (\\d+) byte/.exec(text)?.[1] };
  }

  // ---- 3. every mode ---------------------------------------------------
  for (const mode of MODES) {
    log(`\n=== reveal=${mode}${mode === 'match' ? ` needle=${JSON.stringify(NEEDLE)}` : ''} ===`);
    const reveal = mode === 'match' ? { mode, needle: NEEDLE } : { mode };
    let run = await notarize(reveal);
    for (let attempt = 1; attempt <= 3 && /failed:/.test(run.text) && !/signed record/.test(run.text); attempt++) {
      const why = (/(failed:.*)/.exec(run.text) || [])[1] || 'failed';
      log(`  retry ${attempt} after: ${why.slice(0, 120)}`);
      await sleep(4000);
      run = await notarize(reveal);
    }
    for (const line of run.text.split('\n')) {
      if (/using a pasted|notarised|revealed \d|warning|withheld|record|failed/.test(line)) log(`  | ${line.trim()}`);
    }
    check(/using a pasted Cookie header/.test(run.text), `${mode}: the manual cookie-paste path was used`);
    check(/signed record found/.test(run.text), `${mode}: the notary published a signed record`);
    if (!run.link) continue;

    const record = await (await fetch(run.link)).json();
    const sent = Buffer.from(record.sent_b64, 'base64');
    const recv = Buffer.from(record.received_b64, 'base64');
    const sentText = sent.toString('latin1');
    const recvText = recv.toString('latin1');
    const leaked = distinctive.filter((c) => sentText.includes(c.value)).map((c) => c.name);

    log(`  record ${record.session_id}: ${record.sent_len} sent / ${record.received_len} received`);
    const disclosed = sentText.split('\r\n').slice(0, 6)
      .map((l) => l.replace(/\u0000+/g, (r) => `<zeroed ${r.length}B>`));
    log(`  request lines disclosed: ${JSON.stringify(disclosed)}`);

    check(record.sent_len === sent.length && record.received_len === recv.length, `${mode}: lengths match`);
    check(/^HTTP\/1\.1 200/.test(recvText), `${mode}: target answered 200`);
    check(!/\bcookie:/i.test(sentText), `${mode}: no cookie header in revealed request`);
    check(leaked.length === 0, `${mode}: no live cookie value in revealed request${leaked.length ? ` (${leaked})` : ''}`);
    if (mode !== 'all') check(sentText.includes('\u0000'), `${mode}: withheld bytes zero-filled`);
    if (mode === 'match') {
      log(`  ${/warning: the response does not contain/.test(run.text) ? 'note: needle was request-only, warning fired' : 'note: needle matched in response'}`);
    }
  }
} catch (error) {
  failures.push(error?.message || String(error));
  console.error(`\nHARNESS ERROR: ${error?.message || error}`);
} finally {
  try { notaryPage?.close(); } catch {}
  try { loginPage?.close(); } catch {}
  try { browser?.close(); } catch {}
  chrome.kill('SIGKILL');
  if (!process.env.KEEP_PROFILE) {
    await sleep(500);
    try { rmSync(profile, { recursive: true, force: true }); } catch {}
  }
}

if (failures.length) {
  console.error(`\n${failures.length} check(s) FAILED:`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
log(`\nPASS — minimal (cookie-blind) extension notarised a logged-in session via manual paste; records disclose only chosen ranges.`);