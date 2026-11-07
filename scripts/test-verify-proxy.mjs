// Functional tests for verify-proxy.html — the REAL page script is evaluated
// (indirect eval) and its audit function is driven with attestations signed by
// a real RSA-2048 key, exactly the way tls-proxy/src/main.rs signs them.
//
// The point of these tests is the property the page claims: the signature is
// checked over the bytes the enclave signed, so ANY change to a field — a
// digest, a length, the server name, the order, a duplicate key — must fail,
// and re-formatting (which changes whitespace but not bytes of the values) must
// still verify through the documented minified fallback.
//
// Usage: node scripts/test-verify-proxy.mjs
import { readFileSync, writeFileSync, mkdtempSync } from 'fs';
import { spawnSync } from 'child_process';
import { tmpdir } from 'os';
import { join } from 'path';
import { createHash, generateKeyPairSync, sign as rsaSign } from 'crypto';

const repoRoot = new URL('..', import.meta.url).pathname;

// ---- DOM stubs (the audit function is DOM-free; render() is smoke-tested) ---
const elements = {};
function makeEl() {
    const p = { innerHTML: '' };
    return {
        style: {}, innerText: '', innerHTML: '', textContent: '', value: '', className: '',
        querySelector: () => p,
        addEventListener: () => {},
    };
}
globalThis.document = {
    getElementById: (id) => (elements[id] ||= makeEl()),
    addEventListener: () => {},
};
globalThis.FileReader = class {};

let pass = 0, fail = 0;
function check(name, cond, detail) {
    if (cond) { pass++; console.log(`  ✅ ${name}`); }
    else { fail++; console.log(`  ❌ ${name}${detail ? ' — ' + detail : ''}`); }
}

// ---- fixtures -------------------------------------------------------------
const key = generateKeyPairSync('rsa', { modulusLength: 2048 });
const pubPem = key.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const sha = (b) => createHash('sha256').update(b).digest();
const hashOf = (b) => sha(Buffer.from(b)).toString('hex');

const SENT = 'GET / HTTP/1.1\r\nHost: test-server.io\r\n\r\n';
const RECV = 'HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world';

// Mirrors tls-proxy/src/main.rs SignedBody field order.
function buildAttestation(over = {}) {
    const body = {
        version: 'tls-proxy/1',
        session_id: 'a'.repeat(32),
        server_name: 'test-server.io',
        notarized_at: 1793932800,
        sent_len: Buffer.byteLength(SENT),
        received_len: Buffer.byteLength(RECV),
        sent_sha256: hashOf(SENT),
        received_sha256: hashOf(RECV),
        sent_b64: Buffer.from(SENT).toString('base64'),
        received_b64: Buffer.from(RECV).toString('base64'),
        truncated: false,
    };
    Object.assign(body, over.fields || {});
    const signed = JSON.stringify(body);
    let sig = rsaSign('sha256', Buffer.from(signed), key.privateKey);
    if (over.tamperSignature) { sig = Buffer.from(sig); sig[7] ^= 0xff; }
    const doc = JSON.parse(signed);
    doc.enclave_pubkey_pem = over.pubPem || pubPem;
    doc.signature_alg = 'RSA-PKCS1-v1_5-SHA256';
    doc.signature_b64 = sig.toString('base64');
    return { doc, signed, text: JSON.stringify(doc) };
}

// ---- load the page script -------------------------------------------------
const html = readFileSync(join(repoRoot, 'verify-proxy.html'), 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
check('page has exactly one inline script (no CDN to trust)', scripts.length === 1, `found ${scripts.length}`);
check('page references no external resources', !/<script[^>]+src=|<link[^>]+href="https?:/.test(html));

const dir = mkdtempSync(join(tmpdir(), 'verify-proxy-'));
const scriptPath = join(dir, 'page.js');
writeFileSync(scriptPath, scripts[0]);
{
    const r = spawnSync(process.execPath, ['--check', scriptPath], { encoding: 'utf8' });
    check('extracted script passes node --check', r.status === 0, (r.stderr || '').split('\n')[0]);
}
// const/let stay in the eval's lexical scope, so hand the bindings back explicitly.
const api = (0, eval)(scripts[0] + '\n;({ SIGNED_FIELDS, SIGNED_FIELD_COUNT, auditAttestation, renderAudit })');
const { SIGNED_FIELDS, SIGNED_FIELD_COUNT, auditAttestation, renderAudit } = api;

console.log('\nTest 0: signed-field list matches the page constants');
check('SIGNED_FIELDS has 11 entries', SIGNED_FIELDS.length === 11, String(SIGNED_FIELDS.length));
check('SIGNED_FIELD_COUNT agrees', SIGNED_FIELD_COUNT === SIGNED_FIELDS.length);

console.log('\nTest 1: honest attestation → everything verifies');
let honest;
{
    const built = buildAttestation();
    honest = built;
    const res = await auditAttestation(built.text);
    const byId = Object.fromEntries(res.rows.map(r => [r.id, r.state]));
    check('ok', res.ok === true, JSON.stringify(res.rows.filter(r => r.state === false)));
    check('signature verified', byId.signature === true);
    check('request digest verified', byId.sentDigest === true);
    check('response digest verified', byId.recvDigest === true);
    check('server name accepted', byId.name === true);
    check('signed bytes are exactly the ten+one fields',
        res.signedText === built.signed, res.signedText.slice(0, 80));
    check('key-binding row is a warning, not a pass', byId.binding === 'warning');
    check('transcript decoded', res.transcript.includes('hello world'));
    check('render() runs against a DOM', (() => { renderAudit(res); return true; })());
}

console.log('\nTest 2: modified transcript bytes → digest fails');
{
    const text = honest.text.replace(
        Buffer.from(RECV).toString('base64'),
        Buffer.from(RECV.replace('hello world', 'hello w0rld')).toString('base64'),
    );
    const res = await auditAttestation(text);
    const byId = Object.fromEntries(res.rows.map(r => [r.id, r.state]));
    check('ok false', res.ok === false);
    check('signature fails (bytes changed)', byId.signature === false, String(byId.signature));
    check('response digest fails', byId.recvDigest === false);
}

console.log('\nTest 3: re-signed but altered server name → signature fails on the ORIGINAL bytes only');
{
    const built = buildAttestation();
    const text = built.text.replace('test-server.io', 'evil.example');
    const res = await auditAttestation(text);
    const byId = Object.fromEntries(res.rows.map(r => [r.id, r.state]));
    check('ok false', res.ok === false);
    check('signature fails', byId.signature === false);
}

console.log('\nTest 4: pretty-printed input still verifies (whitespace is not signed)');
{
    const pretty = JSON.stringify(JSON.parse(honest.text), null, 2);
    const res = await auditAttestation(pretty);
    const byId = Object.fromEntries(res.rows.map(r => [r.id, r.state]));
    check('ok', res.ok === true, String(byId.signature));
    check('mode reports minified fallback', res.mode === 'minified', res.mode);
    check('bytes row explains the reformatting',
        res.rows.find(r => r.id === 'bytes').desc.includes('re-formatted'));
}

console.log('\nTest 5: reordered fields rejected before any crypto');
{
    const doc = JSON.parse(honest.text);
    const reordered = {};
    for (const k of ['session_id', 'version', ...Object.keys(doc).filter(k => k !== 'session_id' && k !== 'version')]) {
        reordered[k] = doc[k];
    }
    const res = await auditAttestation(JSON.stringify(reordered));
    check('ok false', res.ok === false);
    check('shape row failed', res.rows.find(r => r.id === 'shape').state === false);
}

console.log('\nTest 6: duplicate key rejected');
{
    const text = honest.text.replace('{"version"', '{"version":"tls-proxy/1","version"');
    const res = await auditAttestation(text);
    check('ok false', res.ok === false);
    const shape = res.rows.find(r => r.id === 'shape');
    check('duplicate named', /duplicate keys: version/.test(shape.desc), shape.desc);
}

console.log('\nTest 7: wrong public key → signature fails');
{
    const other = generateKeyPairSync('rsa', { modulusLength: 2048 })
        .publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const res = await auditAttestation(buildAttestation({ pubPem: other }).text);
    const byId = Object.fromEntries(res.rows.map(r => [r.id, r.state]));
    check('ok false', res.ok === false);
    check('signature fails', byId.signature === false);
}

console.log('\nTest 8: corrupted signature → signature fails');
{
    const res = await auditAttestation(buildAttestation({ tamperSignature: true }).text);
    check('ok false', res.ok === false);
    check('signature fails', res.rows.find(r => r.id === 'signature').state === false);
}

console.log('\nTest 9: lying lengths / digests are caught');
{
    const res = await auditAttestation(buildAttestation({
        fields: { sent_len: 9999, received_sha256: 'f'.repeat(64) },
    }).text);
    const byId = Object.fromEntries(res.rows.map(r => [r.id, r.state]));
    check('ok false', res.ok === false);
    check('request length mismatch surfaced', byId.sentDigest === false);
    check('response digest mismatch surfaced', byId.recvDigest === false);
}

console.log('\nTest 10: wrong signature_alg → fail closed');
{
    const text = honest.text.replace('RSA-PKCS1-v1_5-SHA256', 'RSA-PSS-SHA256');
    const res = await auditAttestation(text);
    check('ok false', res.ok === false);
    check('reason names the algorithm',
        /expected RSA-PKCS1-v1_5-SHA256/.test(res.rows.find(r => r.id === 'signature').desc));
}

console.log('\nTest 11: hostname guards');
{
    const bad = async (name) => {
        const res = await auditAttestation(buildAttestation({ fields: { server_name: name } }).text);
        return res.rows.find(r => r.id === 'name');
    };
    check('bare IP literal rejected', (await bad('203.0.113.9')).state === false);
    check('host:port rejected', (await bad('example.com:8443')).state === false);
    check('scheme/path rejected', (await bad('https://example.com/x')).state === false);
    check('multi-label name accepted', (await bad('api.example.co.uk')).state === true);
}

console.log('\nTest 12: markup in fields is escaped, never injected');
{
    const hostile = buildAttestation({ fields: { server_name: '"><img src=x onerror=window.__pwned=1>' } });
    const res = await auditAttestation(hostile.text);
    renderAudit(res);
    const htmlOut = elements['rows'] ? elements['rows'].innerHTML : '';
    check('no raw <img> in the rendered verdict', !/<img/i.test(htmlOut), htmlOut.slice(0, 160));
    check('hostile name is escaped', htmlOut.includes('&lt;img'), htmlOut.slice(0, 160));
}

console.log('\nTest 13: not-JSON and non-object inputs fail closed');
{
    const r1 = await auditAttestation('not json');
    check('garbage rejected', r1.ok === false && r1.rows[0].id === 'parse');
    const r2 = await auditAttestation('[1,2,3]');
    check('array rejected', r2.ok === false);
    const r3 = await auditAttestation('{}');
    check('empty object rejected', r3.ok === false && r3.rows[0].id === 'shape');
}

console.log(`\n${fail === 0 ? '✅ all checks passed' : '❌ failures'}: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
