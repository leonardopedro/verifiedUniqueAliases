#!/usr/bin/env node
// check-relay-targets.mjs — keep committed configs, the example and the docs
// saying the same thing about `services.tls_proxy.relay_targets`.
//
// Why this exists: relay targets are an egress boundary that the docs promise
// are "validated and fail the boot". A config can be perfectly valid to the
// encoder and still be a lie in the repository — the example lists a host the
// docs never mention, a committed config advertises a target nobody documented,
// or the docs' JSON block drifts from the example it claims to show. None of
// those break a build, and all of them mislead the next operator, so they are
// checked here instead of being discovered at boot.
//
// What is compared:
//   * every committed config that sets relay_targets (config*.json), against
//   * docs/tls-proxy.md — both its fenced JSON block (the documented list) and
//     its prose (each name must be mentioned somewhere), and
//   * config.proxy.example.json — the canonical example.
//
// Exit 0 = in agreement, 1 = drift (with the offending entries named).
import { readFileSync, readdirSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join, resolve } from 'path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DOC = join(root, 'docs', 'tls-proxy.md');
const EXAMPLE = join(root, 'config.proxy.example.json');

const failures = [];
function fail(msg) {
  failures.push(msg);
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    fail(`${path}: not valid JSON — ${e.message}`);
    return null;
  }
}

// --- the documented list ----------------------------------------------------
if (!existsSync(DOC)) {
  fail('docs/tls-proxy.md is missing — it is the only place relay targets are described');
}
const doc = existsSync(DOC) ? readFileSync(DOC, 'utf8') : '';

// The documented list is the `relay_targets` array inside the fenced json block
// that configures services.tls_proxy. The docs write that block the way a human
// reads it — an object fragment with `//` annotations — so comments are stripped
// and the fragment is wrapped before parsing. Parsing (rather than regexing the
// array) keeps the comparison honest about ordering and quoting.
function stripLineComments(src) {
  let out = '';
  let inStr = false;
  let esc = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (inStr) {
      out += c;
      if (esc) esc = false;
      else if (c === '\\') esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') {
      inStr = true;
      out += c;
      continue;
    }
    if (c === '/' && src[i + 1] === '/') {
      while (i < src.length && src[i] !== '\n') i++;
      out += '\n';
      continue;
    }
    out += c;
  }
  return out;
}

function parseFragment(block) {
  const clean = stripLineComments(block);
  for (const candidate of [clean, `{${clean}}`]) {
    try {
      return JSON.parse(candidate);
    } catch {
      /* try the wrapped shape next */
    }
  }
  return null;
}

let documented = [];
const blocks = [...doc.matchAll(/```json\n([\s\S]*?)```/g)].map((m) => m[1]);
let parsedDocBlock = null;
for (const block of blocks) {
  const parsed = parseFragment(block);
  const targets = parsed?.services?.tls_proxy?.relay_targets;
  if (Array.isArray(targets)) {
    parsedDocBlock = parsed;
    documented = targets;
    break;
  }
}
if (!parsedDocBlock) {
  fail('docs/tls-proxy.md: no fenced json block documents services.tls_proxy.relay_targets');
}

// --- the example ------------------------------------------------------------
const example = existsSync(EXAMPLE) ? readJson(EXAMPLE) : null;
if (!example) {
  fail('config.proxy.example.json is missing');
}
const exampleTargets = example?.services?.tls_proxy?.relay_targets ?? [];
if (!Array.isArray(exampleTargets) || exampleTargets.length === 0) {
  fail('config.proxy.example.json: services.tls_proxy.relay_targets must be a non-empty array');
}

// Documented list and example must be the same list, same order: the docs
// present the example, so a difference is drift whichever side changed.
if (parsedDocBlock) {
  const a = JSON.stringify(exampleTargets);
  const b = JSON.stringify(documented);
  if (a !== b) {
    fail(
      `docs/tls-proxy.md documents [${documented.join(', ')}] but config.proxy.example.json lists ` +
        `[${exampleTargets.join(', ')}] — update both together`
    );
  }
}

// --- every committed config -------------------------------------------------
const configs = readdirSync(root)
  .filter((f) => /^config.*\.json$/.test(f))
  .sort();
const checked = [];
for (const file of configs) {
  const cfg = readJson(join(root, file));
  if (!cfg) continue;
  const targets = cfg?.services?.tls_proxy?.relay_targets;
  if (!Array.isArray(targets)) continue; // absent = defaults, nothing to describe
  checked.push(file);
  for (const target of targets) {
    if (!documented.includes(target)) {
      fail(`${file}: relay target "${target}" is not in the documented list (docs/tls-proxy.md)`);
    }
    if (!exampleTargets.includes(target)) {
      fail(
        `${file}: relay target "${target}" is not in config.proxy.example.json — ` +
          `the example is what the docs describe, so a config that needs it must update both`
      );
    }
    // Prose mention: the list alone is not enough for a name nobody explains.
    const bare = target.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (!new RegExp(bare).test(doc)) {
      fail(`${file}: relay target "${target}" is never mentioned in docs/tls-proxy.md`);
    }
  }
}

if (failures.length) {
  console.error('❌ relay-target documentation drift:');
  for (const f of failures) console.error('   ' + f);
  process.exit(1);
}

console.log(
  `✅ relay targets in agreement: ${checked.length} config(s) [${checked.join(', ') || 'none'}], ` +
    `${documented.length} documented [${documented.join(', ')}]`
);
