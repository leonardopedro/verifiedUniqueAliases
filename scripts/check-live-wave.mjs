#!/usr/bin/env node
// check-live-wave.mjs — run N simultaneous live prover sessions against the
// deployed notary and report each one, so "the notary survives a burst" is a
// number instead of an anecdote.
//
// Why this exists: a single `cargo test --test live` proves the relay works when
// nobody else is asking. The failure mode that actually bit PayPal's edge is
// width — the notary's dial spacing, the commit bound and the retry hint only
// matter when several provers arrive at once, and the measurements in
// docs/tls-proxy.md (4-wide 12/12, 8-wide 3/8 and 5/8, 8 spaced 1.5 s apart
// 8/8) were taken with throwaway shell loops. Those loops are why a `host/path`
// in LIVE_SERVER used to fail as `invalid DNS name`, and why nobody could rerun
// the numbers. This is the same burst, kept.
//
// It does NOT rebuild per slot: `cargo test --no-run --message-format=json`
// gives the compiled `tests/live` executable once, and every slot spawns that
// binary directly with `--ignored --nocapture` (the cargo lock would otherwise
// serialise the slots and measure nothing).
//
// Usage:
//   node scripts/check-live-wave.mjs                       # 8-wide, api-m.paypal.com
//   node scripts/check-live-wave.mjs --width 4 --target www.sandbox.paypal.com
//   node scripts/check-live-wave.mjs --target api-m.paypal.com --attempts 2
//   node scripts/check-live-wave.mjs --spacing 1500        # stagger starts (ms)
//   node scripts/check-live-wave.mjs --binary tls-proxy/target/debug/deps/live-…  # skip the build
//
// Knobs (flags win over env): WAVE_WIDTH, LIVE_SERVER/WAVE_TARGET, LIVE_NOTARY,
// LIVE_ATTEMPTS, WAVE_SPACING (ms), WAVE_TIMEOUT (s, per slot), WAVE_CA_BUNDLE,
// and WAVE_BINARY (an already-built `tests/live` executable — use it where cargo
// cannot link, e.g. a NixOS host with a mismatched openssl, after building the
// binary in the project's podman image).
//
// Exit 0 = every slot got a verdict, 1 = at least one slot failed (the reason
// and the notary's own sentence are printed per slot), 2 = the harness itself
// could not run (build failure, missing binary).

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, resolve, join } from 'path';
import { existsSync } from 'fs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const MANIFEST = join(root, 'tls-proxy', 'Cargo.toml');

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) {
      out[key] = true;
    } else {
      out[key] = next;
      i++;
    }
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
const width = Number(args.width ?? process.env.WAVE_WIDTH ?? 8);
const target = args.target ?? process.env.WAVE_TARGET ?? process.env.LIVE_SERVER ?? 'api-m.paypal.com';
const notary = args.notary ?? process.env.LIVE_NOTARY ?? '101.200.178.251:8443';
const attempts = String(args.attempts ?? process.env.LIVE_ATTEMPTS ?? 1);
const spacingMs = Number(args.spacing ?? process.env.WAVE_SPACING ?? 0);
const timeoutS = Number(args.timeout ?? process.env.WAVE_TIMEOUT ?? 180);
const caBundle = args['ca-bundle'] ?? process.env.WAVE_CA_BUNDLE ?? process.env.LIVE_CA_BUNDLE;

if (!Number.isInteger(width) || width < 1 || width > 64) {
  console.error(`❌ --width must be 1..64, got ${args.width ?? width}`);
  process.exit(2);
}

function cargoBin() {
  return process.env.CARGO ?? 'cargo';
}

// One build, every slot reuses it. `--message-format=json` keeps cargo's human
// output quiet enough to parse; artifacts are one JSON object per line.
function buildLiveBinary() {
  return new Promise((done, bad) => {
    const p = spawn(cargoBin(), ['test', '--manifest-path', MANIFEST, '--test', 'live', '--no-run', '--message-format=json'], {
      cwd: root,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let buf = '';
    let executable = null;
    const errs = [];
    p.stdout.on('data', (d) => {
      buf += d.toString();
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line.startsWith('{')) continue;
        let msg;
        try {
          msg = JSON.parse(line);
        } catch {
          continue;
        }
        if (msg.reason === 'compiler-artifact' && msg.target?.name === 'live' && msg.executable) {
          executable = msg.executable;
        }
        if (msg.reason === 'build-finished' && msg.success === false) {
          executable = null;
        }
      }
    });
    p.stderr.on('data', (d) => errs.push(d.toString()));
    p.on('close', (code) => {
      if (code !== 0 || !executable) {
        bad(new Error(`cargo test --no-run failed (rc=${code})${errs.length ? `: ${errs.join('').trim().split('\n').slice(-3).join(' | ')}` : ''}`));
      } else {
        done(executable);
      }
    });
  });
}

function runSlot(executable, index) {
  return new Promise((done) => {
    const env = {
      ...process.env,
      LIVE_NOTARY: notary,
      LIVE_SERVER: target,
      LIVE_ATTEMPTS: attempts,
    };
    if (caBundle) env.LIVE_CA_BUNDLE = caBundle;

    const started = Date.now();
    const p = spawn(executable, ['--ignored', '--nocapture', '--exact', 'live_relay_of_a_real_website'], {
      cwd: root,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    const take = (d) => {
      out += d.toString();
      if (out.length > 64000) out = out.slice(-32000);
    };
    p.stdout.on('data', take);
    p.stderr.on('data', take);
    const timer = setTimeout(() => {
      out += `\n--- WAVE: slot ${index} cancelled after ${timeoutS}s\n`;
      p.kill('SIGKILL');
    }, timeoutS * 1000);
    p.on('close', (code) => {
      clearTimeout(timer);
      const seconds = ((Date.now() - started) / 1000).toFixed(1);
      const lines = out.split('\n').map((l) => l.trim()).filter(Boolean);
      const verdict = [...lines].reverse().find((l) => /^--- (passed|attempt .*failed)/.test(l))
        ?? [...lines].reverse().find((l) => /^(response head|transcript|Error)/.test(l))
        ?? lines[lines.length - 1]
        ?? '(no output)';
      const passedOn = lines.filter((l) => l.startsWith('--- passed on attempt')).pop();
      done({
        index,
        ok: code === 0,
        code,
        seconds,
        verdict: verdict.slice(0, 200),
        passedOn: passedOn ? passedOn.replace(/^--- /, '') : null,
      });
    });
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  console.log(`=== wave: ${width} concurrent, target ${target}, notary ${notary}, attempts ${attempts}, spacing ${spacingMs} ms`);
  const prebuilt = args.binary ?? process.env.WAVE_BINARY;
  let executable;
  if (prebuilt) {
    executable = resolve(root, prebuilt);
    if (!existsSync(executable)) {
      console.error(`❌ WAVE_BINARY names ${executable}, which does not exist`);
      process.exit(2);
    }
  } else {
    try {
      executable = await buildLiveBinary();
    } catch (e) {
      console.error(`❌ ${e.message}`);
      process.exit(2);
    }
  }
  if (!existsSync(executable)) {
    console.error(`❌ cargo named ${executable} but it is not on disk`);
    process.exit(2);
  }
  console.log(`    prover: ${executable}`);

  const started = Date.now();
  const slots = [];
  for (let i = 1; i <= width; i++) {
    slots.push(runSlot(executable, i));
    if (spacingMs > 0 && i < width) await sleep(spacingMs);
  }
  const results = await Promise.all(slots);
  const wall = ((Date.now() - started) / 1000).toFixed(1);

  console.log('');
  for (const r of results) {
    const mark = r.ok ? 'PASS' : 'FAIL';
    const retry = r.passedOn ? ` (${r.passedOn})` : '';
    console.log(`  ${mark} ${String(r.index).padStart(2)}  ${r.seconds.padStart(6)}s  rc=${r.code}${retry}`);
    if (!r.ok) console.log(`        ${r.verdict}`);
  }
  const passed = results.filter((r) => r.ok).length;
  console.log('');
  console.log(`=== ${passed}/${width} passed, wall ${wall}s, target ${target}`);
  if (passed !== width) {
    console.log('    A FAIL here is not automatically a notary fault: read /proxy/refusals on the');
    console.log('    origin — `kind:"stalled"` names what was waited on and carries the retry hint.');
    process.exit(1);
  }
  process.exit(0);
}

main();
