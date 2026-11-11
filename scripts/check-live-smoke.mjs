#!/usr/bin/env node
// check-live-smoke.mjs — one command that answers "is the deployed notary
// actually working right now?": it runs a single live session, then a width-8
// burst, and prints one PASS/FAIL summary for each.
//
// Why both: a solo session proves the relay, the commitment bound and the
// attestation; the burst proves the dial pacing and the retry path, which only
// show up when several provers arrive at once. Running them together is the
// difference between "it worked when I tried it" and a check someone can paste
// into a release note.
//
// The prover binary is built once and reused by both phases (see
// check-live-wave.mjs for why: per-slot `cargo test` serialises on the cargo
// lock and would measure nothing).
//
// Usage:
//   node scripts/check-live-smoke.mjs
//   node scripts/check-live-smoke.mjs --target www.sandbox.paypal.com/robots.txt
//   node scripts/check-live-smoke.mjs --binary tls-proxy/target/debug/deps/live-…  # skip the build
//   node scripts/check-live-smoke.mjs --solo-only | --wave-only
//
// Knobs (flags win over env): LIVE_NOTARY, LIVE_SERVER/SMOKE_TARGET, WAVE_WIDTH,
// LIVE_ATTEMPTS (the wave's retry count), LIVE_CA_BUNDLE, SMOKE_BINARY/WAVE_BINARY.
//
// Exit 0 = both phases passed, 1 = a phase failed (the notary's own sentence is
// printed), 2 = the harness could not run (build failure, missing binary).

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
const target = args.target ?? process.env.SMOKE_TARGET ?? process.env.LIVE_SERVER ?? 'www.sandbox.paypal.com/robots.txt';
const notary = args.notary ?? process.env.LIVE_NOTARY ?? '101.200.178.251:8443';
const width = String(args.width ?? process.env.WAVE_WIDTH ?? 8);
const waveAttempts = String(process.env.LIVE_ATTEMPTS ?? 2);
const caBundle = args['ca-bundle'] ?? process.env.LIVE_CA_BUNDLE;
const soloOnly = Boolean(args['solo-only']);
const waveOnly = Boolean(args['wave-only']);

function buildLiveBinary() {
  return new Promise((done, bad) => {
    const p = spawn(process.env.CARGO ?? 'cargo', [
      'test', '--manifest-path', MANIFEST, '--test', 'live', '--no-run', '--message-format=json',
    ], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
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
        if (msg.reason === 'build-finished' && msg.success === false) executable = null;
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

function runSolo(executable) {
  return new Promise((done) => {
    const env = { ...process.env, LIVE_NOTARY: notary, LIVE_SERVER: target, LIVE_ATTEMPTS: '1' };
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
      out += '\n--- SMOKE: solo cancelled after 180s\n';
      p.kill('SIGKILL');
    }, 180_000);
    p.on('close', (code) => {
      clearTimeout(timer);
      const lines = out.split('\n').map((l) => l.trim()).filter(Boolean);
      const verdict = [...lines].reverse().find((l) => /^--- attempt .*failed/.test(l))
        ?? lines.find((l) => /^response head/.test(l))
        ?? lines[lines.length - 1]
        ?? '(no output)';
      done({ ok: code === 0, code, seconds: ((Date.now() - started) / 1000).toFixed(1), verdict: verdict.slice(0, 200) });
    });
  });
}

function runWave(executable) {
  return new Promise((done) => {
    const child = spawn(process.execPath, [
      join(root, 'scripts', 'check-live-wave.mjs'),
      '--width', width,
      '--target', target,
      '--notary', notary,
      '--attempts', waveAttempts,
      '--binary', executable,
    ], { cwd: root, stdio: 'inherit' });
    child.on('close', (code) => done({ ok: code === 0, code }));
  });
}

async function main() {
  console.log(`=== live smoke: notary ${notary}, target ${target}`);
  const prebuilt = args.binary ?? process.env.SMOKE_BINARY ?? process.env.WAVE_BINARY;
  let executable;
  if (prebuilt) {
    executable = resolve(root, prebuilt);
    if (!existsSync(executable)) {
      console.error(`❌ --binary names ${executable}, which does not exist`);
      process.exit(2);
    }
    console.log(`    prover: ${executable} (prebuilt)`);
  } else {
    try {
      executable = await buildLiveBinary();
    } catch (e) {
      console.error(`❌ ${e.message}`);
      process.exit(2);
    }
    console.log(`    prover: ${executable} (built once)`);
  }

  const results = [];
  if (!waveOnly) {
    console.log('\n--- solo: one session, no retry');
    const solo = await runSolo(executable);
    console.log(`  ${solo.ok ? 'PASS' : 'FAIL'} solo  ${solo.seconds}s  rc=${solo.code}`);
    if (!solo.ok) console.log(`        ${solo.verdict}`);
    results.push({ name: 'solo', ok: solo.ok });
  }
  if (!soloOnly) {
    console.log(`\n--- wave: ${width} concurrent, up to ${waveAttempts} attempt(s) each`);
    const wave = await runWave(executable);
    results.push({ name: `wave x${width}`, ok: wave.ok });
  }

  const failed = results.filter((r) => !r.ok);
  console.log('\n=== summary');
  for (const r of results) console.log(`  ${r.ok ? 'PASS' : 'FAIL'}  ${r.name}`);
  if (failed.length) {
    console.log('\n    A FAIL is not automatically a notary fault: read /proxy/refusals on the');
    console.log('    origin — `kind:"stalled"` names what was waited on and carries the retry hint.');
    process.exit(1);
  }
  process.exit(0);
}

main();
