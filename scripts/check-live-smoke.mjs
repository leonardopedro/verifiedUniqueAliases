#!/usr/bin/env node
// check-live-smoke.mjs — one command that answers "is the deployed notary
// actually working right now?": it runs a single live session, then a width-8
// burst, then a failover probe against a two-edge host, and prints one PASS/FAIL
// summary for each.
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
//   node scripts/check-live-smoke.mjs --solo-only | --wave-only | --failover-only
//   node scripts/check-live-smoke.mjs --no-failover
//   node scripts/check-live-smoke.mjs --failover-host api-m.paypal.com --failover-addresses 146.75.123.1,104.16.124.74
//
// The prover is built three ways, in order, so the command works on any host:
// local `cargo`, then the project's build container (`--build-container`,
// default `localhost/tlsproxytest`, mounted at /app — this host cannot build
// tlsn natively), and finally the newest `live-*` binary already in
// `tls-proxy/target/debug/deps`, with a warning that it is not from this tree.
//
// The third phase is the failover probe: a host pinned to several addresses
// (default `sandbox.paypal.com`, served by two different CDN edges) is dialled
// one session at a time. A dark FIRST address is the failure this catches — the
// edge that accepts the TCP connection and withholds the handshake. It passes
// when a session passes, and it fails when `/proxy/health` shows an address
// struck off
// (zero_byte_runs) while no other pinned address has ever answered, which is
// exactly the shape of the v243 bug: the strike was recorded, the alternates
// never existed, and every session kept dialling the dead edge.
//
// Knobs (flags win over env): LIVE_NOTARY, LIVE_SERVER/SMOKE_TARGET, WAVE_WIDTH,
// LIVE_ATTEMPTS (the wave's retry count), WAVE_SPACING (ms between starts,
// default 2000), LIVE_CA_BUNDLE, SMOKE_BINARY/WAVE_BINARY, PROD_URL (the origin
// whose /proxy/health the failover probe reads, default https://login.airma.de),
// SMOKE_FAILOVER_HOST, SMOKE_FAILOVER_ADDRESSES, SMOKE_CONFIG (a copy of the
// deployment config, read only for `relay_targets`), LIVE_BUILD_CONTAINER.
//
// Exit 0 = every phase passed or was inconclusive (the reason is printed), 1 = a
// phase failed with the notary at fault (its own sentence is printed), 2 = the
// harness could not run (no prover, missing binary).

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, resolve, join } from 'path';
import { existsSync, readdirSync, statSync } from 'fs';
import { endpointRows, pinnedForHost, isTargetPolicyRefusal } from './lib/failover-health.mjs';

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
// 8 provers arriving in the same instant is what produced the one or two
// per-burst stalls measured on 2026-11-11 even with the edge-naming verdict in
// place; 2 s apart is the spacing that measured 8/8, so that is the default the
// smoke check ships with. `--spacing 0` measures the harsher shape.
const waveSpacing = String(args.spacing ?? process.env.WAVE_SPACING ?? 2000);
const caBundle = args['ca-bundle'] ?? process.env.LIVE_CA_BUNDLE;
const soloOnly = Boolean(args['solo-only']);
const waveOnly = Boolean(args['wave-only']);
const noFailover = Boolean(args['no-failover']);
const failoverOnly = Boolean(args['failover-only']);
// The origin is a different machine from the notary socket: the notary answers
// the prover protocol on :8443, while /proxy/health is published on the origin
// that fronts it. The failover probe needs the latter.
const origin = (args.origin ?? process.env.PROD_URL ?? 'https://login.airma.de').replace(/\/$/, '');
const failoverHost =
  args['failover-host'] ?? process.env.SMOKE_FAILOVER_HOST ?? 'sandbox.paypal.com';
const failoverSessions = Number(args['failover-sessions'] ?? process.env.SMOKE_FAILOVER_SESSIONS ?? 2);
// The host's pinned addresses, when the operator knows them. Otherwise they are
// read from the deployment config, and only failing that inferred from the
// health counters the probe itself moved (see runFailover).
const failoverAddresses = String(
  args['failover-addresses'] ?? process.env.SMOKE_FAILOVER_ADDRESSES ?? '',
)
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const configPath =
  args.config ?? process.env.SMOKE_CONFIG ?? process.env.TLS_PROXY_CONFIG ?? '/tmp/prod-config.json';
const buildContainer =
  args['build-container'] ?? process.env.LIVE_BUILD_CONTAINER ?? 'localhost/tlsproxytest';

/**
 * Run one `cargo test --test live --no-run` and return the prover path.
 *
 * `mapPath` rewrites the path cargo reports: inside the build container the
 * tree is mounted at /app, so the executable comes back as
 * `/app/tls-proxy/target/...` and has to be translated to the host path.
 */
function cargoBuild(command, argv, mapPath = (p) => p) {
  return new Promise((done, bad) => {
    const p = spawn(command, argv, { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
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
        bad(new Error(`${command} ${argv[0]} failed (rc=${code})${errs.length ? `: ${errs.join('').trim().split('\n').slice(-3).join(' | ')}` : ''}`));
      } else {
        done(mapPath(executable));
      }
    });
  });
}

/** The newest `live-*` prover already built in this tree, if any. */
function newestPrebuilt() {
  const dir = join(root, 'tls-proxy', 'target', 'debug', 'deps');
  let best = null;
  try {
    for (const name of readdirSync(dir)) {
      if (!name.startsWith('live-') || name.endsWith('.d')) continue;
      const path = join(dir, name);
      if (!statSync(path).isFile() || (statSync(path).mode & 0o111) === 0) continue;
      if (!best || statSync(path).mtimeMs > statSync(best).mtimeMs) best = path;
    }
  } catch {
    return null;
  }
  return best;
}

/**
 * Build the live prover where this host can, and say which route was used.
 *
 * Order matters: a locally built prover is from this tree; the project's build
 * container is the same tree compiled by the same pinned toolchain (this host
 * cannot build tlsn natively — openssl-sys wants a build environment it does not
 * have); a prebuilt binary in `target/` may predate the working tree, so it is
 * the last resort and is announced loudly.
 */
async function buildLiveBinary() {
  const failures = [];
  const localCargo = ['test', '--manifest-path', MANIFEST, '--test', 'live', '--no-run', '--message-format=json'];
  try {
    const executable = await cargoBuild(process.env.CARGO ?? 'cargo', localCargo);
    return { executable, how: 'built' };
  } catch (e) {
    failures.push(e.message);
  }

  try {
    const executable = await cargoBuild(
      process.env.CONTAINER_RUNTIME ?? 'podman',
      [
        'run', '--rm',
        '-v', `${root}:/app:z`,
        '-w', '/app/tls-proxy',
        buildContainer,
        'cargo', '+1.99.0', 'test', '--test', 'live', '--no-run', '--message-format=json',
      ],
      (p) => p.replace(/^\/app/, root),
    );
    return { executable, how: `built in ${buildContainer}` };
  } catch (e) {
    failures.push(e.message);
  }

  const prebuilt = newestPrebuilt();
  if (prebuilt) {
    console.warn(`    prover: ${prebuilt} (prebuilt — neither local cargo nor ${buildContainer} could build)`);
    console.warn('            it may predate this working tree; pass --binary explicitly to pin one');
    return { executable: prebuilt, how: 'prebuilt' };
  }
  throw new Error(`no prover could be built: ${failures.join(' | ')}`);
}

function runOne(executable, { server = target, attempts = 1 } = {}) {
  return new Promise((done) => {
    const env = { ...process.env, LIVE_NOTARY: notary, LIVE_SERVER: server, LIVE_ATTEMPTS: String(attempts) };
    // The failover probe reads the shared list by digests; it must not also try to
    // fetch its own record, which would add a second network dependency.
    delete env.LIVE_PUBLIC;
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
      done({
        ok: code === 0,
        code,
        seconds: ((Date.now() - started) / 1000).toFixed(1),
        verdict: verdict.slice(0, 240),
        // The notary's own sentence when it has one: a stall names the edge, and
        // a prover that dies in its own preprocessing (commitment or the COT
        // bootstrap behind it) says nothing about the target at all.
        stalled: /stalled|sent no byte|accepted the connection and sent nothing/i.test(out),
        prover: /commitment handshake|computed its commitment|preprocessing proxy-tls failed|bootstrap COT error/i.test(out),
      });
    });
  });
}

async function health() {
  const res = await fetch(`${origin}/proxy/health`, { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`/proxy/health answered ${res.status}`);
  return res.json();
}

/**
 * Failover probe: one session at a time against a host pinned to two addresses.
 *
 * The failure this is for is a dark FIRST address — the edge that accepts the
 * TCP connection and never sends its handshake. A notary that fails over passes
 * after at most one stalled session: the silence is recorded mid-session (v245),
 * the next dial takes the other address. A notary that does not fails every
 * session on the same address, and `/proxy/health` is the proof of it: an
 * address is struck off while no other pinned address has ever answered.
 */
async function runFailover(executable) {
  let before;
  const startedAt = Date.now();
  try {
    before = await health();
  } catch (e) {
    return { ok: false, verdict: `could not read ${origin}/proxy/health: ${e.message}` };
  }
  if (!before || typeof before.relay_endpoints !== 'object') {
    return {
      ok: false,
      verdict: '/proxy/health has no relay_endpoints — this build cannot fail over between pinned addresses',
    };
  }

  const attempts = [];
  for (let i = 1; i <= failoverSessions; i++) {
    console.log(`  session ${i}/${failoverSessions}: ${failoverHost}`);
    const run = await runOne(executable, { server: failoverHost, attempts: 1 });
    attempts.push(run);
    console.log(`    ${run.ok ? 'PASS' : 'FAIL'} ${run.seconds}s${run.ok ? '' : `  ${run.verdict}`}`);
    if (run.ok) break;
    // A prover-side failure says nothing about the target's edge: the next
    // session would prove nothing either, and each costs a minute.
    if (run.prover && !run.stalled) {
      return {
        ok: true,
        inconclusive: true,
        note: `the prover itself failed, so the edge was never judged (${run.verdict.slice(0, 120)})`,
      };
    }
  }

  let after;
  try {
    after = await health();
  } catch (e) {
    return { ok: false, verdict: `could not re-read ${origin}/proxy/health after the sessions: ${e.message}` };
  }
  const rows = endpointRows(after);
  const struck = rows.filter((r) => r.struck);
  const answered = rows.filter((r) => r.answered);
  const passing = attempts.filter((a) => a.ok).length;
  const summary = `sessions ${passing}/${attempts.length} passed; endpoints: ${
    rows.map((r) => `${r.addr} ${r.struck ? 'struck' : 'ok'}${r.answered ? '/answered' : ''}`).join(', ') || '(none reported)'
  }`;

  if (passing > 0) {
    // A pass after a struck address is the failover working; a pass on the
    // preferred address is simply a healthy edge.
    return { ok: true, note: summary };
  }

  // Which addresses does this probe own? Explicitly given, then the deployment
  // config's pins for this host, and only failing both the ones the probe itself
  // moved — a wrong pin that never gets dialled (v243) must NOT read as a
  // target refusal, and a diff can only ever describe what was dialled.
  const beforeRows = new Map(endpointRows(before).map((r) => [r.addr, r]));
  const elapsed = (Date.now() - startedAt) / 1000;
  const touched = rows
    .filter((r) => {
      const old = beforeRows.get(r.addr);
      const newStrike = r.strikes > (old?.strikes ?? 0);
      const justAnswered = r.answered && (!old?.answered || (r.idleSecs ?? 1e9) <= elapsed + 30);
      return newStrike || justAnswered;
    })
    .map((r) => r.addr);
  const pins =
    failoverAddresses.length > 0
      ? failoverAddresses
      : (() => {
          const fromConfig = pinnedForHost(configPath, failoverHost);
          return fromConfig.length > 0 ? fromConfig : touched;
        })();
  const pinsFromConfig = pinnedForHost(configPath, failoverHost);
  const pinsAreKnown = failoverAddresses.length > 0 || pinsFromConfig.length > 0;
  const pinSource =
    failoverAddresses.length > 0
      ? 'given'
      : pinsFromConfig.length > 0
        ? `from ${configPath}`
        : 'inferred from this probe, so a refusal cannot be called target policy';

  if (isTargetPolicyRefusal(pins, rows, { pinsAreKnown })) {
    return {
      ok: true,
      inconclusive: true,
      note:
        `target-policy refusal: ${failoverHost} refused all ${pins.length} pinned address(es) this probe ` +
        `drove (${pins.join(', ')}, pins ${pinSource}), none answered — another address cannot fix a ` +
        'refusal aimed at the source address, so this says nothing about the notary. Confirm with a ' +
        'direct handshake from the notary\'s network, or probe a host that still serves it',
    };
  }
  if (struck.length > 0 && answered.length === 0) {
    return {
      ok: false,
      verdict:
        `every session to ${failoverHost} failed and no pinned address ever answered (${summary}) — ` +
        'the failover is not reaching a second address. If a solo session to another host passes, ' +
        'the target edge is refusing this notary\'s egress on every pinned address instead ' +
        '(a target-policy finding: confirm with a direct handshake from the notary\'s network), ' +
        'which is not something another address can fix',
    };
  }
  return { ok: false, verdict: `${failoverHost} failed ${attempts.length}/${attempts.length} (${summary})` };
}

function runWave(executable) {
  return new Promise((done) => {
    const child = spawn(process.execPath, [
      join(root, 'scripts', 'check-live-wave.mjs'),
      '--width', width,
      '--target', target,
      '--notary', notary,
      '--attempts', waveAttempts,
      '--spacing', waveSpacing,
      '--binary', executable,
    ], { cwd: root, stdio: 'inherit' });
    child.on('close', (code) => done({ ok: code === 0, code }));
  });
}

async function main() {
  console.log(`=== live smoke: notary ${notary}, target ${target}`);
  const prebuilt = args.binary ?? process.env.SMOKE_BINARY ?? process.env.WAVE_BINARY;
  let executable;
  let how = 'prebuilt';
  if (prebuilt) {
    executable = resolve(root, prebuilt);
    if (!existsSync(executable)) {
      console.error(`❌ --binary names ${executable}, which does not exist`);
      process.exit(2);
    }
    console.log(`    prover: ${executable} (prebuilt)`);
  } else {
    try {
      ({ executable, how } = await buildLiveBinary());
    } catch (e) {
      console.error(`❌ ${e.message}`);
      process.exit(2);
    }
    if (how !== 'prebuilt') console.log(`    prover: ${executable} (${how}, once)`);
  }

  const results = [];
  if (!waveOnly && !failoverOnly) {
    console.log('\n--- solo: one session, no retry');
    const solo = await runOne(executable);
    console.log(`  ${solo.ok ? 'PASS' : 'FAIL'} solo  ${solo.seconds}s  rc=${solo.code}`);
    if (!solo.ok) console.log(`        ${solo.verdict}`);
    results.push({ name: 'solo', ok: solo.ok });
  }
  if (!soloOnly && !failoverOnly) {
    console.log(`\n--- wave: ${width} concurrent, ${waveSpacing} ms apart, up to ${waveAttempts} attempt(s) each`);
    const wave = await runWave(executable);
    results.push({ name: `wave x${width}`, ok: wave.ok });
  }
  if (!noFailover && (failoverOnly || (!waveOnly && !soloOnly))) {
    console.log(`\n--- failover: ${failoverHost}, ${failoverSessions} session(s) one at a time, health from ${origin}`);
    const failover = await runFailover(executable);
    const label = failover.inconclusive ? 'INCONCLUSIVE' : failover.ok ? 'PASS' : 'FAIL';
    console.log(`  ${label} failover${failover.note ? `  ${failover.note}` : ''}`);
    if (!failover.ok) console.log(`        ${failover.verdict}`);
    results.push({ name: 'failover', ok: failover.ok, inconclusive: Boolean(failover.inconclusive) });
  }

  const failed = results.filter((r) => !r.ok);
  const inconclusive = results.filter((r) => r.inconclusive);
  console.log('\n=== summary');
  for (const r of results) {
    console.log(`  ${r.ok ? (r.inconclusive ? 'INCONCLUSIVE' : 'PASS') : 'FAIL'}  ${r.name}`);
  }
  if (inconclusive.length) {
    console.log('\n    An INCONCLUSIVE phase is a finding about the target, not a notary fault:');
    console.log('    the reason above names which addresses refused and where the pins came from.');
  }
  if (failed.length) {
    console.log('\n    A FAIL is not automatically a notary fault: read /proxy/refusals on the');
    console.log('    origin — `kind:"stalled"` names what was waited on and carries the retry hint.');
    process.exit(1);
  }
  process.exit(0);
}

main();
