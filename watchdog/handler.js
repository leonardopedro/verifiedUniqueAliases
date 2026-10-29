'use strict';
// pav-watchdog — self-healing replacement for the TDX confidential VM.
//
// Triggered two ways (belt & braces, operator's choice):
//   1. FC timer  — every 5 minutes, the polling guarantee;
//   2. EventBridge rule on ECS instance events — the fast path
//      (ecs:Instance:StateChange / PreemptibleInstanceInterruption /
//       SystemFailure.Delete), delivered over HTTP with a shared token.
// Both funnel into the same idempotent `ensure()`:
//
//   * a tagged instance exists (ANY status)  -> leave it alone.
//     A deliberately Stopped instance is never started: that is how the
//     operator runs in-place disk rewrites. Only a *released* instance
//     (gone from the account) is recreated.
//   * no tagged instance                    -> RunInstances with the exact
//     prod spec, tagged so the next poll finds it, then bind the reserved
//     EIP (only if the allocation is currently unattached — never stolen).
//
// Failure policy: any error is thrown so the trigger layer retries (FC timer
// re-invokes, EventBridge retries delivery). The ClientToken is derived from
// an hour bucket so a burst of retries cannot create two instances.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const rpc = require('./rpc');

const DEFAULT_TAG = { key: 'pav-watchdog', value: 'prod' };

function loadConfig() {
  let file = {};
  try {
    file = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8'));
  } catch (e) {
    file = {};
  }
  const env = process.env;
  const enabled =
    env.PAV_WATCHDOG_ENABLED !== undefined
      ? env.PAV_WATCHDOG_ENABLED === 'true'
      : file.enabled === true || file.enabled === 'true';
  return {
    enabled,
    region: env.PAV_REGION || file.region || 'cn-beijing',
    tagKey: file.tagKey || DEFAULT_TAG.key,
    tagValue: file.tagValue || DEFAULT_TAG.value,
    spec: file.spec || null,
    eipAllocationId: file.eipAllocationId || '',
    userDataB64: file.userDataB64 || '',
    httpToken: file.httpToken || '',
    maxAttempts: Number(env.PAV_MAX_ATTEMPTS || file.maxAttempts || 5),
    retryDelayMs: Number(env.PAV_RETRY_DELAY_MS || file.retryDelayMs || 10000),
    clientTokenPrefix: (file.clientTokenPrefix || 'pav-watchdog').slice(0, 40),
    accessKeyId: env.PAV_AK_ID || '',
    accessKeySecret: env.PAV_AK_SECRET || '',
    securityToken: env.PAV_STS_TOKEN || '',
  };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Deterministic, hour-bucketed idempotency token: retries inside the same
// hour collapse onto one RunInstances result instead of spawning boxes.
function clientToken(cfg, nowMs) {
  const d = new Date(nowMs);
  const p = (n) => String(n).padStart(2, '0');
  const stamp =
    d.getUTCFullYear() + p(d.getUTCMonth() + 1) + p(d.getUTCDate()) + p(d.getUTCHours());
  return `${cfg.clientTokenPrefix}-${cfg.tagValue}-${stamp}`.slice(0, 64);
}

async function listTagged(call, cfg) {
  const r = await call(cfg, 'ecs', '2014-05-26', {
    Action: 'DescribeInstances',
    RegionId: cfg.region,
    'Tag.1.Key': cfg.tagKey,
    'Tag.1.Value': cfg.tagValue,
  });
  return (r && r.Instances && r.Instances.Instance) || [];
}

async function createInstance(call, cfg, opts) {
  const spec = cfg.spec;
  if (!spec) throw new Error('config has no spec — refusing to guess how to build the box');
  const types = (spec.instanceTypes || []).length ? spec.instanceTypes : [spec.instanceType];
  const now = (opts && opts.now) || Date.now();
  const pause = (opts && opts.pause) || sleep;
  let lastErr;
  for (let attempt = 1; attempt <= cfg.maxAttempts; attempt++) {
    const type = types[(attempt - 1) % types.length];
    const params = {
      Action: 'RunInstances',
      RegionId: cfg.region,
      ZoneId: spec.zoneId,
      ImageId: spec.imageId,
      InstanceType: type,
      InstanceChargeType: 'PostPaid',
      SpotStrategy: 'SpotAsPriceGo',
      SpotDuration: '0',
      // TDX — the whole point of the box (AGENTS: enabled per shape).
      'SecurityOptions.ConfidentialComputingMode': 'TDX',
      VSwitchId: spec.vSwitchId,
      SecurityGroupId: spec.securityGroupId,
      InstanceName: spec.instanceName,
      'SystemDisk.Category': spec.systemDiskCategory || 'cloud_auto',
      'SystemDisk.Size': String(spec.systemDiskSize || 20),
      InternetMaxBandwidthOut: String(spec.internetMaxBandwidthOut || 0),
      // No auto public IP: the reserved EIP is bound separately, and a stray
      // public IP blocks EIP association (AGENTS API trap).
      AllocatePublicIp: 'false',
      'Tag.1.Key': cfg.tagKey,
      'Tag.1.Value': cfg.tagValue,
      ClientToken: clientToken(cfg, now),
    };
    if (cfg.userDataB64) params.UserData = cfg.userDataB64;
    try {
      const r = await call(cfg, 'ecs', '2014-05-26', params);
      // RunInstances returns InstanceIdSets.InstanceIdSet (capital D) —
      // reading `.InstanceidSet` silently yields undefined (AGENTS trap).
      const id =
        r && r.InstanceIdSets && r.InstanceIdSets.InstanceIdSet && r.InstanceIdSets.InstanceIdSet[0];
      if (!id) throw new Error('RunInstances gave no instance id: ' + JSON.stringify(r).slice(0, 400));
      return { instanceId: id, instanceType: type, attempt };
    } catch (e) {
      lastErr = e;
      if (attempt < cfg.maxAttempts) await pause(cfg.retryDelayMs);
    }
  }
  throw new Error(
    `RunInstances failed after ${cfg.maxAttempts} attempts: ${lastErr && lastErr.message}`
  );
}

async function eipInfo(call, cfg) {
  if (!cfg.eipAllocationId) return null;
  const r = await call(cfg, 'vpc', '2016-04-28', {
    Action: 'DescribeEipAddresses',
    RegionId: cfg.region,
    AllocationId: cfg.eipAllocationId,
  });
  const list = (r && r.EipAddresses && r.EipAddresses.EipAddress) || [];
  return list[0] || null;
}

async function bindEip(call, cfg, instanceId, pause) {
  let lastErr;
  for (let i = 1; i <= 5; i++) {
    try {
      await call(cfg, 'vpc', '2016-04-28', {
        Action: 'AssociateEipAddress',
        RegionId: cfg.region,
        AllocationId: cfg.eipAllocationId,
        InstanceId: instanceId,
        // no InstanceType — VPC-side API rejects it (AGENTS trap)
      });
      return 'associated';
    } catch (e) {
      lastErr = e;
      if (i < 5) await pause(5000);
    }
  }
  throw new Error('AssociateEipAddress failed: ' + (lastErr && lastErr.message));
}

/**
 * The whole watchdog, idempotent.
 * @param {Function} call  (cfg, product, version, params) => Promise<object>
 * @param {object} cfg
 * @param {object} opts    {now, pause} — injectable for tests
 */
async function ensure(call, cfg, opts) {
  if (!cfg.enabled) return { action: 'disabled' };
  const found = await listTagged(call, cfg);
  let created = null;
  if (found.length === 0) {
    created = await createInstance(call, cfg, opts);
  }
  const inst = found[0] || null;
  const instanceId = inst ? inst.InstanceId : created.instanceId;

  let eip = 'not-configured';
  if (cfg.eipAllocationId) {
    const cur = await eipInfo(call, cfg);
    if (cur && cur.InstanceId === instanceId) eip = 'already-associated';
    else if (cur && cur.InstanceId) {
      // Somebody else holds the allocation. Never yank it away.
      eip = 'held-by-other:' + cur.InstanceId;
    } else {
      eip = await bindEip(call, cfg, instanceId, (opts && opts.pause) || sleep);
    }
  }

  return {
    action: created ? 'created' : 'present',
    instanceId,
    instanceType: created ? created.instanceType : inst.InstanceType,
    status: inst ? inst.Status : 'creating',
    eip,
    createdAttempts: created ? created.attempt : 0,
  };
}

// --- trigger plumbing --------------------------------------------------------

function parseEvent(raw) {
  if (raw === null || raw === undefined) return { kind: 'empty' };
  if (Buffer.isBuffer(raw)) raw = raw.toString('utf8');
  if (typeof raw === 'string') {
    try {
      raw = JSON.parse(raw);
    } catch (e) {
      return { kind: 'raw', payload: String(raw).slice(0, 200) };
    }
  }
  if (typeof raw !== 'object') return { kind: 'raw', payload: String(raw).slice(0, 200) };
  if (raw.headers && (raw.httpMethod || raw.requestContext)) return { kind: 'http', http: raw };
  if (raw.triggerName && raw.triggerTime) return { kind: 'timer', http: null };
  if (raw.source || raw.type || raw.id) return { kind: 'eventbridge', http: null };
  return { kind: 'unknown', http: null };
}

// EventBridge -> HTTP delivery carries the shared secret here (documented
// header name). Anything else arriving over HTTP is refused before any API
// call is made: this endpoint is public, so it must be fail-closed.
function authHttpEvent(http, cfg) {
  if (!cfg.httpToken) return { ok: false, reason: 'no http token configured' };
  const headers = http.headers || {};
  const got =
    headers['x-eventbridge-signature-token'] ||
    headers['X-EventBridge-Signature-Token'] ||
    headers['X-EVENTBRIDGE-SIGNATURE-TOKEN'] ||
    '';
  const a = Buffer.from(String(got));
  const b = Buffer.from(cfg.httpToken);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, reason: 'bad or missing eventbridge token' };
  }
  return { ok: true };
}

function logResult(res) {
  console.log('watchdog:', JSON.stringify(res));
}

/**
 * Core entry point. `deps` lets the tests inject a fake RPC, clock and sleep.
 */
async function run(rawEvent, deps) {
  deps = deps || {};
  const cfg = (deps.loadConfig || loadConfig)();
  const call = deps.call || rpc.call;
  const pause = deps.pause || sleep;
  const now = deps.now || Date.now;

  const evt = parseEvent(rawEvent);
  if (evt.kind === 'http') {
    const auth = authHttpEvent(evt.http, cfg);
    if (!auth.ok) {
      const rejected = { action: 'rejected', reason: auth.reason };
      console.log('watchdog:', JSON.stringify(rejected));
      return { statusCode: 403, headers: { 'content-type': 'application/json' }, body: JSON.stringify(rejected) };
    }
  }

  const res = await ensure(call, cfg, { now, pause });
  const out = Object.assign({ trigger: evt.kind }, res);
  logResult(out);
  return { statusCode: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify(out) };
}

async function handler(event, context) {
  return run(event, null);
}

module.exports = { handler, run, ensure, loadConfig, clientToken, parseEvent, authHttpEvent, listTagged, createInstance };
