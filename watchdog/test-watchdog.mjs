#!/usr/bin/env node
// Unit tests for the FC watchdog (no network: the RPC layer is stubbed).
// Run: node watchdog/test-watchdog.mjs
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);
const w = require('./handler.js');

let passed = 0;
const failures = [];
async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ok  ${name}`);
  } catch (e) {
    failures.push(name);
    console.log(`FAIL  ${name}\n      ${e.message}`);
  }
}

const baseCfg = (over = {}) => ({
  enabled: true,
  region: 'cn-beijing',
  tagKey: 'pav-watchdog',
  tagValue: 'prod',
  eipAllocationId: 'eip-2zet05jbat6wr6rp7elrc',
  userDataB64: 'IyEvYmluL2Jhc2gK',
  httpToken: 'tok-abc',
  maxAttempts: 5,
  retryDelayMs: 1,
  clientTokenPrefix: 'pav-watchdog',
  accessKeyId: 'ak',
  accessKeySecret: 'sk',
  securityToken: '',
  spec: {
    zoneId: 'cn-beijing-i',
    imageId: 'm-2zef5rtftylwooqx1a9b',
    instanceTypes: ['ecs.c9i.large', 'ecs.c9i.xlarge'],
    vSwitchId: 'vsw-2zemsk0m5ky2j6uttlk82',
    securityGroupId: 'sg-2zehehuvi1f0v67q11bo',
    instanceName: 'paypal-auth-vm',
    systemDiskCategory: 'cloud_auto',
    systemDiskSize: 20,
    internetMaxBandwidthOut: 5,
  },
  ...over,
});

const inst = (id, status = 'Running') => ({
  InstanceId: id,
  InstanceType: 'ecs.c9i.large',
  Status: status,
});

// Fake RPC: scripted responses + a call log.
function fakeCall(script) {
  const log = [];
  const call = async (cfg, product, version, params) => {
    log.push({ product, action: params.Action, params });
    const key = `${product}.${params.Action}`;
    const h = script[key];
    if (!h) throw new Error(`unexpected call ${key}`);
    const r = typeof h === 'function' ? h(log, params) : h;
    if (r && r.__throw) throw new Error(r.__throw);
    return r;
  };
  return { call, log };
}

const noSleep = () => Promise.resolve();

// ---------------------------------------------------------------------------
await test('present instance: no create, no EIP churn', async () => {
  const { call, log } = fakeCall({
    'ecs.DescribeInstances': { Instances: { Instance: [inst('i-aaa')] } },
    'vpc.DescribeEipAddresses': {
      EipAddresses: { EipAddress: [{ AllocationId: 'eip-1', InstanceId: 'i-aaa' }] },
    },
  });
  const res = await w.ensure(call, baseCfg(), { pause: noSleep });
  assert.equal(res.action, 'present');
  assert.equal(res.instanceId, 'i-aaa');
  assert.equal(res.eip, 'already-associated');
  assert.ok(!log.some((l) => l.action === 'RunInstances'), 'must not create');
  assert.ok(!log.some((l) => l.action === 'AssociateEipAddress'), 'must not rebind');
});

await test('stopped instance is left stopped (operator deploys are safe)', async () => {
  const { call, log } = fakeCall({
    'ecs.DescribeInstances': { Instances: { Instance: [inst('i-stopped', 'Stopped')] } },
    'vpc.DescribeEipAddresses': {
      EipAddresses: { EipAddress: [{ AllocationId: 'eip-1', InstanceId: 'i-stopped' }] },
    },
  });
  const res = await w.ensure(call, baseCfg(), { pause: noSleep });
  assert.equal(res.action, 'present');
  assert.equal(res.status, 'Stopped');
  assert.ok(!log.some((l) => l.action === 'StartInstance'), 'never start a stopped box');
  assert.ok(!log.some((l) => l.action === 'RunInstances'), 'never replace a stopped box');
});

await test('released instance: recreates with the exact prod spec, then binds EIP', async () => {
  const { call, log } = fakeCall({
    'ecs.DescribeInstances': () => ({
      Instances: { Instance: log.filter((l) => l.action === 'RunInstances').length ? [inst('i-new')] : [] },
    }),
    'ecs.RunInstances': { InstanceIdSets: { InstanceIdSet: ['i-new'] } },
    'vpc.DescribeEipAddresses': { EipAddresses: { EipAddress: [{ AllocationId: 'eip-1', InstanceId: '' }] } },
    'vpc.AssociateEipAddress': {},
  });
  const res = await w.ensure(call, baseCfg(), { pause: noSleep });
  assert.equal(res.action, 'created');
  assert.equal(res.instanceId, 'i-new');
  assert.equal(res.eip, 'associated');

  const run = log.find((l) => l.action === 'RunInstances');
  assert.ok(run, 'RunInstances must be called');
  const p = run.params;
  assert.equal(p.ImageId, 'm-2zef5rtftylwooqx1a9b');
  assert.equal(p.InstanceType, 'ecs.c9i.large');
  assert.equal(p.ZoneId, 'cn-beijing-i');
  assert.equal(p.VSwitchId, 'vsw-2zemsk0m5ky2j6uttlk82');
  assert.equal(p.SecurityGroupId, 'sg-2zehehuvi1f0v67q11bo');
  assert.equal(p['SecurityOptions.ConfidentialComputingMode'], 'TDX', 'TDX must be requested');
  assert.equal(p.SpotStrategy, 'SpotAsPriceGo', 'keep spot pricing');
  assert.equal(p.InstanceChargeType, 'PostPaid');
  assert.equal(p.AllocatePublicIp, 'false', 'auto public IP blocks EIP binding');
  assert.equal(p['Tag.1.Key'], 'pav-watchdog');
  assert.equal(p['Tag.1.Value'], 'prod');
  assert.equal(p.UserData, 'IyEvYmluL2Jhc2gK');
  assert.equal(p['SystemDisk.Size'], '20');
  assert.ok(p.ClientToken && p.ClientToken.length <= 64, 'ClientToken must be <= 64 chars');

  const assoc = log.find((l) => l.action === 'AssociateEipAddress');
  assert.equal(assoc.params.AllocationId, 'eip-2zet05jbat6wr6rp7elrc');
  assert.equal(assoc.params.InstanceId, 'i-new');
  assert.equal(assoc.params.InstanceType, undefined, 'VPC API rejects InstanceType');
});

await test('stock-out: retries through the instance-type list', async () => {
  let n = 0;
  const { call, log } = fakeCall({
    'ecs.DescribeInstances': () => ({
      Instances: { Instance: log.filter((l) => l.action === 'RunInstances').length >= 3 ? [inst('i-ok')] : [] },
    }),
    'ecs.RunInstances': () => {
      n++;
      if (n < 3) return { __throw: 'ecs.RunInstances failed: OperationDenied.NoStock' };
      return { InstanceIdSets: { InstanceIdSet: ['i-ok'] } };
    },
    'vpc.DescribeEipAddresses': { EipAddresses: { EipAddress: [{ AllocationId: 'eip-1', InstanceId: '' }] } },
    'vpc.AssociateEipAddress': {},
  });
  const res = await w.ensure(call, baseCfg(), { pause: noSleep });
  assert.equal(res.action, 'created');
  const runs = log.filter((l) => l.action === 'RunInstances');
  assert.equal(runs.length, 3);
  assert.equal(runs[0].params.InstanceType, 'ecs.c9i.large');
  assert.equal(runs[1].params.InstanceType, 'ecs.c9i.xlarge', 'rotate to the fallback shape');
  assert.equal(runs[2].params.InstanceType, 'ecs.c9i.large', 'wrap around the list');
  assert.equal(new Set(runs.map((r) => r.params.ClientToken)).size, 1,
    'all attempts in a burst share one idempotency token');
});

await test('creation never succeeds: throws so the trigger layer retries', async () => {
  const { call } = fakeCall({
    'ecs.DescribeInstances': { Instances: { Instance: [] } },
    'ecs.RunInstances': { __throw: 'ecs.RunInstances failed: OperationDenied.NoStock' },
  });
  await assert.rejects(
    () => w.ensure(call, baseCfg({ maxAttempts: 3 }), { pause: noSleep }),
    /failed after 3 attempts.*NoStock/
  );
});

await test('EIP held by another instance is never stolen', async () => {
  const { call, log } = fakeCall({
    'ecs.DescribeInstances': { Instances: { Instance: [inst('i-mine')] } },
    'vpc.DescribeEipAddresses': {
      EipAddresses: { EipAddress: [{ AllocationId: 'eip-1', InstanceId: 'i-someone-else' }] },
    },
  });
  const res = await w.ensure(call, baseCfg(), { pause: noSleep });
  assert.equal(res.eip, 'held-by-other:i-someone-else');
  assert.ok(!log.some((l) => l.action === 'AssociateEipAddress'), 'must not yank the EIP');
});

await test('disabled switch: zero API calls', async () => {
  const { call, log } = fakeCall({});
  const res = await w.ensure(call, baseCfg({ enabled: false }), { pause: noSleep });
  assert.deepEqual(res, { action: 'disabled' });
  assert.equal(log.length, 0);
});

await test('no EIP configured: create still works, no VPC calls', async () => {
  const { call, log } = fakeCall({
    'ecs.DescribeInstances': { Instances: { Instance: [] } },
    'ecs.RunInstances': { InstanceIdSets: { InstanceIdSet: ['i-x'] } },
  });
  const res = await w.ensure(call, baseCfg({ eipAllocationId: '' }), { pause: noSleep });
  assert.equal(res.action, 'created');
  assert.equal(res.eip, 'not-configured');
  assert.ok(!log.some((l) => l.product === 'vpc'), 'no VPC traffic at all');
});

// --- trigger plumbing -------------------------------------------------------

await test('HTTP event without the EventBridge token is refused before any API call', async () => {
  const { call, log } = fakeCall({});
  const evt = JSON.stringify({ headers: {}, httpMethod: 'POST', requestContext: {}, body: '{}' });
  const res = await w.run(evt, { call, loadConfig: () => baseCfg(), pause: noSleep });
  assert.equal(res.statusCode, 403);
  assert.match(res.body, /bad or missing eventbridge token/);
  assert.equal(log.length, 0, 'a rogue caller must not reach the RPC layer');
});

await test('HTTP event with the token runs ensure()', async () => {
  const { call } = fakeCall({
    'ecs.DescribeInstances': { Instances: { Instance: [inst('i-aaa')] } },
    'vpc.DescribeEipAddresses': {
      EipAddresses: { EipAddress: [{ AllocationId: 'eip-1', InstanceId: 'i-aaa' }] },
    },
  });
  const evt = JSON.stringify({
    headers: { 'x-eventbridge-signature-token': 'tok-abc' },
    httpMethod: 'POST',
    requestContext: {},
    body: '{}',
  });
  const res = await w.run(evt, { call, loadConfig: () => baseCfg(), pause: noSleep });
  assert.equal(res.statusCode, 200);
  assert.match(res.body, /"action":"present"/);
});

await test('timer event runs ensure() (poll leg)', async () => {
  const { call } = fakeCall({
    'ecs.DescribeInstances': { Instances: { Instance: [inst('i-aaa')] } },
    'vpc.DescribeEipAddresses': {
      EipAddresses: { EipAddress: [{ AllocationId: 'eip-1', InstanceId: 'i-aaa' }] },
    },
  });
  const evt = JSON.stringify({ triggerTime: '2026-10-29T00:00:00Z', triggerName: 'poll-5m', payload: '' });
  const res = await w.run(evt, { call, loadConfig: () => baseCfg(), pause: noSleep });
  assert.equal(res.statusCode, 200);
  assert.match(res.body, /"trigger":"timer"/);
});

await test('event object (direct EventBridge delivery) is understood', async () => {
  const { call } = fakeCall({
    'ecs.DescribeInstances': { Instances: { Instance: [inst('i-aaa')] } },
    'vpc.DescribeEipAddresses': {
      EipAddresses: { EipAddress: [{ AllocationId: 'eip-1', InstanceId: 'i-aaa' }] },
    },
  });
  const evt = { source: 'acs.ecs', type: 'ecs:Instance:StateChange', id: 'x' };
  const res = await w.run(evt, { call, loadConfig: () => baseCfg(), pause: noSleep });
  assert.match(res.body, /"trigger":"eventbridge"/);
});

await test('clientToken is hour-stable and <= 64 chars', () => {
  const cfg = baseCfg();
  const t1 = w.clientToken(cfg, Date.UTC(2026, 9, 29, 10, 5, 0));
  const t2 = w.clientToken(cfg, Date.UTC(2026, 9, 29, 10, 55, 0));
  const t3 = w.clientToken(cfg, Date.UTC(2026, 9, 29, 11, 0, 0));
  assert.equal(t1, t2, 'same hour => same token');
  assert.notEqual(t2, t3, 'next hour => new token');
  assert.ok(t1.length <= 64);
  assert.ok(w.clientToken({ ...cfg, clientTokenPrefix: 'x'.repeat(60) }, Date.now()).length <= 64);
});

// ---------------------------------------------------------------------------
console.log(`\n${passed} passed, ${failures.length} failed`);
if (failures.length) {
  console.log('failed: ' + failures.join(', '));
  process.exit(1);
}
