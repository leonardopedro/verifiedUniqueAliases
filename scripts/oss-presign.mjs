// Presigned OSS URL for any method — the relay legs of rotate-alibaba.sh.
//
// The operator host cannot reach the Beijing bucket (data-plane calls from
// outside mainland China are geo-blocked and these buckets refuse the public
// endpoint), so the bytes move on presigned URLs: PUT to the HK bucket, GET
// from it on the relay ECS, PUT to the Beijing bucket over the intranet.
//
// Signing rule verified against ossutil (2026-10-17): HMAC-SHA1 key = raw SK;
// the canonical resource carries ?security-token=<raw token> for STS profiles.
//
// Usage:
//   node scripts/oss-presign.mjs <METHOD> <bucket> <key> <endpoint-host> [ttl] [vhost|path]
// e.g.
//   node scripts/oss-presign.mjs PUT  paypal-tdx-relay-1792227992 \
//        paypal-auth-vm/disk-alibaba.raw paypal-tdx-relay-1792227992.oss-cn-hongkong.aliyuncs.com
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';

const [method, bucket, key, host, ttlS, style] = process.argv.slice(2);
if (!method || !bucket || !key || !host) {
  console.error('usage: oss-presign.mjs <METHOD> <bucket> <key> <host> [ttl] [vhost|path]');
  process.exit(2);
}
const ttl = parseInt(ttlS || '10800', 10);
const m = method.toUpperCase();

const cfg = JSON.parse(fs.readFileSync(`${os.homedir()}/.aliyun/config.json`, 'utf8'));
const prof = (cfg.profiles || []).find((p) => p.name === (process.env.ALI_PROFILE || cfg.current))
  || cfg.profiles[0];
const AK = prof.access_key_id;
const SK = prof.access_key_secret;
const token = prof.sts_token || prof.security_token || '';

const expires = Math.floor(Date.now() / 1000) + ttl;
const sts = token
  ? `${m}\n\n\n${expires}\n/${bucket}/${key}?security-token=${token}`
  : `${m}\n\n\n${expires}\n/${bucket}/${key}`;
const sig = crypto.createHmac('sha1', SK).update(sts, 'utf8').digest('base64');
const enc = encodeURIComponent;

const query = `OSSAccessKeyId=${enc(AK)}&Expires=${expires}&Signature=${enc(sig)}`;
let url = style === 'path'
  ? `http://${host}/${bucket}/${key}?${query}`
  : `http://${host}/${key}?${query}`;
if (token) url += `&security-token=${enc(token)}`;
process.stdout.write(url);
