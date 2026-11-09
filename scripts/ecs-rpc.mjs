// Minimal Alibaba RPC (Signature V1, HMAC-SHA1) caller — ECS by default.
//
// Needed because the `aliyun` CLI rejects or misreports the calls a rotation
// depends on: `--Features.NvmeSupport` is refused outright (so an imported
// image silently defaults to NvmeSupport=unsupported and ReplaceSystemDisk
// then refuses), and DescribeImages filtered by ImageId returns TotalCount 0
// in cn-beijing-i.
//
// Usage:
//   node scripts/ecs-rpc.mjs '{"Action":"ModifyImageAttribute","RegionId":"cn-beijing",...}'
//   node scripts/ecs-rpc.mjs '{"Action":"UnassociateEipAddress","_host":"vpc","_version":"2016-04-28",...}'
//
// `_host` selects the product endpoint (vpc -> vpc.aliyuncs.com), `_version`
// overrides the API version; both are stripped before signing. Credentials
// come from the aliyun CLI profile (ALI_PROFILE, else the current profile).
import fs from 'node:fs';
import crypto from 'node:crypto';

const cfg = JSON.parse(fs.readFileSync(process.env.HOME + '/.aliyun/config.json', 'utf8'));
const prof = cfg.profiles.find((x) => x.name === (process.env.ALI_PROFILE || cfg.current));
if (!prof) { console.error('aliyun profile not found'); process.exit(2); }
const ak = prof.access_key_id, sk = prof.access_key_secret, tok = prof.sts_token;

const params = JSON.parse(process.argv[2]);
const hostKey = params._host || 'ecs';
const hostMap = { ecs: 'ecs.aliyuncs.com', vpc: 'vpc.aliyuncs.com', sts: 'sts.aliyuncs.com' };
const apiHost = hostMap[hostKey] || hostKey;
const apiVersion = params._version || '2014-05-26';
delete params._host;
delete params._version;
params.Format = 'JSON';
params.Version = apiVersion;
params.AccessKeyId = ak;
params.SignatureMethod = 'HMAC-SHA1';
params.SignatureVersion = '1.0';
params.Timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
params.SignatureNonce = crypto.randomUUID();
if (tok) params.SecurityToken = tok;

const enc = (s) => encodeURIComponent(String(s)).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
const canon = Object.keys(params).sort().map((k) => enc(k) + '=' + enc(params[k])).join('&');
const toSign = 'POST&' + enc('/') + '&' + enc(canon);
params.Signature = crypto.createHmac('sha1', sk + '&').update(toSign).digest('base64');

const body = Object.keys(params).map((k) => enc(k) + '=' + enc(params[k])).join('&');
const res = await fetch('https://' + apiHost + '/', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body,
});
const text = await res.text();
console.log('HTTP', res.status);
console.log(text);
if (!res.ok) process.exit(1);
