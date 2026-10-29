'use strict';
// Hand-signed Alibaba RPC caller (Signature V1 HMAC-SHA1), zero dependencies.
// Same signing scheme as the repo's /tmp/ecs-call.mjs helper (AGENTS.md "API
// traps"): the code package is uploaded as a bare zip, so it must not need npm.
//
// Error model: any response carrying a non-success `Code` (HTTP 400 or not)
// throws with `"<product> <Action> failed: <Code> <Message>"`, so callers can
// retry on stock/permission/limit errors uniformly.

const crypto = require('crypto');

// product -> [api host, default version]
const HOSTS = {
  ecs: ['ecs.aliyuncs.com', '2014-05-26'],
  vpc: ['vpc.aliyuncs.com', '2016-04-28'],
};

const pct = (s) =>
  encodeURIComponent(String(s)).replace(
    /[!'()*]/g,
    (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase()
  );

// CanonicalizedQueryString -> StringToSign ("POST&%2F&<pct(canon)>")
function stringToSign(params) {
  const canon = Object.keys(params)
    .sort()
    .map((k) => pct(k) + '=' + pct(params[k]))
    .join('&');
  return 'POST&' + pct('/') + '&' + pct(canon);
}

/**
 * @param {object} cfg  {accessKeyId, accessKeySecret, securityToken?}
 * @param {string} product  key of HOSTS, or a bare host name
 * @param {string} version  API version
 * @param {object} args     flat RPC parameters, incl. `Action`
 * @returns {Promise<object>} parsed JSON response
 */
async function call(cfg, product, version, args) {
  const entry = HOSTS[product];
  const host = entry ? entry[0] : product + '.aliyuncs.com';
  const ver = version || (entry ? entry[1] : '2014-05-26');

  const params = Object.assign({}, args, {
    Format: 'JSON',
    Version: ver,
    AccessKeyId: cfg.accessKeyId,
    SignatureMethod: 'HMAC-SHA1',
    SignatureVersion: '1.0',
    Timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    SignatureNonce: crypto.randomUUID(),
  });
  if (cfg.securityToken) params.SecurityToken = cfg.securityToken;
  params.Signature = crypto
    .createHmac('sha1', cfg.accessKeySecret + '&')
    .update(stringToSign(params))
    .digest('base64');

  const body = Object.keys(params)
    .map((k) => pct(k) + '=' + pct(params[k]))
    .join('&');

  const res = await fetch('https://' + host + '/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch (e) {
    throw new Error(
      `${product} ${args.Action}: non-JSON response (HTTP ${res.status}): ${text.slice(0, 300)}`
    );
  }
  if (json.Code && json.Code !== 'Success' && json.Code !== 'OK') {
    throw new Error(
      `${product} ${args.Action} failed: ${json.Code} ${json.Message || ''}`.trim()
    );
  }
  if (!res.ok) {
    throw new Error(
      `${product} ${args.Action} failed: HTTP ${res.status} ${text.slice(0, 300)}`
    );
  }
  return json;
}

module.exports = { call, stringToSign, HOSTS };
