// failover-health.mjs — the judgement behind the smoke check's failover phase,
// kept pure so it can be exercised against recorded health shapes.
//
// The notary's `/proxy/health` reports `relay_endpoints` as
// `{address: {zero_byte_runs, last_byte_secs_ago}}`. Three questions are asked of
// it, and they are deliberately separate:
//
//   1. which addresses has this probe moved?      (`endpointRows` + a before/after diff)
//   2. which addresses is the host pinned to?     (`pinnedForHost`, from the config)
//   3. is the refusal aimed at ALL of them?       (`isTargetPolicyRefusal`)

import { existsSync, readFileSync } from 'fs';

/** The addresses the notary has learned something about, as plain rows. */
export function endpointRows(h) {
  const map = h?.relay_endpoints ?? {};
  return Object.entries(map).map(([addr, v]) => ({
    addr,
    strikes: Number(v?.zero_byte_runs ?? 0),
    struck: Number(v?.zero_byte_runs ?? 0) > 0,
    answered: v?.last_byte_secs_ago !== null && v?.last_byte_secs_ago !== undefined,
    idleSecs: v?.last_byte_secs_ago ?? null,
  }));
}

/**
 * The addresses a host is pinned to, from the deployment config's
 * `relay_targets` (`"host@a,b"`). Only that key is read, and nothing from the
 * config is echoed: it also carries the PayPal credentials.
 */
export function pinnedForHost(configPath, host) {
  if (!configPath || !existsSync(configPath)) return [];
  let config;
  try {
    config = JSON.parse(readFileSync(configPath, 'utf8'));
  } catch {
    return [];
  }
  const targets = config?.services?.tls_proxy?.relay_targets ?? config?.relay_targets ?? [];
  for (const line of Array.isArray(targets) ? targets : []) {
    const [name, addrs] = String(line).split('@');
    if (String(name).trim().toLowerCase() !== String(host).toLowerCase() || !addrs) continue;
    return addrs
      .split(',')
      .map((a) => a.trim())
      .filter(Boolean);
  }
  return [];
}

/**
 * Is this refusal about the target's policy rather than the notary?
 *
 * A host whose EVERY pinned address was struck, with not one byte ever answered,
 * is refusing the notary's egress outright: two addresses cannot fix a refusal
 * aimed at the source address, and the notary's failover has nothing left to try.
 * That reads very differently from "the failover is broken", because the same
 * notary serves other hosts in the same run.
 *
 * It requires the pin list to be *known* (config or explicit flag). An inferred
 * list would make a wrong pin that was never dialled look like a target refusal —
 * exactly the v243 bug this check exists to catch.
 */
export function isTargetPolicyRefusal(pins, rows, { pinsAreKnown = true } = {}) {
  if (!pinsAreKnown || pins.length === 0) return false;
  const byAddr = new Map(rows.map((r) => [r.addr, r]));
  return pins.every((addr) => {
    const row = byAddr.get(addr);
    return row && row.struck && !row.answered;
  });
}
