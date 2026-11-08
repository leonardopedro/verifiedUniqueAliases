# The TLSNotary web-attestation proxy (second service)

The PayPal flow answers one question about one provider. This service answers the
same *kind* of question about **any HTTPS website**: a prover commits to a TLS
session with some host, this service — running inside the same TDX guest as
`/init` — relays that session, verifies the revealed presentation, and signs what
it saw with a key that never leaves the VM.

It is a **TLSNotary proxy-mode verifier**. `../tlsn` is the source; the crate here
(`tls-proxy/`) is a separate package with its own lockfile, pinned to the tlsn
commit the local checkout is on.

Why proxy mode and not MPC: proxy mode is the variant where the verifier sees the
cleartext TLS bytes it forwards, so arbitrary hosts can be attested by one
service with no extra MPC machinery. The trade-off is stated plainly below.

## Layout

```
tls-proxy/            separate crate (own Cargo.toml + lockfile)
  src/main.rs         session listener + signed attestations + loopback API
build-tls-proxy-image.sh   builds the dual-service disk (TLS_PROXY=1)
Dockerfile.alibaba    ARG TLS_PROXY=0|1 — 0 is the PayPal-only image, unchanged
.github/workflows/build-tls-proxy.yml   the second CI workflow
config.proxy.example.json   a config with both services enabled
```

`src/main.rs` (the enclave) gains one config block and one supervision task:
when `services.tls_proxy.enabled` is true it opens exactly one inbound port on the
nftables firewall, pins `relay_targets` while DNS is still open, spawns
`/tls-proxy` as a child of PID 1, and restarts it with a 2 s → 60 s backoff.
Nothing else about the PayPal path changes.

## Service selection

`services` is optional; **absent means PayPal only**, i.e. the deployment that
existed before this feature.

```json
"services": {
  "paypal": true,
  "tls_proxy": {
    "enabled": true,
    "session_port": 8443,        // inbound TLSNotary sessions
    "api_port": 8081,            // loopback-only attestation API
    "session_timeout_secs": 120,
    "signing_key_pem": null,     // null/absent = fresh per-boot RSA-2048 key
    "relay_targets": [           // hosts a prover may commit to
      "api-m.paypal.com",
      "api-m.sandbox.paypal.com",
      "sandbox.paypal.com",      // the site a person logs into …
      "www.sandbox.paypal.com"   // … and where it redirects to
    ]
  }
}
```

### Relay targets

`relay_targets` is the list of hosts a prover may commit to, and it is the whole
point of a *general* notary: everything the proxy can reach is decided here.
Absent, it defaults to the two PayPal API hosts and the sandbox website
(`sandbox.paypal.com`, `www.sandbox.paypal.com`).

Both sandbox names are listed because a session attests exactly one TLS
connection and does not follow redirects: `sandbox.paypal.com` answers `301` to
`www.sandbox.paypal.com`, so a prover who commits to the bare name gets a
redirect in the transcript, and a prover who wants the actual page has to commit
to the `www` host. Production `paypal.com`/`www.paypal.com` are deliberately not
in the default set — add them here if you want live-site sessions.

Each name is resolved **once, at boot, while DNS is still open**, written into
`/etc/hosts`, and its addresses become the only destination on 443 the post-boot
firewall allows beyond the PayPal endpoint and the self-report sink. After that
the resolver is gone by design, which is why the list is fixed at boot rather
than looked up per session: a proxy that could resolve at will would be exactly
the exfil channel the lockdown exists to close.

Entries are validated at boot, and a bad list is a fail-closed error rather than
a warning: a `scheme://`, a `:port`, a path, a `*.wildcard`, a bare hostname with
no dot, a duplicate (case-insensitive) or an empty list all stop the boot with
the offending entry named. At most 32 entries are accepted — every one costs a
hosts line and an address in a firewall rule.

Consequence worth stating plainly: adding a target lets **any** prover commit to
it, not just the operator. Widen the list deliberately.

#### Hosts whose addresses rotate, and IP literals

Because the addresses are resolved once per boot, a target whose CDN answers
move (Cloudflare rotates `api-m.sandbox.paypal.com` regularly) keeps working
only until the next boot re-resolves it — a reboot is the refresh mechanism, by
design. If a session fails at connect right after an address change, restart the
instance; there is no per-session lookup to fall back on, and adding one would
reopen the DNS channel the lockdown closes.

When the boot resolver is wrong, or the address you want is a specific one, write
the mapping yourself with `host@address`:

```json
"relay_targets": ["www.sandbox.paypal.com@151.101.195.1"]
```

That entry is **not** resolved: the address is written into `/etc/hosts` as
`151.101.195.1 www.sandbox.paypal.com` and admitted on 443, so the proxy dials
exactly that address for that name. It is the supported way to keep a host with a
rotating or boot-unavailable address reachable without widening the list. The
left side must be a hostname and the right side an IPv4 address (IPv6 is refused —
the egress rule matches `ip daddr` only); a duplicate name with two addresses is
fine, two entries for the same name are not.

A bare IPv4 literal is accepted too, but understand what it buys: it opens 443 to
that address with no DNS and no hosts entry, yet **nothing can be relayed to it**,
because a prover commits a *server name* and tlsn rejects an address as one
(`InvalidDnsNameError`, observed against this build). Literals are for keeping an
address reachable; use `host@address` when you actually want a session.

| Configuration | What runs |
|---|---|
| no `services` block, or `"tls_proxy": {"enabled": false}` | PayPal only (original image, original boot) |
| `"paypal": true` + `"tls_proxy": {"enabled": true}` | both — same VM, same hostname, different ports |
| `"paypal": false` + proxy enabled | proxy only: PayPal credentials are not required, the OAuth routes are not served |

`require_credentials` follows the switch: it refuses a config that would serve
nothing, and stops demanding PayPal app credentials only for the proxy-only case.

## Endpoints

| Where | What |
|---|---|
| `TCP :8443` (`session_port`) | one TLSNotary session per connection |
| `GET :8081/health` | counters: sessions total/ok/failed, stored attestations, stored refusals, uptime |
| `GET :8081/attestations` | ids, server names, timestamps |
| `GET :8081/attestations/{id}` | the signed attestation |
| `GET :8081/refusals` | why the last 32 sessions were refused, newest last |
| `GET https://<domain>/proxy/health` | same liveness answer on the public origin |
| `GET https://<domain>/proxy/refusals` | the refusal ring on the public origin, hostnames fingerprinted |
| `GET https://<domain>/proxy/attestations` | the recorded sessions on the public origin: id, host fingerprint, time |

`/refusals` answers the operator's question "why was that session rejected?"
without a shell: each entry is `{at, kind, reason}`, where `kind` is `rejected`
(a verdict was reached and refused — MPC mode, no revealed server identity, a
mismatched name, a transcript over the bound) or `timeout` (no verdict in
`session_timeout_secs`). The reason quotes the prover's own commit, so it is
capped at 400 characters; these records are diagnostics, never evidence, and
they are not signed.

`/proxy/refusals` exists because a dead session is the one thing an operator
most needs to explain and the boot log is the one thing they often cannot read:
no shell on a managed importer, a spot instance whose serial console has already
scrolled. Health only proves the child is running. The public route relays the
same ring, so "sessions_failed went up by one" becomes "the commit was refused
because …" over plain HTTPS.

It is not a verbatim copy. A refusal reason quotes the host the prover committed
to, and a notary must not publish what other provers were looking at, so
host-shaped tokens are replaced by a stable fingerprint — `api-m.paypal.com`
becomes `host:9f2c0a1b`, the same fingerprint for the same name every time, so
repeated attempts still line up without the name leaving the VM. Numbers that
merely look dotted (`1.99.0`, a byte count) are left alone, since stripping them
would cost the diagnosis without hiding anything. The `redaction` field in the
response says this in-band, and the unredacted text remains at
`GET :8081/refusals` and in the boot log for whoever does have a shell.

`/proxy/attestations` answers the other half of the same question — "was my
session recorded, and under which id?" — for the same operator with no shell. It
relays `GET :8081/attestations` with each `server_name` replaced by the very
fingerprint `/proxy/refusals` uses, so a session can be lined up with the refusal
it replaced without either document naming a host. It publishes the **list only**:
ids, fingerprints, timestamps. The transcript bytes and the signature stay on the
loopback API (`GET :8081/attestations/{id}`), because serving them on a shared
origin would hand every visitor everyone else's transcripts.

The attestation API binds loopback on purpose: the bytes are read by whoever
already has a shell on the VM (or a future in-guest collector), and the two
public routes relay nothing but the refusal ring and the session list. Session
traffic never passes through the HTTPS listener either, so the PayPal TLS
certificate is not involved in a proof.

## The attestation

```json
{
  "version": "tls-proxy/1",
  "session_id": "…32 hex…",
  "server_name": "example.com",
  "notarized_at": 1793932800,
  "sent_len": 214, "received_len": 9182,
  "sent_sha256": "…", "received_sha256": "…",
  "sent_b64": "…", "received_b64": "…",
  "truncated": false,
  "enclave_pubkey_pem": "-----BEGIN PUBLIC KEY-----…",
  "signature_alg": "RSA-PKCS1-v1_5-SHA256",
  "signature_b64": "…"
}
```

The signature covers the **first ten fields in that order**, serialized as JSON
(`serde_json` preserves declaration order, so a verifier rebuilds the exact bytes
by copying them out of the response in the same order and dropping
`enclave_pubkey_pem`, `signature_alg`, `signature_b64`). The public key is in the
response, so verification needs no shared secret; what makes the key trustworthy
is the hardware quote over the VM, which covers the measured initramfs that
contains this binary.

## What it proves, and what it does not

Proves: this enclave relayed a TLS session with `<server_name>`, accepted a
presentation that revealed that name, and the revealed bytes hash to the digests
it signed.

Does **not** prove: that the website's content is true; anything about bytes the
prover redacted; that the prover is a particular person. In proxy mode the
verifier sees cleartext while relaying, so the service learns the plaintext of the
session — that is inherent to proxy mode and is the main reason MPC mode exists.
A deployment that must not learn the plaintext should not enable this service.

## Build

```sh
bash build-tls-proxy-image.sh        # docker or rootless podman
# → output-tls-proxy/disk-tls-proxy.raw, tls-proxy-bin, initramfs-dual.img,
#   SHA256SUMS
```

That is the same pipeline as the PayPal-only image with `--build-arg
TLS_PROXY=1`. Without the arg, `Dockerfile.alibaba` produces the PayPal-only
disk — the only trace of the proxy is an empty `/tls-proxy-bin` placeholder that
never reaches the initramfs.

The proxy is compiled with its own toolchain (`TLS_PROXY_RUST_VERSION`, default
`1.99.0`) because the tlsn tree needs rustc ≥ 1.95, newer than the enclave's
pinned toolchain. That toolchain is installed only in the `TLS_PROXY=1` branch,
so the enclave binary keeps building with the pinned `RUST_VERSION`.

The dual-service disk has **its own RTMR2 and self-measure pins** (the initramfs
now contains `/tls-proxy`; the CA bundle it validates hosts against was already
shipped for the PayPal flow). Rotate the pins before an audit trusts it; CI
prints a notice with the digests.

## Deploy

```sh
bash import-alibaba-image.sh        # import output-tls-proxy/disk-tls-proxy.raw
ALI_IMAGE_ID=m-… bash deploy-alibaba.sh
```

Ship a config with the `services` block (see `config.proxy.example.json`) as
`user_data`. To run the same image as PayPal-only, ship a config without it — no
rebuild, no different image.

## Verifying an attestation

0. Open `verify-proxy.html` (in this repository, or saved to disk) and paste the
   attestation into it. It loads nothing — no CDN, no fonts, no fetch — because
   every check it makes is RSA PKCS#1 v1.5 / SHA-256 through WebCrypto. It cuts
   the signed byte range out of *your* copy of the file (falling back to dropping
   insignificant whitespace if you re-formatted it), verifies the signature over
   exactly those bytes, recomputes both digests, and reports the one thing it
   cannot check: that `enclave_pubkey_pem` is the enclave's key. Do that with the
   VM's hardware quote.
1. Fetch `GET :8081/attestations/<id>`.
2. Rebuild the signed byte string (first ten fields, in order, compact JSON).
3. Check `signature_b64` against `enclave_pubkey_pem` (RSA PKCS#1 v1.5, SHA-256).
4. Bind `enclave_pubkey_pem` to the VM's TDX quote (the quote is what makes the
   key the enclave's, not the operator's).
5. Compare `sent_sha256`/`received_sha256` with the base64 bytes if you need the
   transcript itself.

## Testing it locally

```sh
cargo test --manifest-path tls-proxy/Cargo.toml --test session
```

This runs the real binary against tlsn's own fixture HTTPS server with a real
prover, then fetches the stored attestation and verifies the signature — no mock
in the path. It needs one test-only knob, `TLS_PROXY_TARGET_ADDR`, which pins the
relay target at a socket address instead of resolving the committed name on :443
(the fixture's certificate says `test-server.io` but it listens on loopback).
Unset — the shipped configuration — the proxy resolves the name it was given.

The suite also covers the refusal paths, each asserting both the proxy's
counters and the reason it logged: an MPC commit (rejected with
`this notary accepts proxy-mode sessions only`, and nothing signed), an honest
session whose transcript exceeds the bound (`TLS_PROXY_MAX_TRANSCRIPT_BYTES`
lowers it to 64 bytes, since the fixture website cannot be made to answer with
9 MiB), and a peer that connects and never speaks (closed at the session
timeout, counted failed, no attestation).

## Live smoke against the deployed notary (PayPal sandbox)

`tls-proxy/tests/live.rs` runs the same prover path a real client would, but
against the **deployed** notary and a real sandbox page, so "does the service
actually relay PayPal's sandbox?" is a command instead of an anecdote. It is
`#[ignore]`d: it needs egress and a reachable notary.

```sh
# every PayPal sandbox host the notary allows, one session each
for target in "sandbox.paypal.com /" \
              "sandbox.paypal.com /robots.txt" \
              "www.sandbox.paypal.com /robots.txt"; do
  set -- $target
  LIVE_NOTARY=101.200.178.251:8443 LIVE_SERVER=$1 LIVE_PATH=$2 \
    cargo test --manifest-path tls-proxy/Cargo.toml --test live -- --ignored --nocapture
  echo "--- $1$2: exit $?"
done
```

The default target (`api-m.paypal.com/`) needs only the notary address:
`cargo test --manifest-path tls-proxy/Cargo.toml --test live -- --ignored --nocapture`.

Knobs: `LIVE_NOTARY`, `LIVE_SERVER` (must be on the notary's relay-target
allowlist — see *Relay targets*), `LIVE_PATH`, `LIVE_CA_BUNDLE` (default: the
host bundle, so the relayed chain has to reach a real public root), and
`LIVE_ATTEMPTS` (default 3), which retries a session that ends without a verdict
and reports the attempt that passed.

A passing run prints, in this order, and ends in `test result: ok`:

```
--- attempt 1/3: www.sandbox.paypal.com/signin
[   1.3s] connected to notary 101.200.178.251:8443; committing www.sandbox.paypal.com
[  36.6s] commit accepted — the notary is relaying TLS to www.sandbox.paypal.com
[  36.6s] relayed TLS handshake started
[  38.4s] relayed response status: 200 OK
[  43.8s] transcript: sent 103 B, received 38002 B
[  47.4s] prover finished: presentation complete
test result: ok
```

Sessions recorded against the deployed notary on 2026-11-08:

| Target | Result | Transcript |
|---|---|---|
| `sandbox.paypal.com/` | `301` | 89 B sent / 5,528 B received |
| `sandbox.paypal.com/robots.txt` | `200` | 99 B / 3,479 B |
| `www.sandbox.paypal.com/robots.txt` | `200` | 107 B / 3,429 B |
| `www.sandbox.paypal.com/signin` | `200`, 3 runs of 5 (one on a retry) | ~103 B / ~38,000 B |

**Where the minute goes, and why a session occasionally dies.** The timings above
are the shape of every session: a second to reach the notary, then **29–41 s
before the commit is accepted**, then a **2–4 s** TLS handshake and request, then
the proof. The long wait is the notary dialling the site: it connects to the
committed host from Beijing before it answers the commit, so the SYNs and the
edge's own queueing are charged to the prover's commit. The MPC handshake itself
is not slow — 1.8 s for a 33 KB page.

That single dial is also the flaky part, which is why `LIVE_ATTEMPTS` exists and
defaults to 3. Observed failure shapes, all with the same binary and path:
`hyper::Error(IncompleteMessage)`, `server closed during TLS handshake`,
`session closed while the prover was connected` (a full `200 OK` arrived first),
and on the origin `GET /proxy/refusals` reporting `failed to receive proxy
finished message caused by: unexpected end of file`. None of them is a size
limit: the same 33 KB page passes intermittently, and a surviving session relays
the **whole** page, the declared 33,069 B body included. Re-run before treating a
failure as a regression, and read the refusal reason — it separates "the site
closed on us" from "our side refused".

NixOS, if you rebuild the tests locally: `openssl-sys` links only against an
ELFCLASS64 store output, e.g.
`OPENSSL_LIB_DIR=/nix/store/kysvfcf8d8v26rr32xfqji8ri2lczlqk-openssl-3.6.5/lib`
with `OPENSSL_INCLUDE_DIR=…-openssl-3.6.5-dev/include`. Other `openssl-3.6.5`
outputs in the store are 32-bit and fail with `incompatible with
elf64-x86-64`.

## Limits worth knowing

- Transcripts over 8 MiB are refused rather than stored: the whole transcript
  lives in guest RAM. `TLS_PROXY_MAX_TRANSCRIPT_BYTES` lowers the bound (tests
  use it); the shipped default is 8 MiB.
- Only port 443 is ever dialled, so the service cannot be used as a generic TCP
  relay. `TLS_PROXY_TARGET_ADDR` overrides that target for tests only; it accepts
  a socket address, never a name or a port from the prover.
- At most 256 attestations are retained, per boot; the queue is FIFO.
- A session that produces no verdict within `session_timeout_secs` is closed and
  counted failed, and its driver is aborted so the peer's socket cannot outlive
  the verdict.
- `tlsn` is alpha software; the pinned revision is the one this crate was written
  against, not an audited one.
