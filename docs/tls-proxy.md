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
    "session_timeout_secs": 120,   // hard ceiling for one session
    "stall_timeout_secs": 20,       // silence on the relayed connection = stall
    "commit_timeout_secs": 60,      // ceiling on the commitment handshake
    "dial_spacing_ms": 1500,        // base spacing between dials to ONE target address
    "signing_key_pem": null,     // null/absent = fresh per-boot RSA-2048 key
    "restart_token": null,       // v233: operator token for POST /proxy/restart
    "relay_targets": [           // hosts a prover may commit to
      "api-m.paypal.com",
      "api-m.sandbox.paypal.com",
      "sandbox.paypal.com",      // the site a person logs into …
      "www.sandbox.paypal.com"   // … and where it redirects to
    ]
  }
}
```

### Restarting the notary without a reboot

The notary is a supervised child process that mints a fresh signing key every
boot, so a wedged session, a policy change or a key that has to be retired used
to mean rebooting the whole enclave — the only other thing that restarts it.

With `restart_token` set in the config, `POST /proxy/restart` with the header
`X-Proxy-Restart: <token>` asks the supervisor to kill and re-exec the child.
The token lives in the instance's `user_data` next to the PayPal secrets, so it
is exactly as reachable as the rest of the config. Without a token the route
does not exist and answers `404`; a wrong token gets the same `404`, because a
caller who cannot use the route is not told it is there. `/proxy/health` reports
`restarts`, so the cycle is observable.

The envelope cache follows the new key by itself (`/debug/envelope` probes the
child on every request and re-mints when the fingerprint changes), which
`scripts/check-live-proxy-restart.mjs` proves end-to-end on a live instance.
`rotate-alibaba.sh` runs that check in its verify phase on every release: it
reads `restart_token` from the config it just pushed, so a deployment whose
route is unconfigured — or whose cache stops following the key — fails the
rotation instead of an auditor's binding check days later.

Example:

```bash
curl -sS -X POST https://login.airma.de/proxy/restart \
  -H "x-proxy-restart: $PROXY_RESTART_TOKEN"
# {"service":"tls-proxy","restarting":true,"restarts_before":0}
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
| `GET :8081/pubkey` | the attestation signing key + its SPKI-DER SHA-256 — what the enclave's quoted report names |
| `GET :8081/attestations` | ids, server names, timestamps |
| `GET :8081/attestations/{id}` | the signed attestation |
| `GET :8081/refusals` | why the last 32 sessions were refused, newest last |
| `GET https://<domain>/proxy/health` | same liveness answer on the public origin |
| `GET https://<domain>/proxy/refusals` | the refusal ring on the public origin, hostnames fingerprinted |
| `GET https://<domain>/proxy/attestations` | the recorded sessions on the public origin: id, host fingerprint, time |
| `GET https://<domain>/proxy/attestations/{id}?sent_sha256=&received_sha256=` | **your own** signed record, from anywhere: served only when both digests match |

Since v236 the same verdict also reaches the **prover**, over the commitment
protocol: a commit whose host is not in the boot-time `relay_targets` (or whose
pinned address no longer connects) is answered with a rejection that names the
reason — `… is not in this notary's boot-time relay_targets (lookup failed: …)`
— instead of a bare disconnect. Before that, a prover saw only
`commitment protocol failed to receive response caused by: unexpected end of
file`, and the explanation existed only in the operator's refusal ring.

`/refusals` answers the operator's question "why was that session rejected?"
without a shell: each entry is `{at, kind, reason}`, where `kind` is `rejected`
(a verdict was reached and refused — MPC mode, no revealed server identity, a
mismatched name, a transcript over the bound), `stalled` (nothing moved for a
stall bound — the relayed connection was silent for `stall_timeout_secs` because
the target's edge accepted the TCP connection and then said nothing, or the
prover connected and stopped answering during the commitment handshake for
`commit_timeout_secs`; retryable, see "Bursts and stalls" below) or `timeout` (no verdict in `session_timeout_secs`, with the last thing
the session did before it ran out — normally the address it was relaying to). Every refusal names its own cause,
so a prover who got no answer at all has to be told what went wrong rather than
being left with a bare disconnect. The reason quotes the prover's own commit, so it is
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

### Who may download a transcript

A prover who is not sitting on the VM still needs the signed record — that is
their evidence. `GET /proxy/attestations/{id}` serves it to a caller that
presents `sent_sha256` **and** `received_sha256`, the pair the record itself
signs over. That pair is a capability, not a password:

* a prover computes both digests from the bytes their own proof reveals (TLSNotary
  hands the revealed transcript to the prover, and to nobody else);
* the public list never carries either digest, so reading it is not enough;
* a wrong pair, an unknown id, a malformed digest and a missing parameter all
  answer the same `404 {"error":"no such attestation in this boot"}`, so the
  route cannot be used to test guesses about other people's sessions;
* the bytes are relayed as text, never re-serialised — the signature covers the
  field order the proxy stored (v221), so a JSON round-trip here would hand the
  prover a record that cannot verify.

There is no stronger capability to bind: the TLSNotary session carries no
prover-chosen nonce this notary could key a token to, and any server-generated
token would have no way to reach the prover, since the notary never speaks after
the session ends. The transcript is the only secret both sides already hold.

Loopback reads stay queryless: `GET :8081/attestations/{id}` with no parameters
still serves the record to whoever has a shell on the VM.

The attestation API binds loopback on purpose: the bytes are read by whoever
already has a shell on the VM (or a future in-guest collector). The public routes
relay the refusal ring, the session list, and — only to a caller that presents
the transcript digests — that caller's own record. Session traffic never passes
through the HTTPS listener either, so the PayPal TLS certificate is not involved
in a proof.

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

The signature covers the **first eleven fields in that order** — the ten
`AttestedBody` fields above plus `truncated` — serialized as JSON
(`serde_json` preserves declaration order, so a verifier rebuilds the exact bytes
by copying them out of the response in the same order and dropping only
`enclave_pubkey_pem`, `signature_alg`, `signature_b64`). The public key is in the
response, so verification needs no shared secret.

`truncated` is inside the signature on purpose: it is the record's claim that the
transcript is complete, so a relay that flipped it to `false` must invalidate the
signature. (This paragraph said "ten fields" until v236, which is exactly how an
independent verifier written from this document fails on every real record — the
implemented body has eleven, and `verify-proxy.html` checks all eleven.)

What makes that key trustworthy is a second document, not the record: the
enclave's attestation report publishes `session_context.proxy_signing_key` with
the same PEM and its `pubkey_sha256` (SHA-256 of the SPKI DER). The report body is
signed by the enclave's identity key, and the TDX quote's `report_data` commits to
that identity key together with `/init` and the disk manifest — so the notary key
is covered by the same hardware measurement that covers the PayPal flow. A
verifier compares the record's key against the report's; it never has to take the
record's word for whose key it is.

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

## Verifying an attestation0. Open `verify-proxy.html` (in this repository, or saved to disk) and paste the
   attestation into it, plus — in the second box — this boot's attestation
   report (`GET /debug/envelope`, or the report your login returned). The page
   loads nothing — no CDN, no fonts, no fetch — because every check it makes is
   RSA PKCS #1 v1.5 / SHA-256 through WebCrypto. It cuts the signed byte range
   out of *your* copy of the file (falling back to dropping insignificant
   whitespace if you re-formatted it), verifies the signature over exactly
   those bytes, recomputes both digests, and compares the record's key
   fingerprint with the one the report names (see step 4).
1. Fetch `GET :8081/attestations/<id>`.
2. Rebuild the signed byte string (first **eleven** fields, in order, compact
   JSON — `truncated` is signed too).
3. Check `signature_b64` against `enclave_pubkey_pem` (RSA PKCS#1 v1.5, SHA-256).
4. Bind `enclave_pubkey_pem` to the enclave: the key is per-boot and
   self-asserted, so the record alone proves nothing about who holds it. The
   pipeline is:
   `GET :8081/pubkey` → `{pubkey_pem, pubkey_sha256}` (SHA-256 over the
   SubjectPublicKeyInfo DER) → the enclave fetches that same endpoint while
   minting its attestation report and publishes it as
   `session_context.proxy_signing_key = {available, algorithm, signature_alg,
   pubkey_pem, pubkey_sha256, reported_sha256}` → the report body is signed by
   the enclave's identity key, and the TDX quote's `report_data` commits to that
   identity key **and** to `/init` and the disk manifest → so a fingerprint match
   is a chain to the hardware, not a new anchor. Audit the report itself with
   `verify.html`; `verify-proxy.html` performs the fingerprint comparison and
   says plainly that the quote check lives there.
   The enclave recomputes the fingerprint from the PEM it received rather than
   copying the child's `pubkey_sha256`; the child's claim is kept alongside as
   `reported_sha256` so a disagreement is visible instead of blessed.
   A notary restart mints a new key, so the enclave checks the live key on
   every `/debug/envelope` request (a loopback `GET /pubkey`, no quote) and
   re-mints the cached body the moment it differs. Asking the enclave again is
   therefore enough to get a report that names the running key; the cache can
   only go stale while the notary is unreachable, and then no new key exists to
   name. The page still fails closed on a mismatch instead of assuming.
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

**Where the wait goes, and what actually shortens it.** A session spends its time
before `commit accepted` — **8–41 s** through the deployed notary — and then a
**2–4 s** TLS handshake and proof. That commit phase is MPC setup between prover
and notary, **not** the notary's dial: the notary logs its own connect at **35 ms**
(`relaying TLS to www.sandbox.paypal.com (146.75.123.1:443)`, immediately after
`accepted`), and a TCP connect to PayPal from the operator host measures 27–40 ms.
Pinning an edge address therefore saves a DNS lookup and nothing else.

What does move it is distance to the notary. Same prover, same page, same sandbox
host, with `tls-proxy` running on the operator's own machine (loopback notary):
commit **3.5 s**, whole session **6.1 s**, 200 OK — against 8–41 s commit through
`101.200.178.251` (215 ms RTT). The commit is round-trip bound on a long link,
and the deployed notary is a 2-vCPU spot instance, which is why its own number
varies from run to run.

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

## Bursts and stalls

`api-m.paypal.com` sits behind Cloudflare (`104.16.124.74`), and that edge
tolerates only a few relayed TLS handshakes arriving from one source address at
the same instant. Beyond that it accepts the TCP connection and then never sends
a ServerHello — nothing moves again. Measured on the deployed notary (2026-11-10,
one boot, 2 vCPU, one EIP):

| wave (all `api-m.paypal.com`) | result |
|---|---|
| sequential | 10/10 |
| 4 simultaneous (3 waves) | 12/12 |
| 6 simultaneous | 5/6 |
| 8 simultaneous | 3/8, 5/8 |
| 8 simultaneous, 0.4 s apart | 3/8 |
| 8 simultaneous, 1.5 s apart | 8/8 |
| 8 simultaneous to `api-m.sandbox.paypal.com` (Fastly `146.75.123.1`) | 8/8 |
| 8 raw TLS handshakes from another host to `104.16.124.74` | 8/8 in 71 ms |

The notary is not the limit: it serves eight simultaneous sessions to a
different edge from the same process, and its transcript bytes are tiny (85 B
sent, 5.7 KB received per session), so neither the 2 vCPU nor the 5 Mbps EIP is
involved. What breaks is the timing of handshakes into Cloudflare from one
address.

Two mechanisms answer that, both fail-soft:

- **Dial spacing** (`dial_spacing_ms`, default 1500): the notary spaces its own
  outbound dials per target ADDRESS, so a burst of provers arrives at the edge
  spaced out. A session that waits is logged and reported as `queued N.Ns for a
dial slot to <host> (<addr>)`, which is a queue, not a stall. Eight sessions cost
  at most `7 × spacing` of extra wait for the last one.
- **Adaptive spacing** (v240): the base is a starting point, not a constant. A
  session refused as `stalled` widens that ADDRESS's spacing by half again, up
  to `4 × dial_spacing_ms` (6 s on the default); each run of 4 sessions without
  a stall narrows it by a third, never below the base. An edge having a bad
  minute is then dialled less insistently instead of having its sessions thrown
  away, and a healthy edge pays only a few sessions of extra latency afterwards.
  Widening is immediate and narrowing is gradual on purpose — backing off too
  late loses sessions, recovering too fast only costs a little latency. The
  spacing in force is per address in the child's own `GET /health`
  (`dial_spacing_ms`, `dial_spacing_base_ms`, `dial_spacing_max_ms`); the
  enclave's `/proxy/health` relays the counters, not that map.
- **Stall verdict** (`stall_timeout_secs`, default 20): a relayed connection that
  moves no byte for this long is refused as `stalled`, naming the phase and
  telling the prover to retry. Before this, such a session sat until the 120 s
  `session_timeout_secs`, holding its slot for 100 s of nothing.
- **Commit ceiling** (`commit_timeout_secs`, default 60): the commitment
  handshake has no target connection yet, so the stall watchdog has nothing to
  watch — and tlsn's preprocessing is CPU-bound on the prover, quiet for seconds
  between messages (2 s alone, 16 s under an eight-wide wave). A prover that
  connects and then dies here used to hold its slot for the full 120 s; it is now
  refused as `stalled` at this bound, with "retry this session" in the reason.

A prover should therefore retry once when an attempt ends before its verdict
(the bundled harness does): with spacing in place a retry lands on a healthy
handshake. `tls-proxy/tests/live.rs` defaults to `LIVE_ATTEMPTS=2` for exactly
that reason.

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
  the verdict. The refusal says where it had got to (`last progress: relaying
  TLS to <host> (<address>)`): the address comes from the boot-time pin and
  cannot be re-derived afterwards, so a stall with no address in it is
  unactionable for an operator. A relayed connection that goes silent is cut at
  `stall_timeout_secs` instead, so a stalled session frees its slot in 20 s, and
  a prover that never finishes committing is cut at `commit_timeout_secs` (60 s).
- Concurrent sessions are bounded by the target edge, not by the guest: 1–2 at a
  time is unconditionally safe, 4 works against both measured edges, and the
  notary itself serves 8 (see "Bursts and stalls").
- `tlsn` is alpha software; the pinned revision is the one this crate was written
  against, not an audited one.
