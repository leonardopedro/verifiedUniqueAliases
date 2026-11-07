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
nftables firewall, spawns `/tls-proxy` as a child of PID 1, and restarts it with a
2 s → 60 s backoff. Nothing else about the PayPal path changes.

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
    "signing_key_pem": null      // null/absent = fresh per-boot RSA-2048 key
  }
}
```

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

The attestation API binds loopback on purpose: it is read by whoever already has
a shell on the VM (or a future in-guest collector), not by the internet. Session
traffic never passes through the HTTPS listener, so the PayPal TLS certificate is
not involved in a proof.

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
