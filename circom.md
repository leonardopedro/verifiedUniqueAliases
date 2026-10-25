# Circom + SnarkJS in `verify.html` — the generic plan, adapted to **this** project (v188)

> This document started as a generic proposal (Circom/WASM escrow proving in the
> browser). It has been rewritten against the **actual state of
> `paypal-auth-vm`** — the shipped auditor, the real report schema, the measured
> identity sizes, the pin/parity discipline and the v188 flow redesign (two
> explicit login links, auto-generated key, callback auto-download, no claim
> step). Priorities, in order:
>
> 1. **Improve existing features first, no duplication** — the circuit consumes
>    the *same* canonical identity serialization the auditor already
>    reconstructs, the UI sits *inside* the existing green-audit → download
>    card, artifact integrity reuses the SRI/pin philosophy, and every existing
>    gate stays the enforcement point (the ZK layer adds a *new* capability —
>    selective disclosure — without creating a second trust path).
> 2. **New features only where justified** — the escrow credential itself:
>    today a decrypted report discloses the PayPal identity to *everyone* who
>    audits it. The credential lets a user prove "this Intel TDX quote is bound
>    to a **verified** PayPal identity" *without* revealing the identity, while
>    still letting a designated escrow recipient recover it later.
>
> §9 is the execution log of this plan.

---

## 1. Generic plan vs. this project — corrections that were mandatory

| Generic plan said | Reality in this repo | Adaptation |
|---|---|---|
| Public `H` = `report.paypal_user_info_raw_hash`, prover serializes "the identity JSON" ad hoc | The enclave hashes **`serde_json::to_string(minimized struct)`** — order `user_id, sub, verified_account, payer_id`, `null`s kept. The report embeds `paypal_user_info` through `serde_json::json!` (a **sorted map**), so naive `JSON.stringify` yields *alphabetical* order — the v178 live-debug finding. `runAudit()` already rebuilds the canonical bytes (`identityJson`) and fails closed on drift | The witness builder uses **exactly** that function (same key order, same `null`s). Harness **Test 38** asserts circuit input ≡ auditor `identityJson` ≡ enclave serde bytes. One serializer, zero duplication. |
| `MAX_JSON_BYTES = 128` ("~55 k constraints") | Real identity = **262 bytes**: `user_id`/`sub` are PayPal *identity URLs* (`https://www.paypal.com/webapps/auth/identity/user/…`, ~97 chars each). Captured live 2026-10-25 from `attestation-report-full-*.json` | `MAX = 300` (band **[248, 300]**), measured + 38 B margin. Constraint count is ~4× the generic estimate — see §4. |
| `Sha256(MAX_JSON_BYTES * 8)` from circomlib | circomlib's `Sha256(nBits)` pads with a **compile-time** length; the honest message length is **witness data** (`msg_len` varies per user), and 262 bytes needs 5 SHA blocks, not the claimed 2 | The circuit chains circomlib's `Sha256compression()` over a stream **it pads itself** from private `msg_len` (`0x80` at index `msg_len`, zeros, `uint64_be(msg_len*8)` in bytes 312..319). Band `[248,300]` keeps block count constant at **k = 5** (every honest length in the band pads into exactly 5 blocks). |
| `verified_account: true` enforced by… (implied by display) | The auditor checks it, but a *credential* that only reveals `H` proves nothing about it — selective disclosure needs it **in-circuit** | Window search for the exact 26-byte pattern `,"verified_account":"true"` (IsZero equalities, ~21 k constraints). This is the **one deliberate in-circuit duplicate** of an existing check: it is what lets the credential alone carry the "verified" claim. The auditor gate remains the enforcement point for audits; both are pinned by tests. |
| Bytes beyond the message unconstrained | A prover could then hide a fake pattern past the real end of the message | `raw[i] === 0` for every `i ≥ msg_len` (in-band), and `msg_len` itself is pinned by `H` (changing it changes the SHA length field ⇒ different digest). Sound. |
| Load snarkjs from a CDN (no pin) | This repo pins its only third-party script by **SRI** (`forge/1.3.1`, drift-guarded by Test 1) | snarkjs **0.7.5** is loaded **lazily** (only when a ZK action runs) from jsDelivr with a `sha384-…` `integrity` attribute computed from the exact npm bytes; missing ⇒ ZK UI fails closed, the audit itself is unaffected. |
| Serve `/zk/*.wasm`, `/zk/*.zkey` from "the server" | The enclave's egress budget is **25 MB/h per IP** — a ~60 MB zkey would burn it, and `verify.html` must stay a single self-contained file | Proving artifacts live in the repo's `zk/` and are served from the **pinned GitHub Pages origin** (`ZK_BASE`, same trusted host as the auditor copy, CORS-enabled). The **verification key is embedded in `verify.html`** so credential verification works offline in any copy, with no artifact fetch. |
| A separate "Generate ZK proof" flow | v188 UX: one auto-generated key, two explicit links, one audit card; the green audit already unlocks the 💾 download | The ZK controls live in a `#zkCard` that appears **only after a green audit**, beside the existing download. Credential generation reuses `downloadReportFile`'s Blob/anchor + filename sanitization pattern. |
| Credential embeds `tdx_quote_b64`, PCK cert, enclave signature verbatim | Those live in the audited report the verifier must check anyway | The credential binds to the report by **`report_sha256`** (exact audited envelope file bytes) + `identity_hash_hex` (the hardware-bound hash). Verification procedure = §6. |

### v188 flow context (what the ZK feature plugs into)

- **Key**: generated **automatically on page render** (trusted copies only),
  announced on-page in `#keyNotice` with a timestamp. The circuit's ephemeral
  scalar `r` is separate, fresh per proof, browser-only.
- **Login**: two explicit links — *verified status only* and *share full
  profile*. The morphing workflow button and the whole claim state machine are
  removed (Harness Test 36 pins their absence).
- **Callback** (`src/main.rs`): the ciphertext **downloads automatically on
  load**; the tab tries to close itself; what remains if it can't is only the
  attestation ciphertext + copy/re-download (Test 37).
- **Retrieval**: the downloaded `encrypted-attestation-report.json` goes back
  into the trusted tab's file picker → `decryptPastedBlob()` → audit (Test 33).

---

## 2. The statement proven

```
PRIVATE (witness)                          PUBLIC
─────────────────────                      ─────────────────────────────────
raw_json_bytes[300]  canonical D           identity_hash_bits[256]   H = SHA-256(D)
msg_len              |D| ∈ [248, 300]      escrow_pubkey_x, _y       BabyJubjub recipient
ephemeral_private_key  r                   ── outputs ──
                                            ephemeral_pubkey_x, _y    R = r·G
                                            verified_account_bit      1 ⇔ D contains the pattern
                                            ciphertext[10]            Poseidon-ECIES of D
```

- **271 public signals** (`258` public inputs + `13` outputs), order pinned by
  the harness:
  `[R.x, R.y, verified, C0..C9, H-bits×256, escrow_x, escrow_y]`.
- The verifier ties `H` to hardware *outside* the circuit: the audited report's
  `paypal_user_info_raw_hash` is folded into the SEC-02 nonce → the TDX quote's
  `report_data[0..32]` (existing, unchanged machinery).
- Encryption: `S = r·P_escrow`; keystream `k_i = Poseidon(S_x, S_y + i + 1)`;
  `C_i = chunk_i + k_i` over BN254 (31-byte little-endian chunks, 10 chunks).
  Decrypt with `s·R` — tool in §7.

---

## 3. The circuit — `zk/identity_escrow.circom`

Full source lives in `zk/identity_escrow.circom`; deviations from the generic
code block, all load-bearing:

1. **Self-padded SHA-256** (§1 row 3): 5 × circomlib `Sha256compression()`,
   IV → chained with circomlib's own inter-block bit order, over a 1600-bit
   stream assembled in-circuit from `raw_json_bytes + msg_len`.
   `=== identity_hash_bits` closes the preimage relation.
2. **Tail zeroing** `raw[i]·(1-[i<msg_len]) === 0` for `i ≥ 248` — the
   window search can never match outside the message.
3. **Band guards**: `Num2Bits(9)` + `LessThan` force `248 ≤ msg_len ≤ 300`
   (⇒ k = 5 always; identities outside the band fail at proving time with a
   clear message rather than producing a wrong hash).
4. **Pattern search**: `IsZero(raw[w+j] − P[j])` over all 275 windows, OR-chained
   to `verified_account_bit`. `,"verified_account":"true"` can only match at a
   structural position: a `"` byte can never occur unescaped inside a JSON
   string value, so a match inside `user_id`/`sub` is impossible.
5. **Standard ECIES**: `BabyPbk()` (BASE8 — matches circomlibjs `babyJub.Base8`,
   verified by the decrypt round-trip) + `EscalarMulAny(253)` + 10 × `Poseidon(2)`.

circomlib **2.0.5** quirks handled: no `util.circom` (IsZero lives in
`comparators.circom`), no `Num2Bits8` (use `Num2Bits(8)`), `EscalarMulAny`
needs its own include.

---

## 4. Build, constraint budget, ceremony — `scripts/build-zk.sh`

| Metric | Value | Source |
|---|---|---|
| Constraints (non-linear + linear) | **200,818** (184,775 + 16,043) | `snarkjs r1cs info` — **hard-pinned** by `build-zk.sh` (a circuit diff must consciously bump `CONSTRAINTS_EXPECTED`) |
| Public signals | 271 | r1cs info + Test 38 |
| Powers of tau | **power 18** (262,144 ≥ 200,818; power 17 would not fit) | |
| Witness wasm | `zk/identity_escrow.wasm` (~2.9 MB) | circom 2.2.3 |
| Proving key | `zk/identity_escrow_final.zkey` (see §9 for size/hash) | local ceremony |
| Proving key, **published form** | `zk/identity_escrow_final.zkey.part{0,1}` (60 MB + 45.4 MB) | **F5**: GitHub refuses any git object >100 MB (release assets don't send CORS either), and Pages does — the browser fetches both parts from `ZK_BASE` in order and pins their **concatenation** against the single `ZK_ZKEY_SHA256`. The assembled file is gitignored; `build-zk.sh` regenerates it (`cat parts > zkey`). |
| Verification key | `zk/identity_escrow_vkey.json` | **embedded in `verify.html`** |

Ceremony (all local, no external trust): `powersoftau new → contribute
(entropy = fresh `openssl rand -hex 64`, **never committed**) → prepare phase2
→ `groth16 setup → contribute → beacon → zkey verify`. Honest limitations,
stated once here and in the script header:

- This is a **single-party** setup: the machine that ran `contribute` could
  have kept the toxic waste and forged *credentials*.
- What that does **not** buy: a forged credential is worthless without an
  Intel-signed TDX quote whose SEC-02 nonce binds the *same* `H` — i.e. the
  forgery still requires enclave/hardware cooperation, exactly the trust the
  auditor already models (self-reports never gate; silicon decides).
- For a stronger ceremony, re-run `snarkjs zkey contribute` with N external
  contributors before the beacon; everything else stays identical.

Build reproducibility: circom version + constraint count are pinned; the
*zkey itself* is an artifact of runtime entropy — the committed bytes are the
reference (hashed in §9 and by Test 38), and a deliberate rebuild re-pins them
in the same reviewed commit (same discipline as the golden RTMR/README pins).

---

## 5. Integration into `verify.html`

**Placement** — `#zkCard`, revealed by `runAudit()` exactly where the 💾
`reportDownloadBtn` is revealed (green audit), below the results card:

```
[ 🔐 ZK escrow credential (optional, selective disclosure) ]
  Escrow recipient BabyJubjub key:  x: [ … ]  y: [ … ]   (prefilled EXAMPLE — see §7)
  [ ⚡ Generate credential (proves in this browser, ~Ns) ]   status: …
  ── verify an existing credential (works offline) ──
  credential file: [picker]   [✔ Verify]   status: …
```

**Data flow (prove)** — no second serializer, ever:

1. `runAudit()` already computed `identityJson` + `recomputedPaypalHash` for
   the preimage gate → stashed into `zkIdentityJson` / `zkIdentityHashHex`.
2. `snarkjs` (lazy, SRI-pinned 0.7.5) + `fetch(ZK_BASE + …)` **wasm/zkey with
   runtime SHA-256 verification against pinned constants** (fail closed on
   mismatch — the SRI philosophy applied to data files).
3. `groth16.fullProve({identity_hash_bits, escrow_pubkey_*, raw_json_bytes,
   msg_len, ephemeral_private_key})` — `r` from `crypto.getRandomValues`.
4. Credential `pav-circom-escrow/v1` downloads via the existing
   Blob/anchor pattern:
   `{schema, public_signals:{identity_hash_hex, verified_account_bit,
   ephemeral_pubkey, ciphertext, escrow_pubkey}, groth16_proof,
   report_sha256, created_ms}`.

**Data flow (verify)** — works in *any* copy of `verify.html`, offline
except for the (cached, SRI) snarkjs load: embedded vkey →
`groth16.verify` → public-signal checks → §6.

**Failure behavior**: no snarkjs (offline, CDN blocked) / artifact fetch
failure / hash mismatch / proof invalid ⇒ loud fail-closed status line, ZK
UI disabled. **The audit rows are never affected** — the ZK layer is additive.

---

## 6. Offline verification procedure (third parties)

1. **Audit the report normally** in a trusted `verify.html` copy — silicon
   root, MRTD/RTMR pins, session binding, preimage gate (unchanged).
2. **Load the credential** into the ZK card → `✔ Verify`:
   - Groth16 proof vs the **embedded vkey** (no network, no artifacts);
   - `identity_hash_hex == paypal_user_info_raw_hash` of the audited report
     (the hardware-bound value — this is the bridge from proof to silicon);
   - `report_sha256 == SHA-256(exact bytes of the audited report file)`.
3. **Interpret**: green ⇒ *"a verified PayPal identity, preimage-bound to this
   quote's nonce, exists and is escrowed to `escrow_pubkey`"* — **without the
   verifier ever seeing the identity fields**. The identity itself opens only
   for the escrow holder (§7).

---

## 7. Escrow decryption — `scripts/zk-decrypt-escrow.mjs`

```bash
node scripts/zk-decrypt-escrow.mjs credential.json <escrow_private_scalar_hex>
# → prints the recovered canonical identity JSON (and verifies its SHA-256
#   against credential.public_signals.identity_hash_hex)
```

**Example-key warning**: `verify.html` prefills an *example* escrow pair for
demonstration. Its scalar is published in the tool's `--example` output **so
the round trip can be tested end-to-end** — it provides **zero** secrecy.
Paste your own BabyJubjub public key (or generate: `buildBabyjub` +
`mulPointEscalar(Base8, sk)`) for any real recipient; the private scalar never
leaves whatever offline system you keep it on.

---

## 8. Test plan (harness Test 38 + build gates)

| # | Check | Guards against |
|---|---|---|
| 1 | source pins: circuit band/MAX, pattern bytes, `ZK_BASE`, SRI hash, wasm/zkey sha256 constants present in `verify.html` | silent artifact/UI drift |
| 2 | `zk/test-witness.mjs` (real captured identity): witness → **all 200,818 constraints satisfied** ⇒ in-circuit SHA ≡ hardware-bound hash | padding/endianness regressions in the self-built SHA stream |
| 3 | same run: `verified_account_bit == 1`, public-signal order pin, out-of-circuit ECIES decrypt round-trip == exact `D` | wrong chunking/keystream/indexing |
| 4 | witness builder input ≡ `runAudit()`'s `identityJson` (the same function) | second-serializer drift (the v178 bug class) |
| 5 | `groth16.fullProve → groth16.verify` round-trip against the **committed** vkey, tampered proof rejected | artifact/vkey mismatch |
| 6 | a credential whose `identity_hash_hex` ≠ the audited report's hash is refused by `verifyCredential()` | proof/report substitution |
| 7 | existing suites unchanged: offline 223+, live-envelope 229, cargo, e2e ×2 | no regression from the additive layer |

---

## 9. Execution log

| Step | Status |
|---|---|
| Adapt this document to project state | ✅ |
| Circuit written + compiled (circom 2.2.3, 200,818 constraints, 271 public signals) | ✅ |
| Witness gate vs **real captured identity** (full R1CS check + ECIES round-trip) | ✅ `node zk/test-witness.mjs` → PASS |
| Local trusted setup (`scripts/build-zk.sh`, power 18, beacon) | 🔄 running |
| `verify.html` ZK integration (lazy SRI snarkjs, ZK_BASE fetch + hash pins, embedded vkey, prove/verify UI) | ⬜ |
| `scripts/zk-decrypt-escrow.mjs` | ⬜ |
| Harness Test 38 + full suites (offline, cargo, live-envelope) | ⬜ |
| README digest + `index.html` sync + two-cycle deploy (v188) + e2e ×2 | ⬜ (deploy carries the v188 main.rs + auditor changes together) |
