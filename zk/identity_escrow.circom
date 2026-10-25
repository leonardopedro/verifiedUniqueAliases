pragma circom 2.1.6;

// =============================================================================
// identity_escrow.circom — v188 adaptation of the generic circom.md plan to
// THIS project (paypal-auth-vm). What the statement proves, and why every
// piece is here:
//
//   PRIVATE WITNESS
//     raw_json_bytes[300]  the CANONICAL identity JSON D — byte-identical to
//                           the enclave's serde_json::to_string of the
//                           minimized PayPalUserInfo struct (order: user_id,
//                           sub, verified_account, payer_id; nulls kept).
//                           This is the SAME preimage verify.html already
//                           reconstructs in runAudit() (identityJson) and
//                           checks against paypal_user_info_raw_hash — the
//                           circuit consumes those exact bytes, no second
//                           serialization exists.
//     msg_len              byte length of D. The real production capture is
//                           262 bytes (user_id/sub are PayPal identity URLs);
//                           the band [248, 300] keeps the SHA-256 block count
//                           constant at k=5 (honest lengths 248..311 all pad
//                           into exactly 5 blocks), so the in-circuit padding
//                           matches an honest SHA-256(D) for every provable
//                           identity.
//     ephemeral_private_key  r — fresh per proof, never leaves the browser.
//
//   PUBLIC
//     identity_hash_bits[256]  H = SHA-256(D) as bits, MSB-first per byte —
//                           equals the audited paypal_user_info_raw_hash,
//                           which the enclave folds into the SEC-02 nonce and
//                           therefore into the TDX quote's report_data[0..32].
//                           The OFFLINE verifier checks this against the
//                           audited report; the hardware is what makes H
//                           trustworthy.
//     escrow_pubkey_x/y    BabyJubjub point of the escrow recipient (user-
//                           supplied at prove time).
//     ephemeral_pubkey     R = r·G (output).
//     ciphertext[i]        Poseidon-ECIES chunks of D (output, 10 × ~31 B).
//     verified_account_bit (output) 1 iff D contains the exact byte pattern
//                           `,"verified_account":"true"` — the one deliberate
//                           IN-CIRCUIT re-check of an existing auditor gate:
//                           it is what lets the CREDENTIAL alone (without
//                           opening the plaintext report) carry the
//                           "verified PayPal account" claim, i.e. the whole
//                           selective-disclosure feature. The auditor-side
//                           gate remains the enforcement point for audits.
//
// SHA-256 is built from circomlib's Sha256compression() over a stream that
// THIS circuit pads itself from msg_len (0x80 at index msg_len, zeros, the
// 64-bit big-endian bit length in bytes 312..319) — circomlib's Sha256(nBits)
// cannot be used directly because its message length is a compile-time
// constant while msg_len is witness data.
//
// Soundness notes:
//   * raw bytes at i >= msg_len are forced to 0, so the verified-bit window
//     search can never match past the end of the message;
//   * msg_len is pinned by H (choosing a different length changes the SHA
//     length field ⇒ a different digest ⇒ no proof without a preimage);
//   * a wrong escrow key only breaks the prover's own decryption.
// =============================================================================
include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/escalarmulany.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";  // LessThan + IsZero (circomlib 2.0.5 has no util.circom)

template IdentityEscrow(MAX) {
    var MIN_LEN   = 248;               // k=5 SHA band lower bound (len+9 > 256)
    var SHA_BYTES = 320;               // 5 blocks × 64 B
    var N_BLOCKS  = 5;
    var N_CHUNKS  = (MAX + 30) \ 31;   // 300 → 10 chunks (31 B each)
    var PATTERN_LEN = 26;              // `,"verified_account":"true"`

    // ---- public ----
    signal input identity_hash_bits[256];
    signal input escrow_pubkey_x;
    signal input escrow_pubkey_y;
    // ---- private ----
    signal input raw_json_bytes[MAX];
    signal input msg_len;
    signal input ephemeral_private_key;
    // ---- public outputs ----
    signal output ephemeral_pubkey_x;
    signal output ephemeral_pubkey_y;
    signal output verified_account_bit;
    signal output ciphertext[N_CHUNKS];

    // -------------------------------------------------------------------------
    // 1. msg_len: 9-bit decomposition + band [248, 300]
    // -------------------------------------------------------------------------
    component lenBits = Num2Bits(9);
    lenBits.in <== msg_len;

    component lenGeMin = LessThan(10);          // msg_len >= 248
    lenGeMin.in[0] <== 248;
    lenGeMin.in[1] <== msg_len;
    lenGeMin.out === 1;

    component lenLeMax = LessThan(10);          // msg_len <= 300
    lenLeMax.in[0] <== msg_len;
    lenLeMax.in[1] <== 301;
    lenLeMax.out === 1;

    // -------------------------------------------------------------------------
    // 2. bytes: bit decomposition (booleanity for SHA + window search) and
    //    raw[i] === 0 for every i >= msg_len inside the in-band region
    //    (i < 248 can never be past the end because msg_len >= 248).
    // -------------------------------------------------------------------------
    component rawBits[MAX];
    component pastEnd[MAX - MIN_LEN];
    for (var i = 0; i < MAX; i++) {
        rawBits[i] = Num2Bits(8);
        rawBits[i].in <== raw_json_bytes[i];
        if (i >= MIN_LEN) {
            pastEnd[i - MIN_LEN] = LessThan(10);
            pastEnd[i - MIN_LEN].in[0] <== i;
            pastEnd[i - MIN_LEN].in[1] <== msg_len;
            raw_json_bytes[i] * (1 - pastEnd[i - MIN_LEN].out) === 0;
        }
    }

    // -------------------------------------------------------------------------
    // 3. eqLen[k]  ⇔  msg_len == MIN_LEN + k  (for the 0x80 padding marker)
    // -------------------------------------------------------------------------
    var N_EQ = MAX - MIN_LEN + 1;               // 53 (248..300)
    signal eqLenAcc[N_EQ][9];
    signal eqLen[N_EQ];
    for (var k = 0; k < N_EQ; k++) {
        var v = MIN_LEN + k;
        eqLenAcc[k][0] <== ((v & 1) == 1) ? lenBits.out[0] : (1 - lenBits.out[0]);
        for (var b = 1; b < 9; b++) {
            eqLenAcc[k][b] <== eqLenAcc[k][b - 1] *
                ((((v >> b) & 1) == 1) ? lenBits.out[b] : (1 - lenBits.out[b]));
        }
        eqLen[k] <== eqLenAcc[k][8];
    }

    // -------------------------------------------------------------------------
    // 4. The SHA-256 padded message stream (320 bytes → 1600 bits, MSB-first
    //    per byte), built from raw + msg_len exactly like an honest SHA-256.
    //    Layout: D || 0x80 || zeros || uint64_be(msg_len * 8).
    // -------------------------------------------------------------------------
    signal streamBits[N_BLOCKS * 512];
    for (var j = 0; j < SHA_BYTES; j++) {
        for (var t = 0; t < 8; t++) {           // t = 0 is the MSB of byte j
            var b = 7 - t;                      // bit significance
            if (j < MIN_LEN) {
                // always message: no marker/length possible here
                streamBits[j * 8 + t] <== rawBits[j].out[b];
            } else if (j < MAX) {
                // in-band: message byte, +0x80 in its MSB at i == msg_len
                if (t == 0) {
                    streamBits[j * 8 + t] <== rawBits[j].out[7] + eqLen[j - MIN_LEN];
                } else {
                    streamBits[j * 8 + t] <== rawBits[j].out[b];
                }
            } else if (j == MAX) {
                // marker past the last byte (msg_len == 300)
                streamBits[j * 8 + t] <== (t == 0) ? eqLen[N_EQ - 1] : 0;
            } else if (j < 312) {
                // zero padding between the marker and the length field
                streamBits[j * 8 + t] <== 0;
            } else if (j == 318) {
                // len*8 >> 8  (only bits 5..8 of msg_len can be set)
                if (t < 4)      streamBits[j * 8 + t] <== 0;
                else if (t == 4) streamBits[j * 8 + t] <== lenBits.out[8];
                else if (t == 5) streamBits[j * 8 + t] <== lenBits.out[7];
                else if (t == 6) streamBits[j * 8 + t] <== lenBits.out[6];
                else             streamBits[j * 8 + t] <== lenBits.out[5];
            } else if (j == 319) {
                // (len*8) & 0xff = 8 * (msg_len mod 32)
                if (t < 4)      streamBits[j * 8 + t] <== lenBits.out[4 - t];
                else            streamBits[j * 8 + t] <== 0;
            } else {
                streamBits[j * 8 + t] <== 0;    // bytes 312..317 (high length)
            }
        }
    }

    // -------------------------------------------------------------------------
    // 5. SHA-256: chain 5 Sha256compression blocks (IV → out), mirroring
    //    circomlib's own inter-block bit order, and pin the digest to the
    //    public identity hash.
    // -------------------------------------------------------------------------
    component hIV[8];
    for (var w = 0; w < 8; w++) hIV[w] = H(w);

    component sha[N_BLOCKS];
    for (var blk = 0; blk < N_BLOCKS; blk++) {
        sha[blk] = Sha256compression();
        for (var t = 0; t < 512; t++) {
            sha[blk].inp[t] <== streamBits[blk * 512 + t];
        }
        for (var k = 0; k < 32; k++) {
            if (blk == 0) {
                for (var w = 0; w < 8; w++) {
                    sha[0].hin[w * 32 + k] <== hIV[w].out[k];
                }
            } else {
                for (var w = 0; w < 8; w++) {
                    sha[blk].hin[w * 32 + k] <== sha[blk - 1].out[w * 32 + 31 - k];
                }
            }
        }
    }
    for (var k = 0; k < 256; k++) {
        sha[N_BLOCKS - 1].out[k] === identity_hash_bits[k];
    }

    // -------------------------------------------------------------------------
    // 6. verified_account_bit: does D contain `,"verified_account":"true"`?
    //    Window search with IsZero equalities (2 constraints per byte) over
    //    every offset that fits inside MAX bytes. The bytes past msg_len are
    //    already forced to 0 (step 2) and the pattern contains no 0 byte, so
    //    a match can only land inside the real message — and producing a
    //    match at all requires knowing a preimage of H that carries it.
    // -------------------------------------------------------------------------
    var pattern[26];
    pattern[0] = 44;  // ,
    pattern[1] = 34;  // "
    // verified_account  (16 chars)
    pattern[2] = 118; pattern[3] = 101; pattern[4] = 114; pattern[5] = 105;
    pattern[6] = 102; pattern[7] = 105; pattern[8] = 101; pattern[9] = 100;
    pattern[10] = 95; pattern[11] = 97; pattern[12] = 99; pattern[13] = 99;
    pattern[14] = 111; pattern[15] = 117; pattern[16] = 110; pattern[17] = 116;
    pattern[18] = 34; // "
    pattern[19] = 58; // :
    pattern[20] = 34; // "
    pattern[21] = 116; pattern[22] = 114; pattern[23] = 117; pattern[24] = 101; // true
    pattern[25] = 34; // "

    var N_WIN = MAX - PATTERN_LEN + 1;          // 275
    component winEq[N_WIN][PATTERN_LEN];
    signal winAcc[N_WIN][PATTERN_LEN];
    signal verifiedAcc[N_WIN];
    for (var w = 0; w < N_WIN; w++) {
        for (var j = 0; j < PATTERN_LEN; j++) {
            winEq[w][j] = IsZero();
            winEq[w][j].in <== raw_json_bytes[w + j] - pattern[j];
        }
        winAcc[w][0] <== winEq[w][0].out;
        for (var j = 1; j < PATTERN_LEN; j++) {
            winAcc[w][j] <== winAcc[w][j - 1] * winEq[w][j].out;
        }
        if (w == 0) {
            verifiedAcc[0] <== winAcc[0][PATTERN_LEN - 1];
        } else {
            verifiedAcc[w] <== verifiedAcc[w - 1] + winAcc[w][PATTERN_LEN - 1]
                - verifiedAcc[w - 1] * winAcc[w][PATTERN_LEN - 1];
        }
    }
    verified_account_bit <== verifiedAcc[N_WIN - 1];

    // -------------------------------------------------------------------------
    // 7. ECDH on BabyJubjub: R = r·G (public), S = r·P_escrow (secret)
    // -------------------------------------------------------------------------
    component rG = BabyPbk();
    rG.in <== ephemeral_private_key;
    ephemeral_pubkey_x <== rG.Ax;
    ephemeral_pubkey_y <== rG.Ay;

    component rBits = Num2Bits(253);
    rBits.in <== ephemeral_private_key;
    component sharedSecret = EscalarMulAny(253);
    for (var i = 0; i < 253; i++) sharedSecret.e[i] <== rBits.out[i];
    sharedSecret.p[0] <== escrow_pubkey_x;
    sharedSecret.p[1] <== escrow_pubkey_y;

    // -------------------------------------------------------------------------
    // 8. Pack D into 31-byte field chunks and encrypt with a Poseidon stream
    //    keyed by the shared point: C_i = chunk_i + Poseidon(Sx, Sy + i + 1)
    // -------------------------------------------------------------------------
    signal chunk[N_CHUNKS];
    for (var c = 0; c < N_CHUNKS; c++) {
        var acc = 0;
        for (var bIdx = 0; bIdx < 31; bIdx++) {
            var idx = c * 31 + bIdx;
            if (idx < MAX) {
                acc += raw_json_bytes[idx] * (256 ** bIdx);
            }
        }
        chunk[c] <== acc;
    }

    component ks[N_CHUNKS];
    for (var c = 0; c < N_CHUNKS; c++) {
        ks[c] = Poseidon(2);
        ks[c].inputs[0] <== sharedSecret.out[0];
        ks[c].inputs[1] <== sharedSecret.out[1] + (c + 1);
        ciphertext[c] <== chunk[c] + ks[c].out;
    }
}

// Public signal order emitted by snarkjs (pinned by the security harness):
//   [ephemeral_pubkey_x, ephemeral_pubkey_y, verified_account_bit,
//    ciphertext[0..9], identity_hash_bits[0..255],
//    escrow_pubkey_x, escrow_pubkey_y]           → 271 signals
component main {public [identity_hash_bits, escrow_pubkey_x, escrow_pubkey_y]}
    = IdentityEscrow(300);
