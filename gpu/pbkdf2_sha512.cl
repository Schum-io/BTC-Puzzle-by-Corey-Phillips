/*
 * PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048, dkLen=64)
 * -- the BIP39 seed derivation, one work-item per candidate mnemonic.
 *
 * This is milestone 1 of the sparse_rare.py GPU offload: only the PBKDF2
 * step (the dominant cost per match_address() call in sparse_rare.py) is
 * ported here, to get a real throughput number before committing to the
 * secp256k1/BIP32 kernel.
 *
 * HMAC's ipad/opad key block is only hashed once per candidate (not once
 * per PBKDF2 iteration) by keeping the post-first-block SHA-512 midstate
 * around and reusing it for all 2048 iterations -- the standard PBKDF2
 * optimization, without it every iteration would redo 2 extra compressions
 * for no reason.
 */

__constant ulong K512[80] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
    0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL,
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static inline ulong load_be64(const uchar *p) {
    return ((ulong)p[0] << 56) | ((ulong)p[1] << 48) | ((ulong)p[2] << 40) | ((ulong)p[3] << 32) |
           ((ulong)p[4] << 24) | ((ulong)p[5] << 16) | ((ulong)p[6] << 8)  | ((ulong)p[7]);
}

static inline void store_be64(uchar *p, ulong v) {
    p[0] = (uchar)(v >> 56); p[1] = (uchar)(v >> 48); p[2] = (uchar)(v >> 40); p[3] = (uchar)(v >> 32);
    p[4] = (uchar)(v >> 24); p[5] = (uchar)(v >> 16); p[6] = (uchar)(v >> 8);  p[7] = (uchar)v;
}

static inline void sha512_init(ulong state[8]) {
    state[0] = 0x6a09e667f3bcc908UL; state[1] = 0xbb67ae8584caa73bUL;
    state[2] = 0x3c6ef372fe94f82bUL; state[3] = 0xa54ff53a5f1d36f1UL;
    state[4] = 0x510e527fade682d1UL; state[5] = 0x9b05688c2b3e6c1fUL;
    state[6] = 0x1f83d9abfb41bd6bUL; state[7] = 0x5be0cd19137e2179UL;
}

/* one 128-byte block compression, block already loaded as 16 big-endian words */
static inline void sha512_compress_words(ulong state[8], const ulong w_in[16]) {
    ulong w[80];
    for (int i = 0; i < 16; i++) w[i] = w_in[i];
    for (int i = 16; i < 80; i++) {
        ulong s0 = ROTR(w[i-15], 1) ^ ROTR(w[i-15], 8) ^ (w[i-15] >> 7);
        ulong s1 = ROTR(w[i-2], 19) ^ ROTR(w[i-2], 61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    ulong a = state[0], b = state[1], c = state[2], d = state[3];
    ulong e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 80; i++) {
        ulong S1 = ROTR(e, 14) ^ ROTR(e, 18) ^ ROTR(e, 41);
        ulong ch = (e & f) ^ (~e & g);
        ulong t1 = h + S1 + ch + K512[i] + w[i];
        ulong S0 = ROTR(a, 28) ^ ROTR(a, 34) ^ ROTR(a, 39);
        ulong maj = (a & b) ^ (a & c) ^ (b & c);
        ulong t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static inline void sha512_compress_bytes(ulong state[8], const uchar block[128]) {
    ulong w[16];
    for (int i = 0; i < 16; i++) w[i] = load_be64(block + i * 8);
    sha512_compress_words(state, w);
}

/*
 * Absorb up to 127 bytes of "tail" plus standard SHA-512 padding
 * (0x80, zero fill, 16-byte big-endian bit length of the FULL message,
 * high 64 bits always 0 for our message sizes) and run the final 1-2
 * compressions. `total_len_bytes` is the length of the whole message
 * fed to the hash so far, including any blocks already compressed
 * before this call (e.g. the HMAC key block).
 */
static inline void sha512_pad_absorb(ulong state[8], const uchar *tail, uint tail_len, ulong total_len_bytes) {
    uchar buf[256];
    for (uint i = 0; i < tail_len; i++) buf[i] = tail[i];
    buf[tail_len] = 0x80;
    uint after = tail_len + 1;
    uint padded = ((after + 16 + 127) / 128) * 128;
    for (uint i = after; i < padded - 16; i++) buf[i] = 0;
    for (uint i = 0; i < 8; i++) buf[padded - 16 + i] = 0;
    store_be64(buf + padded - 8, total_len_bytes * 8UL);
    for (uint b = 0; b < padded / 128; b++) sha512_compress_bytes(state, buf + b * 128);
}

/* full SHA-512 digest of an arbitrary message no longer than 127 bytes
 * past the last full 128-byte block (true for every call site here:
 * max message length used is the 215-byte password). */
static inline void sha512_digest(ulong state[8], const uchar *msg, uint msg_len) {
    sha512_init(state);
    uint full_blocks = msg_len / 128;
    for (uint b = 0; b < full_blocks; b++) sha512_compress_bytes(state, msg + b * 128);
    sha512_pad_absorb(state, msg + full_blocks * 128, msg_len - full_blocks * 128, msg_len);
}

/* HMAC-SHA512 key setup: precompute the post-key-block midstates so the
 * 2048 PBKDF2 iterations only pay for the variable part of the message. */
static inline void hmac_sha512_init(ulong ipad_state[8], ulong opad_state[8], const uchar *key, uint key_len) {
    uchar kblock[128];
    if (key_len > 128) {
        ulong kh[8];
        sha512_digest(kh, key, key_len);
        uchar khb[64];
        for (int i = 0; i < 8; i++) store_be64(khb + i * 8, kh[i]);
        for (int i = 0; i < 64; i++) kblock[i] = khb[i];
        for (int i = 64; i < 128; i++) kblock[i] = 0;
    } else {
        for (uint i = 0; i < key_len; i++) kblock[i] = key[i];
        for (uint i = key_len; i < 128; i++) kblock[i] = 0;
    }
    uchar ipad_block[128], opad_block[128];
    for (int i = 0; i < 128; i++) {
        ipad_block[i] = kblock[i] ^ 0x36;
        opad_block[i] = kblock[i] ^ 0x5c;
    }
    sha512_init(ipad_state);
    sha512_compress_bytes(ipad_state, ipad_block);
    sha512_init(opad_state);
    sha512_compress_bytes(opad_state, opad_block);
}

/* one HMAC-SHA512 call given precomputed key midstates; msg_len <= 64 here. */
static inline void hmac_sha512_once(const ulong ipad_state[8], const ulong opad_state[8],
                              const uchar *msg, uint msg_len, uchar out[64]) {
    ulong inner[8];
    for (int i = 0; i < 8; i++) inner[i] = ipad_state[i];
    sha512_pad_absorb(inner, msg, msg_len, 128 + msg_len);
    uchar inner_bytes[64];
    for (int i = 0; i < 8; i++) store_be64(inner_bytes + i * 8, inner[i]);

    ulong outer[8];
    for (int i = 0; i < 8; i++) outer[i] = opad_state[i];
    sha512_pad_absorb(outer, inner_bytes, 64, 128 + 64);
    for (int i = 0; i < 8; i++) store_be64(out + i * 8, outer[i]);
}

/*
 * word_table: 2048 entries * 9 bytes = [len, 8 bytes of the word, zero padded]
 * indices:    batch * n_words, ushort word index per mnemonic slot
 * out_seed:   batch * 64 bytes, the derived BIP39 seed
 * salt_extra: BIP39 passphrase bytes (empty in this project, kept for completeness)
 */
__kernel void pbkdf2_seed(
    __constant uchar *word_table,
    __global const ushort *indices,
    const uint n_words,
    __global uchar *out_seed,
    const uint salt_extra_len,
    __constant uchar *salt_extra
) {
    size_t gid = get_global_id(0);
    __global const ushort *my_idx = indices + gid * n_words;

    uchar password[256];
    uint plen = 0;
    for (uint i = 0; i < n_words; i++) {
        __constant uchar *entry = word_table + ((uint)my_idx[i]) * 9;
        uchar wlen = entry[0];
        for (uchar j = 0; j < wlen; j++) password[plen++] = entry[1 + j];
        if (i + 1 < n_words) password[plen++] = ' ';
    }

    ulong ipad_state[8], opad_state[8];
    hmac_sha512_init(ipad_state, opad_state, password, plen);

    uchar salt[8 + 64 + 4];
    uint slen = 0;
    salt[slen++] = 'm'; salt[slen++] = 'n'; salt[slen++] = 'e'; salt[slen++] = 'm';
    salt[slen++] = 'o'; salt[slen++] = 'n'; salt[slen++] = 'i'; salt[slen++] = 'c';
    for (uint i = 0; i < salt_extra_len; i++) salt[slen++] = salt_extra[i];
    salt[slen++] = 0; salt[slen++] = 0; salt[slen++] = 0; salt[slen++] = 1;

    uchar U[64], T[64];
    hmac_sha512_once(ipad_state, opad_state, salt, slen, U);
    for (int i = 0; i < 64; i++) T[i] = U[i];

    for (int iter = 1; iter < 2048; iter++) {
        uchar Unext[64];
        hmac_sha512_once(ipad_state, opad_state, U, 64, Unext);
        for (int i = 0; i < 64; i++) { T[i] ^= Unext[i]; U[i] = Unext[i]; }
    }

    __global uchar *dst = out_seed + gid * 64;
    for (int i = 0; i < 64; i++) dst[i] = T[i];
}
