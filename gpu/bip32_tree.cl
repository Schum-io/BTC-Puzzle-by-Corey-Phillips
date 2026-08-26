/*
 * Milestone 3 of the sparse_rare.py GPU offload: given a BIP39 seed (the
 * output of gpu/pbkdf2_sha512.cl's PBKDF2 kernel), walk the exact same
 * derivation tree as sparse_rare.py's match_address() and test every node
 * against TARGET_HASH160 -- both compressed and uncompressed pubkey
 * encodings, matching _hit() in sparse_rare.py.
 *
 * Every EC operation here is a scalar multiplication by the base point G
 * (master key, and every CKD child key, are always turned into a pubkey via
 * privkey*G -- there is no "arbitrary base point" case in this algorithm),
 * so hashcat's vendored point_mul_xy (gpu/vendor/inc_ecc_secp256k1.cl) covers
 * 100% of the EC work; set_precomputed_basepoint_g() is called once per
 * work-item and reused for all ~44 nodes.
 *
 * Scope note: the two "brainwallet sha256" checks in match_address() (SHA256
 * of the raw mnemonic text used directly as a private key) are NOT included
 * here -- they need the mnemonic's word bytes, which live in the PBKDF2
 * kernel (gpu/pbkdf2_sha512.cl), not in this kernel's seed-only input. They
 * are deferred to the milestone that fuses both kernels.
 */

#define HARDENED 0x80000000u

/* ---------------------------------------------------------------- */
/* byte/word helpers                                                  */
/* ---------------------------------------------------------------- */

static inline u32 load_be32(const uchar *p) {
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
}
static inline void store_be32(uchar *p, u32 v) {
    p[0] = (uchar)(v >> 24); p[1] = (uchar)(v >> 16); p[2] = (uchar)(v >> 8); p[3] = (uchar)v;
}
static inline u32 load_le32(const uchar *p) {
    return ((u32)p[3] << 24) | ((u32)p[2] << 16) | ((u32)p[1] << 8) | (u32)p[0];
}

/* secp256k1's u32[8] words are LSB-first (word[0] = least significant 32
 * bits), matching the vendored file's own SECP256K1_P0/N0 convention. */
static inline void words_to_be32_256(uchar out32[32], const u32 words[8]) {
    for (int i = 0; i < 8; i++) store_be32(out32 + i * 4, words[7 - i]);
}
static inline void be32_256_to_words(u32 words[8], const uchar in32[32]) {
    for (int i = 0; i < 8; i++) words[7 - i] = load_be32(in32 + i * 4);
}

/* ---------------------------------------------------------------- */
/* SHA-256 (needed for hash160 = RIPEMD160(SHA256(pubkey)))          */
/* ---------------------------------------------------------------- */

__constant u32 K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static inline void sha256_init(u32 state[8]) {
    state[0] = 0x6a09e667; state[1] = 0xbb67ae85; state[2] = 0x3c6ef372; state[3] = 0xa54ff53a;
    state[4] = 0x510e527f; state[5] = 0x9b05688c; state[6] = 0x1f83d9ab; state[7] = 0x5be0cd19;
}

static inline void sha256_compress_bytes(u32 state[8], const uchar block[64]) {
    u32 w[64];
    for (int i = 0; i < 16; i++) w[i] = load_be32(block + i * 4);
    for (int i = 16; i < 64; i++) {
        u32 s0 = ROTR32(w[i-15], 7) ^ ROTR32(w[i-15], 18) ^ (w[i-15] >> 3);
        u32 s1 = ROTR32(w[i-2], 17) ^ ROTR32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    u32 a = state[0], b = state[1], c = state[2], d = state[3];
    u32 e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
        u32 S1 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
        u32 ch = (e & f) ^ (~e & g);
        u32 t1 = h + S1 + ch + K256[i] + w[i];
        u32 S0 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
        u32 maj = (a & b) ^ (a & c) ^ (b & c);
        u32 t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* absorb up to 55 bytes of tail + standard padding (0x80, zero fill, 8-byte
 * big-endian bit length), 1 or 2 blocks. Covers our tails: msg_len 33 or 65
 * bytes, so tail (msg_len mod 64) is always < 64. */
static inline void sha256_pad_absorb(u32 state[8], const uchar *tail, uint tail_len, u32 total_len_bytes) {
    uchar buf[128];
    for (uint i = 0; i < tail_len; i++) buf[i] = tail[i];
    buf[tail_len] = 0x80;
    uint after = tail_len + 1;
    uint padded = ((after + 8 + 63) / 64) * 64;
    for (uint i = after; i < padded - 8; i++) buf[i] = 0;
    for (uint i = 0; i < 4; i++) buf[padded - 8 + i] = 0;
    store_be32(buf + padded - 4, total_len_bytes * 8u);
    for (uint b = 0; b < padded / 64; b++) sha256_compress_bytes(state, buf + b * 64);
}

static inline void sha256_digest(const uchar *msg, uint msg_len, uchar out32[32]) {
    u32 state[8];
    sha256_init(state);
    uint full_blocks = msg_len / 64;
    for (uint b = 0; b < full_blocks; b++) sha256_compress_bytes(state, msg + b * 64);
    sha256_pad_absorb(state, msg + full_blocks * 64, msg_len - full_blocks * 64, msg_len);
    for (int i = 0; i < 8; i++) store_be32(out32 + i * 4, state[i]);
}

/* ---------------------------------------------------------------- */
/* RIPEMD-160 (message is always exactly 32 bytes: a SHA-256 digest)  */
/* Ported from RHash's librhash/ripemd-160.c (public-domain-style     */
/* permissive license, see gpu/vendor/NOTICE.md-adjacent credit here: */
/* Copyright (c) 2009, Aleksey Kravchenko, ISC-style license).        */
/* RIPEMD-160 words are little-endian, unlike SHA-256/512.            */
/* ---------------------------------------------------------------- */

#define RMD_F1(x,y,z) ((x) ^ (y) ^ (z))
#define RMD_F2(x,y,z) ((((y) ^ (z)) & (x)) ^ (z))
#define RMD_F3(x,y,z) (((x) | ~(y)) ^ (z))
#define RMD_F4(x,y,z) ((((x) ^ (y)) & (z)) ^ (y))
#define RMD_F5(x,y,z) ((x) ^ ((y) | ~(z)))

#define RMD_FUNC(FUNC,A,B,C,D,E,X,S,K) \
    (A) += FUNC(B,C,D) + (X) + (K); \
    (A) = ROTL32((A), (S)) + (E); \
    (C) = ROTL32((C), 10);

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define RMD_L1(A,B,C,D,E,X,S) RMD_FUNC(RMD_F1,A,B,C,D,E,X,S,0u)
#define RMD_L2(A,B,C,D,E,X,S) RMD_FUNC(RMD_F2,A,B,C,D,E,X,S,0x5a827999u)
#define RMD_L3(A,B,C,D,E,X,S) RMD_FUNC(RMD_F3,A,B,C,D,E,X,S,0x6ed9eba1u)
#define RMD_L4(A,B,C,D,E,X,S) RMD_FUNC(RMD_F4,A,B,C,D,E,X,S,0x8f1bbcdcu)
#define RMD_L5(A,B,C,D,E,X,S) RMD_FUNC(RMD_F5,A,B,C,D,E,X,S,0xa953fd4eu)
#define RMD_R1(A,B,C,D,E,X,S) RMD_FUNC(RMD_F5,A,B,C,D,E,X,S,0x50a28be6u)
#define RMD_R2(A,B,C,D,E,X,S) RMD_FUNC(RMD_F4,A,B,C,D,E,X,S,0x5c4dd124u)
#define RMD_R3(A,B,C,D,E,X,S) RMD_FUNC(RMD_F3,A,B,C,D,E,X,S,0x6d703ef3u)
#define RMD_R4(A,B,C,D,E,X,S) RMD_FUNC(RMD_F2,A,B,C,D,E,X,S,0x7a6d76e9u)
#define RMD_R5(A,B,C,D,E,X,S) RMD_FUNC(RMD_F1,A,B,C,D,E,X,S,0u)

static inline void ripemd160_process_block(u32 hash[5], const u32 X[16]) {
    u32 A = hash[0],  B = hash[1],  C = hash[2], D = hash[3],  E = hash[4];
    u32 a1 = hash[0], b1 = hash[1], c1 = hash[2], d1 = hash[3], e1 = hash[4];

    RMD_L1(a1,b1,c1,d1,e1, X[ 0], 11); RMD_R1(A,B,C,D,E, X[ 5],  8);
    RMD_L1(e1,a1,b1,c1,d1, X[ 1], 14); RMD_R1(E,A,B,C,D, X[14],  9);
    RMD_L1(d1,e1,a1,b1,c1, X[ 2], 15); RMD_R1(D,E,A,B,C, X[ 7],  9);
    RMD_L1(c1,d1,e1,a1,b1, X[ 3], 12); RMD_R1(C,D,E,A,B, X[ 0], 11);
    RMD_L1(b1,c1,d1,e1,a1, X[ 4],  5); RMD_R1(B,C,D,E,A, X[ 9], 13);
    RMD_L1(a1,b1,c1,d1,e1, X[ 5],  8); RMD_R1(A,B,C,D,E, X[ 2], 15);
    RMD_L1(e1,a1,b1,c1,d1, X[ 6],  7); RMD_R1(E,A,B,C,D, X[11], 15);
    RMD_L1(d1,e1,a1,b1,c1, X[ 7],  9); RMD_R1(D,E,A,B,C, X[ 4],  5);
    RMD_L1(c1,d1,e1,a1,b1, X[ 8], 11); RMD_R1(C,D,E,A,B, X[13],  7);
    RMD_L1(b1,c1,d1,e1,a1, X[ 9], 13); RMD_R1(B,C,D,E,A, X[ 6],  7);
    RMD_L1(a1,b1,c1,d1,e1, X[10], 14); RMD_R1(A,B,C,D,E, X[15],  8);
    RMD_L1(e1,a1,b1,c1,d1, X[11], 15); RMD_R1(E,A,B,C,D, X[ 8], 11);
    RMD_L1(d1,e1,a1,b1,c1, X[12],  6); RMD_R1(D,E,A,B,C, X[ 1], 14);
    RMD_L1(c1,d1,e1,a1,b1, X[13],  7); RMD_R1(C,D,E,A,B, X[10], 14);
    RMD_L1(b1,c1,d1,e1,a1, X[14],  9); RMD_R1(B,C,D,E,A, X[ 3], 12);
    RMD_L1(a1,b1,c1,d1,e1, X[15],  8); RMD_R1(A,B,C,D,E, X[12],  6);

    RMD_L2(e1,a1,b1,c1,d1, X[ 7],  7); RMD_R2(E,A,B,C,D, X[ 6],  9);
    RMD_L2(d1,e1,a1,b1,c1, X[ 4],  6); RMD_R2(D,E,A,B,C, X[11], 13);
    RMD_L2(c1,d1,e1,a1,b1, X[13],  8); RMD_R2(C,D,E,A,B, X[ 3], 15);
    RMD_L2(b1,c1,d1,e1,a1, X[ 1], 13); RMD_R2(B,C,D,E,A, X[ 7],  7);
    RMD_L2(a1,b1,c1,d1,e1, X[10], 11); RMD_R2(A,B,C,D,E, X[ 0], 12);
    RMD_L2(e1,a1,b1,c1,d1, X[ 6],  9); RMD_R2(E,A,B,C,D, X[13],  8);
    RMD_L2(d1,e1,a1,b1,c1, X[15],  7); RMD_R2(D,E,A,B,C, X[ 5],  9);
    RMD_L2(c1,d1,e1,a1,b1, X[ 3], 15); RMD_R2(C,D,E,A,B, X[10], 11);
    RMD_L2(b1,c1,d1,e1,a1, X[12],  7); RMD_R2(B,C,D,E,A, X[14],  7);
    RMD_L2(a1,b1,c1,d1,e1, X[ 0], 12); RMD_R2(A,B,C,D,E, X[15],  7);
    RMD_L2(e1,a1,b1,c1,d1, X[ 9], 15); RMD_R2(E,A,B,C,D, X[ 8], 12);
    RMD_L2(d1,e1,a1,b1,c1, X[ 5],  9); RMD_R2(D,E,A,B,C, X[12],  7);
    RMD_L2(c1,d1,e1,a1,b1, X[ 2], 11); RMD_R2(C,D,E,A,B, X[ 4],  6);
    RMD_L2(b1,c1,d1,e1,a1, X[14],  7); RMD_R2(B,C,D,E,A, X[ 9], 15);
    RMD_L2(a1,b1,c1,d1,e1, X[11], 13); RMD_R2(A,B,C,D,E, X[ 1], 13);
    RMD_L2(e1,a1,b1,c1,d1, X[ 8], 12); RMD_R2(E,A,B,C,D, X[ 2], 11);

    RMD_L3(d1,e1,a1,b1,c1, X[ 3], 11); RMD_R3(D,E,A,B,C, X[15],  9);
    RMD_L3(c1,d1,e1,a1,b1, X[10], 13); RMD_R3(C,D,E,A,B, X[ 5],  7);
    RMD_L3(b1,c1,d1,e1,a1, X[14],  6); RMD_R3(B,C,D,E,A, X[ 1], 15);
    RMD_L3(a1,b1,c1,d1,e1, X[ 4],  7); RMD_R3(A,B,C,D,E, X[ 3], 11);
    RMD_L3(e1,a1,b1,c1,d1, X[ 9], 14); RMD_R3(E,A,B,C,D, X[ 7],  8);
    RMD_L3(d1,e1,a1,b1,c1, X[15],  9); RMD_R3(D,E,A,B,C, X[14],  6);
    RMD_L3(c1,d1,e1,a1,b1, X[ 8], 13); RMD_R3(C,D,E,A,B, X[ 6],  6);
    RMD_L3(b1,c1,d1,e1,a1, X[ 1], 15); RMD_R3(B,C,D,E,A, X[ 9], 14);
    RMD_L3(a1,b1,c1,d1,e1, X[ 2], 14); RMD_R3(A,B,C,D,E, X[11], 12);
    RMD_L3(e1,a1,b1,c1,d1, X[ 7],  8); RMD_R3(E,A,B,C,D, X[ 8], 13);
    RMD_L3(d1,e1,a1,b1,c1, X[ 0], 13); RMD_R3(D,E,A,B,C, X[12],  5);
    RMD_L3(c1,d1,e1,a1,b1, X[ 6],  6); RMD_R3(C,D,E,A,B, X[ 2], 14);
    RMD_L3(b1,c1,d1,e1,a1, X[13],  5); RMD_R3(B,C,D,E,A, X[10], 13);
    RMD_L3(a1,b1,c1,d1,e1, X[11], 12); RMD_R3(A,B,C,D,E, X[ 0], 13);
    RMD_L3(e1,a1,b1,c1,d1, X[ 5],  7); RMD_R3(E,A,B,C,D, X[ 4],  7);
    RMD_L3(d1,e1,a1,b1,c1, X[12],  5); RMD_R3(D,E,A,B,C, X[13],  5);

    RMD_L4(c1,d1,e1,a1,b1, X[ 1], 11); RMD_R4(C,D,E,A,B, X[ 8], 15);
    RMD_L4(b1,c1,d1,e1,a1, X[ 9], 12); RMD_R4(B,C,D,E,A, X[ 6],  5);
    RMD_L4(a1,b1,c1,d1,e1, X[11], 14); RMD_R4(A,B,C,D,E, X[ 4],  8);
    RMD_L4(e1,a1,b1,c1,d1, X[10], 15); RMD_R4(E,A,B,C,D, X[ 1], 11);
    RMD_L4(d1,e1,a1,b1,c1, X[ 0], 14); RMD_R4(D,E,A,B,C, X[ 3], 14);
    RMD_L4(c1,d1,e1,a1,b1, X[ 8], 15); RMD_R4(C,D,E,A,B, X[11], 14);
    RMD_L4(b1,c1,d1,e1,a1, X[12],  9); RMD_R4(B,C,D,E,A, X[15],  6);
    RMD_L4(a1,b1,c1,d1,e1, X[ 4],  8); RMD_R4(A,B,C,D,E, X[ 0], 14);
    RMD_L4(e1,a1,b1,c1,d1, X[13],  9); RMD_R4(E,A,B,C,D, X[ 5],  6);
    RMD_L4(d1,e1,a1,b1,c1, X[ 3], 14); RMD_R4(D,E,A,B,C, X[12],  9);
    RMD_L4(c1,d1,e1,a1,b1, X[ 7],  5); RMD_R4(C,D,E,A,B, X[ 2], 12);
    RMD_L4(b1,c1,d1,e1,a1, X[15],  6); RMD_R4(B,C,D,E,A, X[13],  9);
    RMD_L4(a1,b1,c1,d1,e1, X[14],  8); RMD_R4(A,B,C,D,E, X[ 9], 12);
    RMD_L4(e1,a1,b1,c1,d1, X[ 5],  6); RMD_R4(E,A,B,C,D, X[ 7],  5);
    RMD_L4(d1,e1,a1,b1,c1, X[ 6],  5); RMD_R4(D,E,A,B,C, X[10], 15);
    RMD_L4(c1,d1,e1,a1,b1, X[ 2], 12); RMD_R4(C,D,E,A,B, X[14],  8);

    RMD_L5(b1,c1,d1,e1,a1, X[ 4],  9); RMD_R5(B,C,D,E,A, X[12],  8);
    RMD_L5(a1,b1,c1,d1,e1, X[ 0], 15); RMD_R5(A,B,C,D,E, X[15],  5);
    RMD_L5(e1,a1,b1,c1,d1, X[ 5],  5); RMD_R5(E,A,B,C,D, X[10], 12);
    RMD_L5(d1,e1,a1,b1,c1, X[ 9], 11); RMD_R5(D,E,A,B,C, X[ 4],  9);
    RMD_L5(c1,d1,e1,a1,b1, X[ 7],  6); RMD_R5(C,D,E,A,B, X[ 1], 12);
    RMD_L5(b1,c1,d1,e1,a1, X[12],  8); RMD_R5(B,C,D,E,A, X[ 5],  5);
    RMD_L5(a1,b1,c1,d1,e1, X[ 2], 13); RMD_R5(A,B,C,D,E, X[ 8], 14);
    RMD_L5(e1,a1,b1,c1,d1, X[10], 12); RMD_R5(E,A,B,C,D, X[ 7],  6);
    RMD_L5(d1,e1,a1,b1,c1, X[14],  5); RMD_R5(D,E,A,B,C, X[ 6],  8);
    RMD_L5(c1,d1,e1,a1,b1, X[ 1], 12); RMD_R5(C,D,E,A,B, X[ 2], 13);
    RMD_L5(b1,c1,d1,e1,a1, X[ 3], 13); RMD_R5(B,C,D,E,A, X[13],  6);
    RMD_L5(a1,b1,c1,d1,e1, X[ 8], 14); RMD_R5(A,B,C,D,E, X[14],  5);
    RMD_L5(e1,a1,b1,c1,d1, X[11], 11); RMD_R5(E,A,B,C,D, X[ 0], 15);
    RMD_L5(d1,e1,a1,b1,c1, X[ 6],  8); RMD_R5(D,E,A,B,C, X[ 3], 13);
    RMD_L5(c1,d1,e1,a1,b1, X[15],  5); RMD_R5(C,D,E,A,B, X[ 9], 11);
    RMD_L5(b1,c1,d1,e1,a1, X[13],  6); RMD_R5(B,C,D,E,A, X[11], 11);

    u32 t = hash[1] + c1 + D;
    hash[1] = hash[2] + d1 + E;
    hash[2] = hash[3] + e1 + A;
    hash[3] = hash[4] + a1 + B;
    hash[4] = hash[0] + b1 + C;
    hash[0] = t;
}

/* msg is always exactly 32 bytes here (a SHA-256 digest) -- one block,
 * fixed padding layout, no general absorb loop needed. */
static inline void ripemd160_of_32(const uchar msg32[32], uchar out20[20]) {
    u32 hash[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
    u32 X[16];
    for (int i = 0; i < 8; i++) X[i] = load_le32(msg32 + i * 4);
    X[8] = 0x00000080u;
    for (int i = 9; i < 14; i++) X[i] = 0;
    X[14] = 32u * 8u;
    X[15] = 0;
    ripemd160_process_block(hash, X);
    for (int i = 0; i < 5; i++) {
        out20[i*4+0] = (uchar)(hash[i]);
        out20[i*4+1] = (uchar)(hash[i] >> 8);
        out20[i*4+2] = (uchar)(hash[i] >> 16);
        out20[i*4+3] = (uchar)(hash[i] >> 24);
    }
}

static inline void hash160(const uchar *msg, uint msg_len, uchar out20[20]) {
    uchar digest[32];
    sha256_digest(msg, msg_len, digest);
    ripemd160_of_32(digest, out20);
}

/* ---------------------------------------------------------------- */
/* BIP32 child key derivation                                        */
/* ---------------------------------------------------------------- */

/* (a + b) mod N, working in 9x32-bit limbs so the extra carry/borrow bit
 * never needs separate bookkeeping. a can be any 256-bit value (an HMAC
 * output IL), b is always an already-reduced private key (< N), so
 * a+b < 2^256 + N < 3N (N > 2^255) -- at most two conditional subtractions
 * of N are ever needed. */
static inline void add_mod_n(u32 out[8], const u32 a[8], const u32 b[8]) {
    const u32 Nw[9] = {
        0xd0364141, 0xbfd25e8c, 0xaf48a03b, 0xbaaedce6, 0xfffffffe,
        0xffffffff, 0xffffffff, 0xffffffff, 0,
    };
    u32 sum[9];
    ulong carry = 0;
    for (int i = 0; i < 8; i++) {
        ulong s = (ulong)a[i] + (ulong)b[i] + carry;
        sum[i] = (u32)s;
        carry = s >> 32;
    }
    sum[8] = (u32)carry;

    for (int pass = 0; pass < 2; pass++) {
        int ge = 0;
        for (int i = 8; i >= 0; i--) {
            if (sum[i] > Nw[i]) { ge = 1; break; }
            if (sum[i] < Nw[i]) { ge = 0; break; }
            ge = 1; /* equal so far; if we exhaust the loop equal, ge stays 1 */
        }
        if (!ge) break;
        long borrow = 0;
        for (int i = 0; i < 9; i++) {
            long d = (long)sum[i] - (long)Nw[i] - borrow;
            if (d < 0) { d += 0x100000000L; borrow = 1; } else borrow = 0;
            sum[i] = (u32)d;
        }
    }
    for (int i = 0; i < 8; i++) out[i] = sum[i];
}

static inline void ckd_hardened(const u32 key[8], const uchar chain[32], u32 index,
                          u32 out_key[8], uchar out_chain[32]) {
    uchar data[37];
    data[0] = 0;
    words_to_be32_256(data + 1, key);
    store_be32(data + 33, index);

    ulong ipad[8], opad[8];
    hmac_sha512_init(ipad, opad, chain, 32);
    uchar I[64];
    hmac_sha512_once(ipad, opad, data, 37, I);

    u32 IL[8];
    be32_256_to_words(IL, I);
    add_mod_n(out_key, IL, key);
    for (int i = 0; i < 32; i++) out_chain[i] = I[32 + i];
}

static inline void ckd_nonhardened(const u32 key[8], const uchar chain[32], u32 index,
                             const uchar parent_pub33[33],
                             u32 out_key[8], uchar out_chain[32]) {
    uchar data[37];
    for (int i = 0; i < 33; i++) data[i] = parent_pub33[i];
    store_be32(data + 33, index);

    ulong ipad[8], opad[8];
    hmac_sha512_init(ipad, opad, chain, 32);
    uchar I[64];
    hmac_sha512_once(ipad, opad, data, 37, I);

    u32 IL[8];
    be32_256_to_words(IL, I);
    add_mod_n(out_key, IL, key);
    for (int i = 0; i < 32; i++) out_chain[i] = I[32 + i];
}

static inline void pubkey_both(const u32 key[8], SECP256K1_TMPS_TYPE const secp256k1_t *tmps,
                         uchar out_c33[33], uchar out_u65[65]) {
    u32 x[8], y[8];
    point_mul_xy(x, y, key, tmps);
    uchar xb[32], yb[32];
    words_to_be32_256(xb, x);
    words_to_be32_256(yb, y);

    out_c33[0] = 0x02u | (y[0] & 1u);
    for (int i = 0; i < 32; i++) out_c33[1 + i] = xb[i];

    out_u65[0] = 0x04;
    for (int i = 0; i < 32; i++) { out_u65[1 + i] = xb[i]; out_u65[33 + i] = yb[i]; }
}

static inline int bytes_eq20(const uchar a[20], CONSTANT_AS const uchar b[20]) {
    for (int i = 0; i < 20; i++) if (a[i] != b[i]) return 0;
    return 1;
}

/* checks one derivation-tree node against the target, records the debug
 * hash160 pair, and records the first match (even id = compressed hit,
 * odd id = uncompressed hit at node_idx = id/2) -- matches the semantics of
 * sparse_rare.py's _hit(), which checks both encodings. */
static inline void check_node(const uchar pub_c[33], const uchar pub_u[65],
                        CONSTANT_AS const uchar target[20],
                        GLOBAL_AS uchar *debug_out, uint node_idx, int *match_id) {
    uchar h1[20], h2[20];
    hash160(pub_c, 33, h1);
    hash160(pub_u, 65, h2);

    GLOBAL_AS uchar *slot = debug_out + (size_t)node_idx * 40;
    for (int i = 0; i < 20; i++) { slot[i] = h1[i]; slot[20 + i] = h2[i]; }

    if (*match_id < 0) {
        if (bytes_eq20(h1, target)) *match_id = (int)(node_idx * 2);
        else if (bytes_eq20(h2, target)) *match_id = (int)(node_idx * 2 + 1);
    }
}

#define NUM_NODES 44

/* ---------------------------------------------------------------- */
/* kernel                                                            */
/* ---------------------------------------------------------------- */

__kernel void bip32_search(
    __global const uchar *seeds,          /* batch * 64 */
    __constant uchar *target_hash160,     /* 20 bytes   */
    __global uchar *match_flags,          /* batch * 1  */
    __global int *match_info,             /* batch * 1  */
    __global uchar *debug_hash160         /* batch * NUM_NODES * 40 */
) {
    size_t gid = get_global_id(0);

    uchar seed[64];
    for (int i = 0; i < 64; i++) seed[i] = seeds[gid * 64 + i];

    secp256k1_t g_tmps;
    set_precomputed_basepoint_g(&g_tmps);

    const uchar bitcoin_seed_key[12] = { 'B','i','t','c','o','i','n',' ','s','e','e','d' };
    ulong ipad_m[8], opad_m[8];
    hmac_sha512_init(ipad_m, opad_m, bitcoin_seed_key, 12);
    uchar I0[64];
    hmac_sha512_once(ipad_m, opad_m, seed, 64, I0);

    u32 key_m[8];
    uchar chain_m[32];
    be32_256_to_words(key_m, I0);
    for (int i = 0; i < 32; i++) chain_m[i] = I0[32 + i];

    int match_id = -1;
    uint node_idx = 0;
    GLOBAL_AS uchar *dbg = debug_hash160 + (size_t)gid * NUM_NODES * 40;

    uchar mpub_c[33], mpub_u[65];
    pubkey_both(key_m, &g_tmps, mpub_c, mpub_u);
    check_node(mpub_c, mpub_u, target_hash160, dbg, node_idx++, &match_id);

    for (int account = 0; account < 2; account++) {
        u32 ka[8]; uchar ca[32];
        {
            u32 t1[8]; uchar tc1[32];
            ckd_hardened(key_m, chain_m, 44u + HARDENED, t1, tc1);
            u32 t2[8]; uchar tc2[32];
            ckd_hardened(t1, tc1, 0u + HARDENED, t2, tc2);
            ckd_hardened(t2, tc2, (u32)account + HARDENED, ka, ca);
        }
        uchar apub_c[33], apub_u[65];
        pubkey_both(ka, &g_tmps, apub_c, apub_u);
        check_node(apub_c, apub_u, target_hash160, dbg, node_idx++, &match_id);

        for (int change = 0; change < 2; change++) {
            u32 kb[8]; uchar cb[32];
            ckd_nonhardened(ka, ca, (u32)change, apub_c, kb, cb);
            uchar bpub_c[33], bpub_u[65];
            pubkey_both(kb, &g_tmps, bpub_c, bpub_u);
            check_node(bpub_c, bpub_u, target_hash160, dbg, node_idx++, &match_id);

            for (int i = 0; i < 4; i++) {
                u32 kd[8]; uchar cd[32];
                ckd_nonhardened(kb, cb, (u32)i, bpub_c, kd, cd);
                uchar dpub_c[33], dpub_u[65];
                pubkey_both(kd, &g_tmps, dpub_c, dpub_u);
                check_node(dpub_c, dpub_u, target_hash160, dbg, node_idx++, &match_id);
            }
        }
    }

    {
        u32 kh[8]; uchar ch[32];
        ckd_hardened(key_m, chain_m, 0u + HARDENED, kh, ch);
        uchar hpub_c[33], hpub_u[65];
        pubkey_both(kh, &g_tmps, hpub_c, hpub_u);
        check_node(hpub_c, hpub_u, target_hash160, dbg, node_idx++, &match_id);

        for (int change = 0; change < 2; change++) {
            u32 kb[8]; uchar cb[32];
            ckd_nonhardened(kh, ch, (u32)change, hpub_c, kb, cb);
            uchar bpub_c[33], bpub_u[65];
            pubkey_both(kb, &g_tmps, bpub_c, bpub_u);
            check_node(bpub_c, bpub_u, target_hash160, dbg, node_idx++, &match_id);

            for (int i = 0; i < 4; i++) {
                u32 kd[8]; uchar cd[32];
                ckd_nonhardened(kb, cb, (u32)i, bpub_c, kd, cd);
                uchar dpub_c[33], dpub_u[65];
                pubkey_both(kd, &g_tmps, dpub_c, dpub_u);
                check_node(dpub_c, dpub_u, target_hash160, dbg, node_idx++, &match_id);
            }
        }
    }

    for (int j = 0; j < 2; j++) {
        u32 kj[8]; uchar cj[32];
        ckd_nonhardened(key_m, chain_m, (u32)j, mpub_c, kj, cj);
        uchar jpub_c[33], jpub_u[65];
        pubkey_both(kj, &g_tmps, jpub_c, jpub_u);
        check_node(jpub_c, jpub_u, target_hash160, dbg, node_idx++, &match_id);

        for (int i = 0; i < 4; i++) {
            u32 kd[8]; uchar cd[32];
            ckd_nonhardened(kj, cj, (u32)i, jpub_c, kd, cd);
            uchar dpub_c[33], dpub_u[65];
            pubkey_both(kd, &g_tmps, dpub_c, dpub_u);
            check_node(dpub_c, dpub_u, target_hash160, dbg, node_idx++, &match_id);
        }
    }

    match_flags[gid] = (match_id >= 0) ? 1 : 0;
    match_info[gid] = match_id;
}
