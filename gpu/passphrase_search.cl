/*
 * BIP39-passphrase search for the Corey Phillips kitten puzzle.
 *
 * One work-item per candidate passphrase:
 *
 *   seed  = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048, 64)
 *   key   = BIP32 m/84'/0'/0'/0/0
 *   match = hash160(compressed pubkey) == target
 *
 * Relationship to the poetry-puzzle kernels this reuses
 * -----------------------------------------------------
 * gpu/pbkdf2_sha512.cl and gpu/bip32_tree.cl were written for the reverse
 * problem: there the MNEMONIC varies and the passphrase is a batch-wide
 * constant, and 46 derivation-tree nodes get tested per candidate. Here the
 * mnemonic is fixed and public, the PASSPHRASE varies, and there is exactly
 * one node to test. So:
 *
 *   - the varying bytes move from the PBKDF2 password into the PBKDF2 salt,
 *     which is why this needs its own kernel rather than a new argument;
 *   - m/84'/0'/0' are all hardened, so only 3 EC multiplications happen
 *     (the two non-hardened levels plus the final pubkey) instead of ~46.
 *
 * Everything else -- SHA-512, HMAC, SHA-256, RIPEMD-160, hash160, add_mod_n,
 * ckd_hardened, ckd_nonhardened, pubkey_both, and hashcat's vendored
 * secp256k1 -- is used unmodified from those two files.
 *
 * Host contract (see gpu_bruteforce.py):
 *   mnemonic      : __constant, the NFKD mnemonic bytes, no trailing NUL
 *   mnemonic_len  : its length (152 for the kitten mnemonic)
 *   pass_blob     : all candidate passphrases concatenated, no separators
 *   pass_off      : batch+1 offsets into pass_blob; candidate i is
 *                   pass_blob[pass_off[i] .. pass_off[i+1])
 *   target_hash160: 20 bytes, the decoded witness program of the target
 *   match_flags   : batch bytes, set to 1 for a match
 *
 * A candidate longer than MAX_PASS bytes must be handled by the host (it is
 * cheaper to check those few on the CPU than to size every buffer for them).
 * The host enforces this; the kernel clamps as a backstop so a mistake can
 * never read out of bounds.
 */

#define MAX_PASS 192
#define BIP39_ITERS 2048

__kernel void search_passphrase(
    __constant uchar *mnemonic,
    const uint mnemonic_len,
    __global const uchar *pass_blob,
    __global const uint *pass_off,
    __constant uchar *target_hash160,
    __global uchar *match_flags
) {
    size_t gid = get_global_id(0);

    /* hmac_sha512_init() and friends take generic (private) pointers, so the
     * __constant mnemonic and __global passphrase have to be copied into
     * private arrays first -- same pattern as search.cl's word_table copy. */
    uchar password[256];
    uint plen = mnemonic_len > 256 ? 256 : mnemonic_len;
    for (uint i = 0; i < plen; i++) password[i] = mnemonic[i];

    uint off = pass_off[gid];
    uint pass_len = pass_off[gid + 1] - off;
    if (pass_len > MAX_PASS) pass_len = MAX_PASS;

    /* salt = "mnemonic" || passphrase || INT_32_BE(1) */
    uchar salt[8 + MAX_PASS + 4];
    salt[0] = 'm'; salt[1] = 'n'; salt[2] = 'e'; salt[3] = 'm';
    salt[4] = 'o'; salt[5] = 'n'; salt[6] = 'i'; salt[7] = 'c';
    for (uint i = 0; i < pass_len; i++) salt[8 + i] = pass_blob[off + i];
    uint slen = 8 + pass_len;
    salt[slen++] = 0; salt[slen++] = 0; salt[slen++] = 0; salt[slen++] = 1;

    /* PBKDF2. The mnemonic is the HMAC key and never changes, but it is
     * >128 bytes so hmac_sha512_init() hashes it down first; that is 4 extra
     * compressions against the 4096 the iteration loop performs, i.e. noise.
     * Hoisting it to the host would save ~0.1% and cost a clarity/parity
     * risk, so it stays here. */
    ulong ipad_pw[8], opad_pw[8];
    hmac_sha512_init(ipad_pw, opad_pw, password, plen);

    uchar U[64], T[64];
    hmac_sha512_once(ipad_pw, opad_pw, salt, slen, U);
    for (int i = 0; i < 64; i++) T[i] = U[i];
    for (int iter = 1; iter < BIP39_ITERS; iter++) {
        uchar Un[64];
        hmac_sha512_once(ipad_pw, opad_pw, U, 64, Un);
        for (int i = 0; i < 64; i++) { T[i] ^= Un[i]; U[i] = Un[i]; }
    }
    /* T is the 64-byte BIP39 seed */

    secp256k1_t g_tmps;
    set_precomputed_basepoint_g(&g_tmps);

    const uchar bitcoin_seed_key[12] = { 'B','i','t','c','o','i','n',' ','s','e','e','d' };
    ulong ipad_m[8], opad_m[8];
    hmac_sha512_init(ipad_m, opad_m, bitcoin_seed_key, 12);
    uchar I0[64];
    hmac_sha512_once(ipad_m, opad_m, T, 64, I0);

    u32 key[8];
    uchar chain[32];
    be32_256_to_words(key, I0);
    for (int i = 0; i < 32; i++) chain[i] = I0[32 + i];

    /* m/84'/0'/0' -- hardened, so no pubkey is needed at these levels */
    u32 k1[8]; uchar c1[32];
    ckd_hardened(key, chain, 84u + HARDENED, k1, c1);
    u32 k2[8]; uchar c2[32];
    ckd_hardened(k1, c1, 0u + HARDENED, k2, c2);
    u32 k3[8]; uchar c3[32];
    ckd_hardened(k2, c2, 0u + HARDENED, k3, c3);

    /* /0/0 -- non-hardened, one pubkey each, plus the final child's pubkey */
    uchar pub_c[33], pub_u[65];
    pubkey_both(k3, &g_tmps, pub_c, pub_u);
    u32 k4[8]; uchar c4[32];
    ckd_nonhardened(k3, c3, 0u, pub_c, k4, c4);

    pubkey_both(k4, &g_tmps, pub_c, pub_u);
    u32 k5[8]; uchar c5[32];
    ckd_nonhardened(k4, c4, 0u, pub_c, k5, c5);

    pubkey_both(k5, &g_tmps, pub_c, pub_u);

    /* P2WPKH commits to the COMPRESSED pubkey only -- unlike the P2PKH search
     * in search.cl there is no uncompressed encoding to also test. */
    uchar h160[20];
    hash160(pub_c, 33, h160);
    match_flags[gid] = bytes_eq20(h160, target_hash160) ? 1 : 0;
}
