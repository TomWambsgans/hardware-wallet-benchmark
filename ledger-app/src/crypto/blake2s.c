#include <string.h>

#include "blake2s.h"

uint32_t g_hash_calls;
uint32_t g_compressions;
// No initialized globals on BOLOS (no .data section): the app sets g_b2s_impl.
uint8_t g_b2s_impl;

static const uint32_t IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};

// IV[0] ^ parameter block of an unkeyed BLAKE2s-256: digest length 32, fanout 1, depth 1.
#define H0_UNKEYED (0x6A09E667u ^ 0x01010020u)

static const uint8_t SIGMA[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

static inline uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

#define G(a, b, c, d, x, y)         \
    do {                            \
        a = a + b + (x);            \
        d = rotr32(d ^ a, 16);      \
        c = c + d;                  \
        b = rotr32(b ^ c, 12);      \
        a = a + b + (y);            \
        d = rotr32(d ^ a, 8);       \
        c = c + d;                  \
        b = rotr32(b ^ c, 7);       \
    } while (0)

// The RFC 7693 loop. A fully unrolled C variant (constant message indices)
// measured no faster on the Nano S Plus (41.1 vs 40.1 us per compression).
void b2s_compress_c(uint32_t h[8], const uint32_t m[16], uint32_t t, uint32_t f) {
    uint32_t v[16];
    for (unsigned i = 0; i < 8; i++) {
        v[i] = h[i];
        v[i + 8] = IV[i];
    }
    v[12] ^= t;
    v[14] ^= f;
    for (unsigned r = 0; r < 10; r++) {
        const uint8_t *s = SIGMA[r];
        G(v[0], v[4], v[8], v[12], m[s[0]], m[s[1]]);
        G(v[1], v[5], v[9], v[13], m[s[2]], m[s[3]]);
        G(v[2], v[6], v[10], v[14], m[s[4]], m[s[5]]);
        G(v[3], v[7], v[11], v[15], m[s[6]], m[s[7]]);
        G(v[0], v[5], v[10], v[15], m[s[8]], m[s[9]]);
        G(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
        G(v[2], v[7], v[8], v[13], m[s[12]], m[s[13]]);
        G(v[3], v[4], v[9], v[14], m[s[14]], m[s[15]]);
    }
    for (unsigned i = 0; i < 8; i++) {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

void b2s_compress(uint32_t h[8], const uint32_t m[16], uint32_t t, uint32_t f) {
    g_compressions++;
#if defined(__thumb2__)
    if (g_b2s_impl == B2S_ASM) {
        b2s_compress_asm(h, m, t, f);
        return;
    }
    if (g_b2s_impl == B2S_ASM2) {
        b2s_compress_asm2(h, m, t, f);
        return;
    }
    if (g_b2s_impl == B2S_ASM3) {
        b2s_compress_asm3(h, m, t, f);
        return;
    }
#endif
    b2s_compress_c(h, m, t, f);
}

static inline void init_h(uint32_t h[8]) {
    h[0] = H0_UNKEYED;
    for (unsigned i = 1; i < 8; i++) {
        h[i] = IV[i];
    }
}

void b2s_oneblock(uint32_t *out, unsigned out_words, const uint32_t block[16], uint32_t len) {
    uint32_t h[8];
    init_h(h);
    g_hash_calls++;
    b2s_compress(h, block, len, 0xFFFFFFFFu);
    memcpy(out, h, out_words * 4);
}

void b2s_init(b2s_ctx_t *c) {
    init_h(c->h);
    c->buf_words = 0;
    c->t = 0;
}

// The last block is always kept back for b2s_final, which sets the final flag.
void b2s_update_words(b2s_ctx_t *c, const uint32_t *w, size_t n_words) {
    while (n_words > 0) {
        if (c->buf_words == 16) {
            c->t += 64;
            b2s_compress(c->h, c->buf, c->t, 0);
            c->buf_words = 0;
        }
        size_t take = 16 - c->buf_words;
        if (take > n_words) {
            take = n_words;
        }
        memcpy(c->buf + c->buf_words, w, take * 4);
        c->buf_words += take;
        w += take;
        n_words -= take;
    }
}

void b2s_final(b2s_ctx_t *c, uint32_t out[8]) {
    c->t += c->buf_words * 4;
    memset(c->buf + c->buf_words, 0, (16 - c->buf_words) * 4);
    g_hash_calls++;
    b2s_compress(c->h, c->buf, c->t, 0xFFFFFFFFu);
    memcpy(out, c->h, 32);
}

void b2s_hash_bytes(uint32_t out[8], const uint8_t *in, size_t len) {
    uint32_t h[8];
    uint32_t block[16];
    uint32_t t = 0;
    init_h(h);
    // Every block but the last is compressed without the final flag; an empty
    // input is one all-zero final block.
    while (len > 64) {
        memcpy(block, in, 64);
        t += 64;
        b2s_compress(h, block, t, 0);
        in += 64;
        len -= 64;
    }
    memset(block, 0, sizeof(block));
    memcpy(block, in, len);
    t += len;
    g_hash_calls++;
    b2s_compress(h, block, t, 0xFFFFFFFFu);
    memcpy(out, h, 32);
}
