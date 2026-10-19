#include <string.h>

#include "blake2s.h"
#include "hash.h"
#include "keccak.h"
#include "sha256.h"

hash_id_t g_hash;
uint32_t  g_compressions;

void hash_setup(void) {
    blake2s_setup();
    sha256_setup();
    keccak_setup();
}

void th_oneblock(uint32_t out[4], const uint32_t block[16], uint32_t len) {
    g_compressions++;
    if (g_hash == HASH_SHA256) {
        sha256_oneblock16(out, block);
    } else if (g_hash == HASH_KECCAK256) {
        keccak256_oneblock16(out, block, len);
    } else {
        blake2s_oneblock16(out, block, len);
    }
}

void h_init(hctx_t *c) {
    c->buf_words = 0;
    c->t = 0;
    if (g_hash == HASH_SHA256) {
        sha256_init_state(c->h);
    } else if (g_hash == HASH_KECCAK256) {
        memset(c->h, 0, sizeof(c->h));
    } else {
        blake2s_init_state(c->h);
    }
}

static void compress_buf(hctx_t *c, uint32_t final) {
    g_compressions++;
    if (g_hash == HASH_SHA256) {
        sha256_compress(c->h, c->buf);
    } else if (g_hash == HASH_KECCAK256) {
        keccak_absorb(c->h, c->buf, KECCAK_RATE_WORDS);
        keccak_permute(c->h);
    } else {
        blake2s_compress(c->h, c->buf, c->t, final ? 0xFFFFFFFFu : 0);
    }
}

static uint32_t block_words(void) {
    return g_hash == HASH_KECCAK256 ? KECCAK_RATE_WORDS : 16;
}

// A full buffer is compressed only once more input arrives: the last block
// (BLAKE2s: with the final flag) is left for h_final.
void h_update_words(hctx_t *c, const uint32_t *w, uint32_t n_words) {
    const uint32_t bw = block_words();
    while (n_words > 0) {
        if (c->buf_words == bw) {
            c->t += 64;
            compress_buf(c, 0);
            c->buf_words = 0;
        }
        uint32_t take = bw - c->buf_words;
        if (take > n_words) {
            take = n_words;
        }
        memcpy(c->buf + c->buf_words, w, take * 4);
        c->buf_words += take;
        w += take;
        n_words -= take;
    }
}

void h_final(hctx_t *c, uint32_t out[8]) {
    if (g_hash == HASH_KECCAK256) {
        // The padding needs a byte of room: a full block is absorbed on its own first.
        if (c->buf_words == KECCAK_RATE_WORDS) {
            compress_buf(c, 0);
            c->buf_words = 0;
        }
        g_compressions++;
        keccak_absorb(c->h, c->buf, c->buf_words);
        keccak_pad(c->h, 4 * c->buf_words);
        keccak_permute(c->h);
        keccak_squeeze(out, c->h, 8);
        return;
    }
    c->t += c->buf_words * 4;
    memset(c->buf + c->buf_words, 0, (16 - c->buf_words) * 4);
    compress_buf(c, 1);
    if (g_hash == HASH_SHA256) {
        uint8_t *o = (uint8_t *) out;
        for (unsigned i = 0; i < 8; i++) {
            o[4 * i] = (uint8_t) (c->h[i] >> 24);
            o[4 * i + 1] = (uint8_t) (c->h[i] >> 16);
            o[4 * i + 2] = (uint8_t) (c->h[i] >> 8);
            o[4 * i + 3] = (uint8_t) c->h[i];
        }
    } else {
        memcpy(out, c->h, 32);
    }
}
