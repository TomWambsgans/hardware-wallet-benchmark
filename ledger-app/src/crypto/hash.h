#pragma once

// The scheme's hash H, instantiated with either
//  - BLAKE2s-256 (leanVM's scheme), or
//  - the SHA-256 compression function applied from the standard IV to the input's
//    64-byte blocks, the last one zero-padded, no length padding; the digest is the
//    final state, big-endian. Every input length is fixed by its tweak type.
// Inputs are whole 16-byte words; digests are byte strings held in word arrays.

#include <stdint.h>

typedef enum { HASH_BLAKE2S = 0, HASH_SHA256 = 1, HASH_COUNT } hash_id_t;

extern hash_id_t g_hash;          // the hash every call below uses
extern uint32_t  g_compressions;  // compression function calls, for the stats

// Once at startup: the assembly's tables to RAM.
void hash_setup(void);

// Th's one-block case: H(block[0..len))[0..16), len <= 64, block zero-padded.
void th_oneblock(uint32_t out[4], const uint32_t block[16], uint32_t len);

// H over longer inputs (WOTS leaves, FORS roots, message digest), streamed.
typedef struct {
    uint32_t h[8];
    uint32_t buf[16];
    uint32_t buf_words;
    uint32_t t;  // bytes compressed (BLAKE2s counter)
} hctx_t;

void h_init(hctx_t *c);
void h_update_words(hctx_t *c, const uint32_t *w, uint32_t n_words);
void h_final(hctx_t *c, uint32_t out[8]);  // the 32-byte digest
