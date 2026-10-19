#pragma once

// The scheme's hash H, instantiated with
//  - BLAKE2s-256 (leanVM's scheme),
//  - the SHA-256 compression function applied from the standard IV to the input's
//    64-byte blocks, the last one zero-padded, no length padding; the digest is the
//    final state, big-endian. Every input length is fixed by its tweak type; or
//  - Keccak-256, as in Ethereum (keccak.h).
// Inputs are whole 16-byte words; digests are byte strings held in word arrays.

#include <stdint.h>

typedef enum { HASH_BLAKE2S = 0, HASH_SHA256 = 1, HASH_KECCAK256 = 2, HASH_COUNT } hash_id_t;

extern hash_id_t g_hash;          // the hash every call below uses
extern uint32_t  g_compressions;  // compression function (Keccak: permutation) calls, for the stats

// Once at startup: the assembly's tables to RAM.
void hash_setup(void);

// Th's one-block case: H(block[0..len))[0..16), len <= 64, block zero-padded.
void th_oneblock(uint32_t out[4], const uint32_t block[16], uint32_t len);

// A WOTS chain: `steps` times, v = Th of the 48-byte block with word 1 = p, p + 1, ...
// and words 8..11 = v (block words 12..15 zero). Keccak keeps v interleaved throughout.
void th_chain(uint32_t v[4], uint32_t block[16], uint32_t p, uint32_t steps);

// H over longer inputs (WOTS leaves, FORS roots, message digest), streamed.
typedef struct {
    uint32_t h[50];   // chaining value; Keccak: the sponge state
    uint32_t buf[34]; // a block: 16 words; Keccak: the rate, 34
    uint32_t buf_words;
    uint32_t t;  // bytes compressed (BLAKE2s counter)
} hctx_t;

void h_init(hctx_t *c);
void h_update_words(hctx_t *c, const uint32_t *w, uint32_t n_words);
void h_final(hctx_t *c, uint32_t out[8]);  // the 32-byte digest
