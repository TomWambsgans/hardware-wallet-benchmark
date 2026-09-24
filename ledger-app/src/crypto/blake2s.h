#pragma once

// BLAKE2s-256 (RFC 7693, unkeyed), and the one-block fast path the scheme uses
// for nearly every call.
// Everything works on little-endian 32-bit words: on the (little-endian) device
// a byte string and its word array are the same memory.

#include <stddef.h>
#include <stdint.h>

extern uint32_t g_hash_calls;    // BLAKE2s evaluations
extern uint32_t g_compressions;  // compression function calls

// One compression of block m at byte counter t (inputs here are < 4 GiB), final
// flag f, by the implementation g_b2s_impl selects (B2S_*; the C one where there
// is no Thumb-2 assembly, e.g. natively on the host).
void b2s_compress(uint32_t h[8], const uint32_t m[16], uint32_t t, uint32_t f);
void b2s_compress_c(uint32_t h[8], const uint32_t m[16], uint32_t t, uint32_t f);
#if defined(__thumb2__)
void b2s_compress_asm(uint32_t h[8], const uint32_t m[16], uint32_t t, uint32_t f);   // blake2s_thumb2.S
void b2s_compress_asm2(uint32_t h[8], const uint32_t m[16], uint32_t t, uint32_t f);  // blake2s_thumb2.S
void b2s_compress_asm3(uint32_t h[8], const uint32_t m[16], uint32_t t, uint32_t f);  // blake2s_thumb2.S
#endif
enum { B2S_C = 0, B2S_ASM = 1, B2S_ASM2 = 2, B2S_ASM3 = 3, B2S_IMPLS };
extern uint8_t g_b2s_impl;

// BLAKE2s-256 of an input of len <= 64 bytes, already laid out zero-padded in
// block: a single compression. Writes the first out_words words of the digest.
void b2s_oneblock(uint32_t *out, unsigned out_words, const uint32_t block[16], uint32_t len);

// Streaming BLAKE2s-256, for the multi-block inputs (WOTS leaves, FORS roots,
// message digest). Absorbs whole 16-byte words only, which is all the scheme needs.
typedef struct {
    uint32_t h[8];
    uint32_t buf[16];
    uint32_t buf_words;  // words in buf
    uint32_t t;          // bytes compressed so far
} b2s_ctx_t;

void b2s_init(b2s_ctx_t *c);
void b2s_update_words(b2s_ctx_t *c, const uint32_t *w, size_t n_words);
void b2s_final(b2s_ctx_t *c, uint32_t out[8]);

// BLAKE2s-256 of arbitrary bytes, for cross-checking against the host.
void b2s_hash_bytes(uint32_t out[8], const uint8_t *in, size_t len);
