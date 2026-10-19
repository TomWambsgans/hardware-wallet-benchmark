#pragma once

// Keccak-f[1600] and the Keccak-256 sponge: rate 136 bytes, padding 0x01 ... 0x80 (the
// original Keccak, as Ethereum uses it; not SHA3-256). A state is 50 words in this
// platform's representation: on the device bit-interleaved (each 64-bit lane as a word of
// its even bits, then a word of its odd bits), elsewhere the plain little-endian lanes.

#include <stdint.h>

#define KECCAK_RATE_WORDS 34

// XORs n_words (<= 34) input words (the input's bytes) into the start of the rate.
void keccak_absorb(uint32_t s[50], const uint32_t *in, uint32_t n_words);

// XORs the padding of a final block holding n_bytes (< 136) of input.
void keccak_pad(uint32_t s[50], uint32_t n_bytes);

void keccak_permute(uint32_t s[50]);

// The first n_words (even) words of output.
void keccak_squeeze(uint32_t *out, const uint32_t s[50], uint32_t n_words);

// First 16 bytes of Keccak-256(block[0..len)), len <= 64, block zero-padded.
void keccak256_oneblock16(uint32_t out[4], const uint32_t block[16], uint32_t len);

// A WOTS chain of Keccak-256 Th steps (hash.h, th_chain): v = Keccak-256(block)[0..16)
// `steps` times, block word 1 = p, p + 1, ..., words 8..11 = v, 48 bytes.
void keccak256_chain16(uint32_t v[4], const uint32_t block[16], uint32_t p, uint32_t steps);

// Copies the assembly's round constants to RAM (loads from flash are slower). Device only; a no-op elsewhere.
void keccak_setup(void);
