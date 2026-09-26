#pragma once

// BLAKE2s-256 (RFC 7693, unkeyed) on 32-bit words: a 64-byte block is 16
// little-endian words, i.e. the same memory as the bytes.

#include <stdint.h>

// The unkeyed BLAKE2s-256 initial state.
void blake2s_init_state(uint32_t h[8]);

// One compression of block m at byte counter t (inputs here are < 4 GiB), final flag f.
void blake2s_compress(uint32_t h[8], const uint32_t m[16], uint32_t t, uint32_t f);

// First 16 bytes of BLAKE2s-256(block[0..len)), len <= 64, block zero-padded.
void blake2s_oneblock16(uint32_t out[4], const uint32_t block[16], uint32_t len);

// Copies the assembly's table to RAM (loads from flash are slower). Device only; a no-op elsewhere.
void blake2s_setup(void);
