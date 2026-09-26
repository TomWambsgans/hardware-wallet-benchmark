#pragma once

// SHA-256 compression function (FIPS 180-4). A block is 64 bytes, read big-endian as
// SHA-256 specifies, passed as a 16-word array (the bytes' memory); a state is 8 words.

#include <stdint.h>

// The standard SHA-256 initial state.
void sha256_init_state(uint32_t h[8]);

// One compression of the 64-byte block.
void sha256_compress(uint32_t h[8], const uint32_t block[16]);

// First 16 bytes (big-endian) of compress(IV, block): the SHA-256 scheme's hash of an
// input of at most 64 bytes, zero-padded to the block.
void sha256_oneblock16(uint32_t out[4], const uint32_t block[16]);

// Copies the assembly's K table to RAM (loads from flash are slower). Device only; a no-op elsewhere.
void sha256_setup(void);
