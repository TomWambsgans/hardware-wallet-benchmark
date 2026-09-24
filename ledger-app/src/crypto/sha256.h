#pragma once

// SHA-256 compression function (FIPS 180-4) on 32-bit words: h the 8-word
// chaining value (any IV), m the 16 message words, i.e. the big-endian decoding
// of a 64-byte block. No padding, no length: one compression per call.

#include <stdint.h>

void sha256_compress_c(uint32_t h[8], const uint32_t m[16]);
#if defined(__thumb2__)
void sha256_compress_asm(uint32_t h[8], const uint32_t m[16]);   // sha256_thumb2.S
void sha256_compress_asm2(uint32_t h[8], const uint32_t m[16]);  // sha256_thumb2.S
void sha256_compress_asm3(uint32_t h[8], const uint32_t m[16]);  // sha256_thumb2.S
#endif
