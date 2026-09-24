#pragma once

#include <stdint.h>

// SHA-256 compression by the OS crypto library, from any chaining value h (8
// native words) on message words m (the big-endian decoding of the block).
// Returns 0 on success.
int sha256_compress_os(uint32_t h[8], const uint32_t m[16]);
