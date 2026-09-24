// One SHA-256 compression from an arbitrary chaining value, through the OS crypto
// library's public SHA-256 API. The API has no compression call and no IV
// parameter, but the context lives in app memory: cx_sha256_init sets acc to the
// standard IV (8 native uint32 words), cx_sha256_update compresses as soon as a
// 64-byte block is complete, and only cx_sha256_final pads and byte-swaps. So
// overwriting acc and updating with exactly one block is one raw compression
// (lib_cxng/src/cx_sha256.c in the SDK; checked on the device by pqbench.py).

#include <string.h>

#include "cx.h"
#include "sha256_os.h"

int sha256_compress_os(uint32_t h[8], const uint32_t m[16]) {
    cx_sha256_t ctx;
    uint8_t     block[64];

    for (unsigned i = 0; i < 16; i++) {
        block[4 * i] = (uint8_t) (m[i] >> 24);
        block[4 * i + 1] = (uint8_t) (m[i] >> 16);
        block[4 * i + 2] = (uint8_t) (m[i] >> 8);
        block[4 * i + 3] = (uint8_t) m[i];
    }
    cx_sha256_init_no_throw(&ctx);
    memcpy(ctx.acc, h, 32);
    cx_err_t err = cx_sha256_update(&ctx, block, sizeof(block));
    memcpy(h, ctx.acc, 32);
    return err == CX_OK ? 0 : -1;
}
