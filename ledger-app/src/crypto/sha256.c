#include "sha256.h"

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROTR(x, n)    (((x) >> (n)) | ((x) << (32 - (n))))
#define SIG0(x)       (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIG1(x)       (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sig0(x)       (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define sig1(x)       (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))
#define CH(x, y, z)   ((z) ^ ((x) & ((y) ^ (z))))
#define MAJ(x, y, z)  (((x) & (y)) | ((z) & ((x) | (y))))

// One round with the eight working variables renamed instead of shifted.
#define RND(a, b, c, d, e, f, g, h, i)                                 \
    do {                                                               \
        uint32_t t1 = (h) + SIG1(e) + CH(e, f, g) + K[i] + W[i];      \
        (d) += t1;                                                     \
        (h) = t1 + SIG0(a) + MAJ(a, b, c);                             \
    } while (0)

void sha256_compress_c(uint32_t s[8], const uint32_t m[16]) {
    uint32_t W[64];
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];

    for (int i = 0; i < 16; i++) {
        W[i] = m[i];
    }
    for (int i = 16; i < 64; i++) {
        W[i] = sig1(W[i - 2]) + W[i - 7] + sig0(W[i - 15]) + W[i - 16];
    }
    for (int i = 0; i < 64; i += 8) {
        RND(a, b, c, d, e, f, g, h, i + 0);
        RND(h, a, b, c, d, e, f, g, i + 1);
        RND(g, h, a, b, c, d, e, f, i + 2);
        RND(f, g, h, a, b, c, d, e, i + 3);
        RND(e, f, g, h, a, b, c, d, i + 4);
        RND(d, e, f, g, h, a, b, c, i + 5);
        RND(c, d, e, f, g, h, a, b, i + 6);
        RND(b, c, d, e, f, g, h, a, i + 7);
    }
    s[0] += a;
    s[1] += b;
    s[2] += c;
    s[3] += d;
    s[4] += e;
    s[5] += f;
    s[6] += g;
    s[7] += h;
}
