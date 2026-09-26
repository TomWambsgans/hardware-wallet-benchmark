// The device's scheme code (ledger-app/src/crypto, portable C paths) on the host.
//   spx_native <blake2s|sha256> <seed hex> <message hex>  ->  "P root signature"

#include <stdio.h>
#include <string.h>

#include "hash.h"
#include "sphincs.h"

static void unhex(uint8_t *out, const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        sscanf(s + 2 * i, "%2hhx", &out[i]);
    }
}

static void puthex(const void *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        printf("%02x", ((const uint8_t *) p)[i]);
    }
}

int main(int argc, char **argv) {
    static spx_key_t key;
    static uint8_t   sig[SPX_SIG_BYTES];
    uint8_t          seed[32], msg[32];
    spx_sign_stats_t stats;

    if (argc != 4) {
        fprintf(stderr, "usage: %s <blake2s|sha256> <seed hex> <message hex>\n", argv[0]);
        return 2;
    }
    g_hash = strcmp(argv[1], "sha256") == 0 ? HASH_SHA256 : HASH_BLAKE2S;
    unhex(seed, argv[2], 32);
    unhex(msg, argv[3], 32);
    spx_keygen(&key, seed);
    if (!spx_sign(&key, msg, sig, &stats)) {
        return 1;
    }
    puthex(key.pp, 16);
    printf(" ");
    puthex(key.root, 16);
    printf(" ");
    puthex(sig, sizeof(sig));
    printf("\n");
    return 0;
}
