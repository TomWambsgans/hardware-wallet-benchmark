// Runs the device's crypto code (ledger-app/src/crypto) natively, to check it
// against leanVM's vectors before sideloading. See check_native.py.
//   spx_native <impl> keygen <seed hex>            -> P root
//   spx_native <impl> sign <seed hex> <msg hex>    -> signature hex, stats

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blake2s.h"
#include "sphincs.h"

void spx_yield(void) {}

static void unhex(uint8_t *out, const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        sscanf(s + 2 * i, "%2hhx", &out[i]);
    }
}

static void puthex(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        printf("%02x", p[i]);
    }
}

int main(int argc, char **argv) {
    static spx_key_t key;
    static uint8_t   sig[SPX_SIG_BYTES];
    uint8_t          seed[32], msg[32];

    if (argc < 4) {
        fprintf(stderr, "usage: %s <impl> keygen|sign <seed hex> [msg hex]\n", argv[0]);
        return 2;
    }
    g_impl = (uint8_t) atoi(argv[1]);
    unhex(seed, argv[3], 32);
    spx_keygen(&key, seed);
    if (strcmp(argv[2], "keygen") == 0) {
        puthex((uint8_t *) key.pp, 16);
        printf(" ");
        puthex((uint8_t *) key.root, 16);
        printf(" %u %u\n", g_hash_calls, g_compressions);
        return 0;
    }
    unhex(msg, argv[4], 32);
    spx_sign_stats_t st;
    g_hash_calls = g_compressions = 0;
    int ok = spx_sign(&key, msg, sig, &st);
    puthex(sig, sizeof(sig));
    printf(" %d %u %u %u %u %u %u\n", ok, g_hash_calls, g_compressions, st.digest_trials, st.counters[0],
           st.counters[1], st.counters[2]);
    return 0;
}
