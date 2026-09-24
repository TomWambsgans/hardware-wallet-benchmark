#pragma once

// leanVM's SPHINCS+ variant: BLAKE2s, WOTS+C and FORS+C, 2^24 signatures per key.
// Spec: leanVM doc/sphincs/main.tex; reference: leanVM crates/sphincs.
//   Th(P, tw, M) = BLAKE2s-256(tw || P || M)[..16]
//   WOTS+C: w = 3 (chains of 8), v = 42 chains, target sum T = 191
//   hypertree: d = 3 layers numbered from the top, heights (12, 7, 7)
//   FORS+C: a = 10, k = 15 digest indices, k - 1 = 14 trees
// Values (n = 16 bytes) are handled as 4 little-endian 32-bit words.

#include <stdbool.h>
#include <stdint.h>

#define SPX_N_WORDS   4
#define SPX_W         3
#define SPX_CHAIN_LEN 8
#define SPX_V         42
#define SPX_T         191
#define SPX_D         3
#define SPX_H0        12
#define SPX_H1        7
#define SPX_H2        7
#define SPX_H         (SPX_H0 + SPX_H1 + SPX_H2)
#define SPX_A         10
#define SPX_K         15
#define SPX_FTS_TREES (SPX_K - 1)
// Layer 0's nodes at this level are the signer's 1 KB public cache.
#define SPX_SPLIT     6
#define SPX_CACHE_LEN (1 << (SPX_H0 - SPX_SPLIT))

#define SPX_SIG_BYTES (16 + SPX_FTS_TREES * (1 + SPX_A) * 16 + SPX_D * (4 + SPX_V * 16) + SPX_H * 16)
_Static_assert(SPX_SIG_BYTES == 4924, "signature size");

typedef uint32_t val_t[SPX_N_WORDS];

typedef struct {
    uint32_t master[8];  // S, 256 bits
    val_t    pp;         // P
    val_t    root;
    val_t    cache[SPX_CACHE_LEN];
} spx_key_t;

// What a signature cost, beyond the hash counters.
typedef struct {
    uint32_t digest_trials;    // randomizers tried until u_{k-1} = 0
    uint32_t counters[SPX_D];  // least admissible WOTS encoding counter per layer
} spx_sign_stats_t;

// Called between units of work so the device can service its event loop
// during a long computation. Defined by the app.
void spx_yield(void);

// Gen on a 32-byte master seed: P, then layer 0's tree (root and cache).
void spx_keygen(spx_key_t *key, const uint8_t seed[32]);

// Sign a 32-byte message into sig (SPX_SIG_BYTES). Returns false if the final
// root differs from key->root (an internal consistency check).
bool spx_sign(const spx_key_t *key, const uint8_t msg[32], uint8_t *sig, spx_sign_stats_t *stats);

// Microbenchmarks: count chain steps (one compression each), or count WOTS
// public leaves (42 PRF + 294 chain steps + an 11-block leaf hash each).
void spx_bench_chain(const spx_key_t *key, uint32_t count, val_t out);
void spx_bench_ots_leaf(const spx_key_t *key, uint32_t count, val_t out);
