#include <string.h>

#include "hash.h"
#include "sphincs.h"

// Tweak types (spec, Appendix A).
enum {
    TW_PRF        = 0,
    TW_CHAIN      = 1,
    TW_LEAF       = 2,
    TW_NODE       = 3,
    TW_ENC        = 4,
    TW_PARAMETER  = 5,
    TW_RANDOMIZER = 7,
    TW_FTS_PRF    = 8,
    TW_FTS_LEAF   = 9,
    TW_FTS_NODE   = 10,
    TW_FTS_ROOTS  = 11,
    TW_MSG        = 12,
};

// Signature layout: rho, 14 FORS openings (secret + 10 siblings), then per
// layer 0..2: LE32 counter, 42 chain values, h_lay siblings.
#define FTS_OPENING_BYTES (16 * (1 + SPX_A))
#define LAYER0_OFFSET     (16 + SPX_FTS_TREES * FTS_OPENING_BYTES)
#define LAYER_OTS_BYTES   (4 + SPX_V * 16)

static const uint8_t HEIGHTS[SPX_D] = {SPX_H0, SPX_H1, SPX_H2};

// The key every call reads P and S from, set per operation.
static const spx_key_t *K_;

static inline void copy4(uint32_t *dst, const uint32_t *src) {
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
}

// tw = [domain_sep = 1 | type | layer | 0 | p:LE32 | tree:LE32 | index:LE32],
// as four little-endian words.
static inline void tweak(uint32_t tw[4], uint32_t type, uint32_t lay, uint32_t tau, uint32_t p, uint32_t j) {
    tw[0] = 1u | (type << 8) | (lay << 16);
    tw[1] = p;
    tw[2] = tau;
    tw[3] = j;
}

// The first 32 bytes of every Th input: tw || P.
static inline void block_head(uint32_t blk[16], uint32_t type, uint32_t lay, uint32_t tau, uint32_t p, uint32_t j) {
    tweak(blk, type, lay, tau, p, j);
    copy4(blk + 4, K_->pp);
}

// Th(P, tw, S): a derived secret, 64 bytes.
static void prf(val_t out, uint32_t type, uint32_t lay, uint32_t tau, uint32_t p, uint32_t j) {
    uint32_t blk[16];
    block_head(blk, type, lay, tau, p, j);
    memcpy(blk + 8, K_->master, 32);
    th_oneblock(out, blk, 64);
}

// Th(P, tw, left || right): a Merkle node, 64 bytes.
static void node(val_t out, uint32_t type, uint32_t lay, uint32_t tau, uint32_t level, uint32_t j,
                 const val_t left, const val_t right) {
    uint32_t blk[16];
    block_head(blk, type, lay, tau, level, j);
    copy4(blk + 8, left);
    copy4(blk + 12, right);
    th_oneblock(out, blk, 64);
}

// ---------------------------------------------------------------------------
// WOTS+C

// Chain i of key (lay, tau, e): walk `steps` steps from position `start`; the
// step onto position s uses p = 8i + s - 1. 48 bytes each, one compression.
static void chain(val_t v, uint32_t lay, uint32_t tau, uint32_t e, uint32_t i, uint32_t start, uint32_t steps) {
    uint32_t blk[16];
    block_head(blk, TW_CHAIN, lay, tau, 0, e);
    blk[12] = blk[13] = blk[14] = blk[15] = 0;
    for (uint32_t s = 1; s <= steps; s++) {
        blk[1] = SPX_CHAIN_LEN * i + start + s - 1;
        copy4(blk + 8, v);
        th_oneblock(v, blk, 48);
    }
}

// The Merkle leaf of a WOTS key: its 42 chain tips hashed in order (704 bytes,
// 11 compressions), streamed as the tips are produced.
static void ots_public_leaf(val_t out, uint32_t lay, uint32_t tau, uint32_t e) {
    hctx_t c;
    uint32_t  head[8];
    uint32_t  d[8];
    val_t     v;

    h_init(&c);
    tweak(head, TW_LEAF, lay, tau, 0, e);
    copy4(head + 4, K_->pp);
    h_update_words(&c, head, 8);
    for (uint32_t i = 0; i < SPX_V; i++) {
        prf(v, TW_PRF, lay, tau, i, e);
        chain(v, lay, tau, e, i, 0, SPX_CHAIN_LEN - 1);
        h_update_words(&c, v, 4);
    }
    h_final(&c, d);
    copy4(out, d);
}

// Sum of ten 3-bit fields at bits 0..29.
static inline uint32_t sum10(uint32_t x) {
    const uint32_t m = 0x071C71C7u;  // fields 0, 2, 4, 6, 8
    uint32_t       y = (x & m) + ((x >> 3) & m);
    return (y & 63) + ((y >> 6) & 63) + ((y >> 12) & 63) + ((y >> 18) & 63) + ((y >> 24) & 63);
}

// The codeword of an encoding digest, or false: each 64-bit half holds 21
// 3-bit positions and a zero top bit, and the 42 positions sum to T.
static bool codeword(uint8_t x[SPX_V], const uint32_t d[4]) {
    if ((d[1] | d[3]) >> 31) {
        return false;
    }
    uint32_t sum = 0;
    for (unsigned q = 0; q < 2; q++) {
        uint32_t lo = d[2 * q], hi = d[2 * q + 1];
        // Positions 0..9 in lo, position 10 straddles the words, 11..20 in hi.
        sum += sum10(lo) + ((lo >> 30) | ((hi & 1) << 2)) + sum10(hi >> 1);
    }
    if (sum != SPX_T) {
        return false;
    }
    for (unsigned q = 0; q < 2; q++) {
        uint64_t half = (uint64_t) d[2 * q] | ((uint64_t) d[2 * q + 1] << 32);
        for (unsigned r = 0; r < SPX_V / 2; r++) {
            x[q * (SPX_V / 2) + r] = (uint8_t) ((half >> (3 * r)) & 7);
        }
    }
    return true;
}

// Ots.sign: the least admissible counter for m, then each chain opened at its
// position. Writes LE32(c) || 42 chain values to out; returns c.
static uint32_t ots_sign(uint8_t *out, uint32_t lay, uint32_t tau, uint32_t e, const val_t m) {
    uint32_t blk[16];
    uint32_t d[4];
    uint8_t  x[SPX_V];
    uint32_t c;
    val_t    v;

    // Enc input: tw || P || M || LE32(c), 52 bytes.
    block_head(blk, TW_ENC, lay, tau, 0, e);
    copy4(blk + 8, m);
    blk[13] = blk[14] = blk[15] = 0;
    for (c = 0;; c++) {
        blk[12] = c;
        th_oneblock(d, blk, 52);
        if (codeword(x, d)) {
            break;
        }
    }
    memcpy(out, &c, 4);
    for (uint32_t i = 0; i < SPX_V; i++) {
        prf(v, TW_PRF, lay, tau, i, e);
        chain(v, lay, tau, e, i, 0, x[i]);
        memcpy(out + 4 + 16 * i, v, 16);
    }
    return c;
}

// ---------------------------------------------------------------------------
// Streaming treehash over leaves [first, first + 2^height), node j at level z
// hashed under tweak(node_type, lay, tau, z, j) with global indices. Captures
// the siblings of leaf `target` (levels < height) and, optionally, every node
// of level cap_level.

typedef void (*leaf_fn_t)(val_t out, uint32_t leaf, const void *arg);

typedef struct {
    uint32_t node_type, lay, tau;
    uint32_t target;  // 0xFFFFFFFF: no path
    val_t   *path;
    uint32_t cap_level;
    val_t   *cap;  // NULL: no capture
} tree_opts_t;

static inline void capture(const tree_opts_t *o, uint32_t height, uint32_t first, uint32_t z, uint32_t j, const val_t v) {
    if (o->path != NULL && z < height && ((o->target >> z) ^ 1) == j) {
        copy4(o->path[z], v);
    }
    if (o->cap != NULL && z == o->cap_level) {
        copy4(o->cap[j - (first >> z)], v);
    }
}

static void treehash(val_t root, uint32_t first, uint32_t height, leaf_fn_t leaf_fn, const void *arg,
                     const tree_opts_t *o) {
    val_t    stack[SPX_H0 + 1];
    uint8_t  heights[SPX_H0 + 1];
    unsigned sp = 0;

    for (uint32_t i = 0; i < (1u << height); i++) {
        uint32_t leaf = first + i;
        uint32_t z = 0;
        val_t    v;
        leaf_fn(v, leaf, arg);
        capture(o, height, first, 0, leaf, v);
        while (sp > 0 && heights[sp - 1] == z) {
            sp--;
            z++;
            uint32_t j = leaf >> z;
            node(v, o->node_type, o->lay, o->tau, z, j, stack[sp], v);
            capture(o, height, first, z, j, v);
        }
        copy4(stack[sp], v);
        heights[sp] = (uint8_t) z;
        sp++;
    }
    copy4(root, stack[0]);
}

typedef struct {
    uint32_t lay, tau;
} ots_tree_t;

static void ots_leaf_fn(val_t out, uint32_t e, const void *arg) {
    const ots_tree_t *t = arg;
    ots_public_leaf(out, t->lay, t->tau, e);
}

typedef struct {
    uint32_t kappa, idx, opened;
    uint32_t *secret;  // the opened leaf's secret
} fts_tree_t;

static void fts_leaf_fn(val_t out, uint32_t j, const void *arg) {
    const fts_tree_t *t = arg;
    uint32_t          blk[16];
    val_t             s;
    prf(s, TW_FTS_PRF, t->kappa, t->idx, 0, j);
    if (j == t->opened) {
        copy4(t->secret, s);
    }
    block_head(blk, TW_FTS_LEAF, t->kappa, t->idx, 0, j);
    copy4(blk + 8, s);
    blk[12] = blk[13] = blk[14] = blk[15] = 0;
    th_oneblock(out, blk, 48);
}

// Layer 0's path at e and its root, from the cache: rebuild the 2^6-leaf
// subtree holding e, then refold the 64 cached nodes above it.
static void cached_path_and_root(val_t root, uint32_t e, val_t path[SPX_H0]) {
    const ots_tree_t  t = {0, 0};
    const tree_opts_t o = {TW_NODE, 0, 0, e, path, 0, NULL};
    val_t             nodes[SPX_CACHE_LEN];
    val_t             sub_root;

    treehash(sub_root, (e >> SPX_SPLIT) << SPX_SPLIT, SPX_SPLIT, ots_leaf_fn, &t, &o);
    memcpy(nodes, K_->cache, sizeof(nodes));
    for (uint32_t level = SPX_SPLIT; level < SPX_H0; level++) {
        // nodes holds this level whole (global indices), so e's sibling is direct.
        copy4(path[level], nodes[(e >> level) ^ 1]);
        uint32_t count = 1u << (SPX_H0 - level);
        for (uint32_t j = 0; j < count / 2; j++) {
            node(nodes[j], TW_NODE, 0, 0, level + 1, j, nodes[2 * j], nodes[2 * j + 1]);
        }
    }
    copy4(root, nodes[0]);
}

// ---------------------------------------------------------------------------

void spx_keygen(spx_key_t *key, const uint8_t seed[32]) {
    uint32_t blk[16];

    memcpy(key->master, seed, 32);
    // P = Th(0^128, tw_parameter, S).
    tweak(blk, TW_PARAMETER, 0, 0, 0, 0);
    blk[4] = blk[5] = blk[6] = blk[7] = 0;
    memcpy(blk + 8, key->master, 32);
    th_oneblock(key->pp, blk, 64);

    K_ = key;
    const ots_tree_t  t = {0, 0};
    const tree_opts_t o = {TW_NODE, 0, 0, 0xFFFFFFFFu, NULL, SPX_SPLIT, key->cache};
    treehash(key->root, 0, SPX_H0, ots_leaf_fn, &t, &o);
}

// Bits [off, off + len) of a little-endian digest, len <= 32.
static uint32_t digest_bits(const uint32_t d[8], uint32_t off, uint32_t len) {
    uint32_t w = off / 32, s = off % 32;
    uint64_t two = (uint64_t) d[w] | ((w + 1 < 8 ? (uint64_t) d[w + 1] : 0) << 32);
    return (uint32_t) ((two >> s) & ((1ull << len) - 1));
}

bool spx_sign(const spx_key_t *key, const uint8_t msg[32], uint8_t *sig, spx_sign_stats_t *stats) {
    uint32_t  m[8];
    uint32_t  head[8];
    uint32_t  dig[8];
    val_t     rho;
    uint32_t  idx, u[SPX_K];
    hctx_t c;

    K_ = key;
    memcpy(m, msg, 32);

    // 1. Randomizers rho_a = Th(P, tw_rnd(a), S || m) until the digest's last
    //    index is zero. Both inputs are 96 bytes (two compressions).
    for (uint32_t trial = 0;; trial++) {
        h_init(&c);
        tweak(head, TW_RANDOMIZER, 0, 0, trial, 0);
        copy4(head + 4, key->pp);
        h_update_words(&c, head, 8);
        h_update_words(&c, key->master, 8);
        h_update_words(&c, m, 8);
        h_final(&c, dig);
        copy4(rho, dig);

        h_init(&c);
        tweak(head, TW_MSG, 0, 0, 0, 0);
        copy4(head + 4, key->pp);
        h_update_words(&c, head, 8);
        h_update_words(&c, rho, 4);
        h_update_words(&c, key->root, 4);
        h_update_words(&c, m, 8);
        h_final(&c, dig);
        if (digest_bits(dig, SPX_H + (SPX_K - 1) * SPX_A, SPX_A) == 0) {
            stats->digest_trials = trial + 1;
            break;
        }
    }
    idx = digest_bits(dig, 0, SPX_H);
    for (uint32_t k = 0; k < SPX_K; k++) {
        u[k] = digest_bits(dig, SPX_H + k * SPX_A, SPX_A);
    }
    memcpy(sig, rho, 16);

    // 2. FORS: open the 14 trees at u, and the key over their roots.
    val_t message;
    {
        uint8_t *out = sig + 16;
        h_init(&c);
        tweak(head, TW_FTS_ROOTS, 0, idx, 0, 0);
        copy4(head + 4, key->pp);
        h_update_words(&c, head, 8);
        for (uint32_t kappa = 0; kappa < SPX_FTS_TREES; kappa++) {
            val_t             secret, root, path[SPX_A];
            const fts_tree_t  t = {kappa, idx, u[kappa], secret};
            const tree_opts_t o = {TW_FTS_NODE, kappa, idx, u[kappa], path, 0, NULL};
            treehash(root, 0, SPX_A, fts_leaf_fn, &t, &o);
            memcpy(out, secret, 16);
            memcpy(out + 16, path, sizeof(path));
            out += FTS_OPENING_BYTES;
            h_update_words(&c, root, 4);
        }
        h_final(&c, dig);
        copy4(message, dig);
    }

    // 3. Layers 2, 1, 0: each WOTS key signs the value below it; its tree's
    //    root is what the next layer up signs.
    uint32_t offset[SPX_D];
    offset[0] = LAYER0_OFFSET;
    offset[1] = offset[0] + LAYER_OTS_BYTES + 16 * SPX_H0;
    offset[2] = offset[1] + LAYER_OTS_BYTES + 16 * SPX_H1;
    for (int lay = SPX_D - 1; lay >= 0; lay--) {
        uint32_t below = 0;
        for (int j = lay + 1; j < SPX_D; j++) {
            below += HEIGHTS[j];
        }
        uint32_t tau = (idx >> below) >> HEIGHTS[lay];
        uint32_t e = (idx >> below) & ((1u << HEIGHTS[lay]) - 1);
        uint8_t *out = sig + offset[lay];
        val_t    path[SPX_H0];

        stats->counters[lay] = ots_sign(out, lay, tau, e, message);
        if (lay == 0) {
            cached_path_and_root(message, e, path);
        } else {
            const ots_tree_t  t = {(uint32_t) lay, tau};
            const tree_opts_t o = {TW_NODE, (uint32_t) lay, tau, e, path, 0, NULL};
            treehash(message, 0, HEIGHTS[lay], ots_leaf_fn, &t, &o);
        }
        memcpy(out + LAYER_OTS_BYTES, path, 16 * HEIGHTS[lay]);
    }
    return memcmp(message, key->root, 16) == 0;
}
