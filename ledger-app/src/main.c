// PQ Bench: keygen / sign / microbenchmarks for leanVM's SPHINCS+ variant
// (BLAKE2s, WOTS+C, FORS+C) on a Ledger device. No on-screen confirmation:
// this is a research app for a device holding no funds. See doc/PROTOCOL.md.

#include <stdint.h>
#include <string.h>

#include "os.h"
#include "cx.h"
#include "io.h"
#include "parser.h"
#include "nbgl_use_case.h"
#include "glyphs.h"

#include "crypto/blake2s.h"
#include "crypto/sha256.h"
#include "crypto/sphincs.h"
#include "probes.h"
#include "sha256_os.h"

#define CLA 0xE0

enum {
    INS_INFO    = 0x01,
    INS_KEYGEN  = 0x02,
    INS_SIGN    = 0x03,
    INS_GET_SIG = 0x04,
    INS_BENCH   = 0x05,
    INS_NOP     = 0x06,
    INS_HASH     = 0x07,
    INS_CONFIG   = 0x08,
    INS_COMPRESS = 0x09,
};

// INS_COMPRESS / INS_BENCH compression functions.
enum {
    FN_B2S_C       = 0,
    FN_B2S_ASM     = 1,
    FN_B2S_ASM2    = 2,
    FN_B2S_ASM3    = 3,
    FN_B2S_ASM3R   = 4,
    FN_B2S_ASM4R   = 5,
    FN_SHA256_C    = 6,
    FN_SHA256_ASM  = 7,
    FN_SHA256_ASM2 = 8,
    FN_SHA256_ASM3 = 9,
    FN_SHA256_ASM3R = 10,
    FN_SHA256_OS   = 11,
    FN_COUNT
};

static void compress_fn(unsigned fn, uint32_t h[8], const uint32_t m[16], uint32_t t, uint32_t f) {
    switch (fn) {
        case FN_B2S_C:
            b2s_compress_c(h, m, t, f);
            break;
        case FN_B2S_ASM:
            b2s_compress_asm(h, m, t, f);
            break;
        case FN_B2S_ASM2:
            b2s_compress_asm2(h, m, t, f);
            break;
        case FN_B2S_ASM3:
            b2s_compress_asm3(h, m, t, f);
            break;
        case FN_B2S_ASM3R:
            b2s_compress_asm3r(h, m, t, f);
            break;
        case FN_B2S_ASM4R:
            b2s_compress_asm4r(h, m, t, f);
            break;
        case FN_SHA256_C:
            sha256_compress_c(h, m);
            break;
        case FN_SHA256_ASM:
            sha256_compress_asm(h, m);
            break;
        case FN_SHA256_ASM2:
            sha256_compress_asm2(h, m);
            break;
        case FN_SHA256_ASM3:
            sha256_compress_asm3(h, m);
            break;
        case FN_SHA256_ASM3R:
            sha256_compress_asm3r(h, m);
            break;
        default:
            sha256_compress_os(h, m);
            break;
    }
}

static uint32_t G_probe_buf[512];

#define SW_OK              0x9000
#define SW_WRONG_LENGTH    0x6700
#define SW_NO_KEY          0x6985
#define SW_WRONG_P1P2      0x6A86
#define SW_INS_UNSUPPORTED 0x6D00
#define SW_CLA_UNSUPPORTED 0x6E00
#define SW_SIGN_MISMATCH   0x6F02

#define SIG_CHUNK 240

// The key persists in the app's NVM (flash): P, S, root and the 1 KB cache.
// SECRET KEY MATERIAL, unencrypted: this is a research app on a test device.
typedef struct {
    spx_key_t key;
    uint8_t   valid;
} stored_key_t;

const stored_key_t N_stored_key_real;
#define N_stored_key (*(volatile stored_key_t *) PIC(&N_stored_key_real))

static spx_key_t G_key;
static bool      G_have_key;
static uint8_t   G_sig[SPX_SIG_BYTES];
static uint8_t   G_yield;

// Off by default: io_seproxyhal_io_heartbeat() waits for the next event (the
// 100 ms ticker when idle), so calling it per WOTS leaf multiplied leaf time by
// ~6.6. Long computations (a 1-minute keygen) complete fine without it.
void spx_yield(void) {
    if (G_yield) {
        io_seproxyhal_io_heartbeat();
    }
}

static void app_quit(void) {
    os_sched_exit(-1);
}

static void ui_home(void) {
    nbgl_useCaseHomeAndSettings(
        APPNAME, &C_home_pqbench_14px, "SPHINCS+ bench", INIT_HOME_PAGE, NULL, NULL, NULL, app_quit);
}

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t) (v >> 24);
    p[1] = (uint8_t) (v >> 16);
    p[2] = (uint8_t) (v >> 8);
    p[3] = (uint8_t) v;
}

static uint32_t get_be32(const uint8_t *p) {
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | p[3];
}

static void handle(const command_t *cmd) {
    uint8_t out[64];

    if (cmd->cla != CLA) {
        io_send_sw(SW_CLA_UNSUPPORTED);
        return;
    }
    switch (cmd->ins) {
        case INS_INFO: {
            static const char opt[] = CRYPTO_OPT_LEVEL;
            out[0] = MAJOR_VERSION;
            out[1] = MINOR_VERSION;
            out[2] = PATCH_VERSION;
            out[3] = G_have_key;
            out[4] = G_yield;
            out[5] = g_b2s_impl;
            memcpy(out + 6, opt, sizeof(opt));
            io_send_response_pointer(out, 6 + sizeof(opt), SW_OK);
            return;
        }

        case INS_NOP:
            io_send_sw(SW_OK);
            return;

        case INS_CONFIG:
            // P1: 1 to service the event loop during long computations, 0 not to.
            // P2: the BLAKE2s compression the scheme uses (B2S_*).
            if (cmd->p1 > 1 || cmd->p2 >= B2S_IMPLS) {
                io_send_sw(SW_WRONG_P1P2);
                return;
            }
            G_yield = cmd->p1;
            g_b2s_impl = cmd->p2;
            io_send_sw(SW_OK);
            return;

        case INS_COMPRESS: {
            // P1: FN_*. Data: h (8 LE words) || m (16 LE words) [|| t || f, LE, BLAKE2s].
            // Returns h after one compression, to check each function on the device.
            uint32_t h[8], m[16], tf[2] = {0, 0};
            bool     b2s = cmd->p1 <= FN_B2S_ASM4R;
            if (cmd->p1 >= FN_COUNT) {
                io_send_sw(SW_WRONG_P1P2);
                return;
            }
            if (cmd->lc != (b2s ? 104 : 96)) {
                io_send_sw(SW_WRONG_LENGTH);
                return;
            }
            memcpy(h, cmd->data, 32);
            memcpy(m, cmd->data + 32, 64);
            if (b2s) {
                memcpy(tf, cmd->data + 96, 8);
            }
            compress_fn(cmd->p1, h, m, tf[0], tf[1]);
            io_send_response_pointer((const uint8_t *) h, 32, SW_OK);
            return;
        }

        case INS_GET_SIG: {
            // P1: chunk index; chunks of SIG_CHUNK bytes, the last one shorter.
            uint32_t off = (uint32_t) cmd->p1 * SIG_CHUNK;
            if (off >= SPX_SIG_BYTES) {
                io_send_sw(SW_WRONG_P1P2);
                return;
            }
            uint32_t len = SPX_SIG_BYTES - off;
            io_send_response_pointer(G_sig + off, len > SIG_CHUNK ? SIG_CHUNK : len, SW_OK);
            return;
        }

        default:
            break;
    }

    g_hash_calls = 0;
    g_compressions = 0;

    switch (cmd->ins) {
        case INS_KEYGEN: {
            // Data: empty (a fresh seed from the TRNG) or a 32-byte master seed.
            uint8_t seed[32];
            if (cmd->lc == 0) {
                cx_rng_no_throw(seed, sizeof(seed));
            } else if (cmd->lc == sizeof(seed)) {
                memcpy(seed, cmd->data, sizeof(seed));
            } else {
                io_send_sw(SW_WRONG_LENGTH);
                return;
            }
            spx_keygen(&G_key, seed);
            explicit_bzero(seed, sizeof(seed));
            G_have_key = true;
            // Persist: invalidate, write the key, then mark it valid.
            uint8_t flag = 0;
            nvm_write((void *) &N_stored_key.valid, &flag, 1);
            nvm_write((void *) &N_stored_key.key, &G_key, sizeof(G_key));
            flag = 1;
            nvm_write((void *) &N_stored_key.valid, &flag, 1);
            memcpy(out, G_key.pp, 16);
            memcpy(out + 16, G_key.root, 16);
            put_be32(out + 32, g_hash_calls);
            put_be32(out + 36, g_compressions);
            io_send_response_pointer(out, 40, SW_OK);
            return;
        }

        case INS_SIGN: {
            if (!G_have_key) {
                io_send_sw(SW_NO_KEY);
                return;
            }
            if (cmd->lc != 32) {
                io_send_sw(SW_WRONG_LENGTH);
                return;
            }
            uint8_t          msg[32];
            spx_sign_stats_t stats;
            memcpy(msg, cmd->data, sizeof(msg));
            bool ok = spx_sign(&G_key, msg, G_sig, &stats);
            put_be32(out, g_hash_calls);
            put_be32(out + 4, g_compressions);
            put_be32(out + 8, stats.digest_trials);
            for (unsigned lay = 0; lay < SPX_D; lay++) {
                put_be32(out + 12 + 4 * lay, stats.counters[lay]);
            }
            io_send_response_pointer(out, 12 + 4 * SPX_D, ok ? SW_OK : SW_SIGN_MISMATCH);
            return;
        }

        case INS_BENCH: {
            // P2 = 0: count chain steps (a 48-byte Th, one compression each).
            // P2 = 1: count compressions of function P1 (FN_*).
            // P2 = 2: count WOTS public leaves (337 hashes, 347 compressions each).
            // P2 = 3: count iterations of timing probe P1 (probes.c).
            if (cmd->lc != 4) {
                io_send_sw(SW_WRONG_LENGTH);
                return;
            }
            uint32_t count = get_be32(cmd->data);
            val_t    v = {0};
            uint32_t h[8] = {0};
            uint32_t m[16] = {0};
            if (cmd->p2 == 0) {
                spx_bench_chain(&G_key, count, v);
            } else if (cmd->p2 == 1 && cmd->p1 < FN_COUNT) {
                for (uint32_t i = 0; i < count; i++) {
                    compress_fn(cmd->p1, h, m, 64, 0xFFFFFFFFu);
                }
            } else if (cmd->p2 == 2) {
                spx_bench_ots_leaf(&G_key, count, v);
            } else if (cmd->p2 == 3 && cmd->p1 < PROBE_COUNT) {
                run_probe(cmd->p1, count, G_probe_buf);
            } else {
                io_send_sw(SW_WRONG_P1P2);
                return;
            }
            if (cmd->p2 != 0 && cmd->p2 != 2) {
                memcpy(v, h, 16);
            }
            memcpy(out, v, 16);
            put_be32(out + 16, g_hash_calls);
            put_be32(out + 20, g_compressions);
            io_send_response_pointer(out, 24, SW_OK);
            return;
        }

        case INS_HASH: {
            // BLAKE2s-256(data), to cross-check against the host.
            uint32_t d[8];
            b2s_hash_bytes(d, cmd->data, cmd->lc);
            io_send_response_pointer((const uint8_t *) d, 32, SW_OK);
            return;
        }

        default:
            io_send_sw(SW_INS_UNSUPPORTED);
            return;
    }
}

void app_main(void) {
    command_t cmd;

    // RAM starts zeroed and initialized globals are not allowed (no .data).
    G_yield = 0;
    g_b2s_impl = B2S_C;
    crypto_tables_init();
    if (N_stored_key.valid == 1) {
        memcpy(&G_key, (const void *) &N_stored_key.key, sizeof(G_key));
        G_have_key = true;
    }

    io_init();
    ui_home();

    for (;;) {
        int input_len = io_recv_command();
        if (input_len < 0) {
            return;
        }
        if (!apdu_parser(&cmd, G_io_apdu_buffer, input_len)) {
            io_send_sw(SW_WRONG_LENGTH);
            continue;
        }
        handle(&cmd);
    }
}
