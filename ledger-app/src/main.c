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
#include "crypto/sphincs.h"

#define CLA 0xE0

enum {
    INS_INFO    = 0x01,
    INS_KEYGEN  = 0x02,
    INS_SIGN    = 0x03,
    INS_GET_SIG = 0x04,
    INS_BENCH   = 0x05,
    INS_NOP     = 0x06,
    INS_HASH    = 0x07,
    INS_CONFIG  = 0x08,
};

#define SW_OK              0x9000
#define SW_WRONG_LENGTH    0x6700
#define SW_NO_KEY          0x6985
#define SW_WRONG_P1P2      0x6A86
#define SW_INS_UNSUPPORTED 0x6D00
#define SW_CLA_UNSUPPORTED 0x6E00
#define SW_SIGN_MISMATCH   0x6F02

#define SIG_CHUNK 240

static spx_key_t G_key;
static bool      G_have_key;
static uint8_t   G_sig[SPX_SIG_BYTES];
static uint8_t   G_yield;

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
            out[3] = IMPL_COUNT;
            out[4] = g_impl;
            out[5] = G_have_key;
            out[6] = G_yield;
            memcpy(out + 7, opt, sizeof(opt));
            io_send_response_pointer(out, 7 + sizeof(opt), SW_OK);
            return;
        }

        case INS_NOP:
            io_send_sw(SW_OK);
            return;

        case INS_CONFIG:
            // P1: 1 to service the event loop during long computations, 0 not to.
            if (cmd->p1 > 1) {
                io_send_sw(SW_WRONG_P1P2);
                return;
            }
            G_yield = cmd->p1;
            io_send_sw(SW_OK);
            return;

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

    // Every command below runs on the BLAKE2s implementation named by P1.
    if (cmd->p1 >= IMPL_COUNT) {
        io_send_sw(SW_WRONG_P1P2);
        return;
    }
    g_impl = cmd->p1;
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
            // P2 = 1: count bare compressions.
            // P2 = 2: count WOTS public leaves (337 hashes, 347 compressions each).
            if (cmd->lc != 4) {
                io_send_sw(SW_WRONG_LENGTH);
                return;
            }
            uint32_t count = get_be32(cmd->data);
            val_t    v = {0};
            if (cmd->p2 == 0) {
                spx_bench_chain(&G_key, count, v);
            } else if (cmd->p2 == 1) {
                uint32_t h[8] = {0};
                uint32_t m[16] = {0};
                for (uint32_t i = 0; i < count; i++) {
                    b2s_compress(h, m, 64, 0xFFFFFFFFu);
                    if ((i & 1023) == 1023) {
                        spx_yield();
                    }
                }
                memcpy(v, h, 16);
            } else if (cmd->p2 == 2) {
                spx_bench_ots_leaf(&G_key, count, v);
            } else {
                io_send_sw(SW_WRONG_P1P2);
                return;
            }
            memcpy(out, v, 16);
            put_be32(out + 16, g_hash_calls);
            put_be32(out + 20, g_compressions);
            io_send_response_pointer(out, 24, SW_OK);
            return;
        }

        case INS_HASH: {
            // BLAKE2s-256(data), to cross-check implementations against the host.
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
    G_yield = 1;
    g_impl = IMPL_UNROLLED;

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
