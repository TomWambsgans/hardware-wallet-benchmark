// PQ Bench: leanVM's SPHINCS+ variant (keygen with the layer-0 cache, sign) on a
// Ledger Nano S Plus, with H = BLAKE2s-256 or the raw SHA-256 compression.
//
// A research app for a test device: there is no on-screen confirmation, the key is
// kept unencrypted in the app's flash, and the screen freezes during computations.
//
// APDUs (CLA 0xE0; P1 = hash: 0 BLAKE2s, 1 SHA-256; counters are big-endian u32):
//   01 INFO     -> version (3 bytes), have_key[2]
//   02 KEYGEN   data: 32-byte seed (or empty: seed from the TRNG)
//               -> P (16) || root (16) || compressions; the key is stored in flash
//   03 SIGN     data: 32-byte message -> compressions || randomizer trials || 3 counters;
//               the 4924-byte signature is kept in RAM
//   04 GET_SIG  P1 = chunk i -> signature bytes [240 i, 240 i + 240)
//   05 BENCH    data: count (u32) -> runs count compressions (timed by the host)
//   06 NOP      (USB round-trip baseline)

#include <stdint.h>
#include <string.h>

#include "os.h"
#include "cx.h"
#include "io.h"
#include "parser.h"
#include "nbgl_use_case.h"
#include "glyphs.h"

#include "crypto/blake2s.h"
#include "crypto/hash.h"
#include "crypto/sha256.h"
#include "crypto/sphincs.h"

#define CLA 0xE0

enum { INS_INFO = 0x01, INS_KEYGEN = 0x02, INS_SIGN = 0x03, INS_GET_SIG = 0x04, INS_BENCH = 0x05, INS_NOP = 0x06 };

#define SW_OK              0x9000
#define SW_WRONG_LENGTH    0x6700
#define SW_NO_KEY          0x6985
#define SW_WRONG_P1P2      0x6A86
#define SW_INS_UNSUPPORTED 0x6D00
#define SW_CLA_UNSUPPORTED 0x6E00
#define SW_SIGN_MISMATCH   0x6F02

#define SIG_CHUNK 240

// One key per hash (P, S, root and the 1 KB layer-0 cache), persisted in flash.
typedef struct {
    spx_key_t key;
    uint8_t   valid;
} stored_key_t;

const stored_key_t N_keys_real[HASH_COUNT];
#define N_keys ((volatile stored_key_t *) PIC(N_keys_real))

static spx_key_t G_key[HASH_COUNT];
static bool      G_have_key[HASH_COUNT];
static uint8_t   G_sig[SPX_SIG_BYTES];

static void app_quit(void) {
    os_sched_exit(-1);
}

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t) (v >> 24);
    p[1] = (uint8_t) (v >> 16);
    p[2] = (uint8_t) (v >> 8);
    p[3] = (uint8_t) v;
}

static void handle(const command_t *cmd) {
    uint8_t out[40];

    if (cmd->cla != CLA) {
        io_send_sw(SW_CLA_UNSUPPORTED);
        return;
    }
    switch (cmd->ins) {
        case INS_INFO:
            out[0] = MAJOR_VERSION;
            out[1] = MINOR_VERSION;
            out[2] = PATCH_VERSION;
            out[3] = G_have_key[HASH_BLAKE2S];
            out[4] = G_have_key[HASH_SHA256];
            io_send_response_pointer(out, 5, SW_OK);
            return;

        case INS_NOP:
            io_send_sw(SW_OK);
            return;

        case INS_GET_SIG: {
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

    if (cmd->p1 >= HASH_COUNT) {
        io_send_sw(SW_WRONG_P1P2);
        return;
    }
    hash_id_t hash = (hash_id_t) cmd->p1;
    g_hash = hash;
    g_compressions = 0;

    switch (cmd->ins) {
        case INS_KEYGEN: {
            uint8_t seed[32];
            if (cmd->lc == 0) {
                cx_rng_no_throw(seed, sizeof(seed));
            } else if (cmd->lc == sizeof(seed)) {
                memcpy(seed, cmd->data, sizeof(seed));
            } else {
                io_send_sw(SW_WRONG_LENGTH);
                return;
            }
            spx_keygen(&G_key[hash], seed);
            explicit_bzero(seed, sizeof(seed));
            G_have_key[hash] = true;
            // Persist: invalidate, write the key, mark it valid.
            uint8_t flag = 0;
            nvm_write((void *) &N_keys[hash].valid, &flag, 1);
            nvm_write((void *) &N_keys[hash].key, &G_key[hash], sizeof(spx_key_t));
            flag = 1;
            nvm_write((void *) &N_keys[hash].valid, &flag, 1);
            memcpy(out, G_key[hash].pp, 16);
            memcpy(out + 16, G_key[hash].root, 16);
            put_be32(out + 32, g_compressions);
            io_send_response_pointer(out, 36, SW_OK);
            return;
        }

        case INS_SIGN: {
            if (!G_have_key[hash]) {
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
            bool ok = spx_sign(&G_key[hash], msg, G_sig, &stats);
            put_be32(out, g_compressions);
            put_be32(out + 4, stats.digest_trials);
            for (unsigned lay = 0; lay < SPX_D; lay++) {
                put_be32(out + 8 + 4 * lay, stats.counters[lay]);
            }
            io_send_response_pointer(out, 8 + 4 * SPX_D, ok ? SW_OK : SW_SIGN_MISMATCH);
            return;
        }

        case INS_BENCH: {
            if (cmd->lc != 4) {
                io_send_sw(SW_WRONG_LENGTH);
                return;
            }
            uint32_t count = ((uint32_t) cmd->data[0] << 24) | ((uint32_t) cmd->data[1] << 16)
                             | ((uint32_t) cmd->data[2] << 8) | cmd->data[3];
            uint32_t h[8] = {0}, m[16] = {0};
            for (uint32_t i = 0; i < count; i++) {
                if (hash == HASH_SHA256) {
                    sha256_compress(h, m);
                } else {
                    blake2s_compress(h, m, 64, 0xFFFFFFFFu);
                }
            }
            io_send_response_pointer((const uint8_t *) h, 16, SW_OK);
            return;
        }

        default:
            io_send_sw(SW_INS_UNSUPPORTED);
            return;
    }
}

void app_main(void) {
    command_t cmd;

    hash_setup();
    for (unsigned i = 0; i < HASH_COUNT; i++) {
        if (N_keys[i].valid == 1) {
            memcpy(&G_key[i], (const void *) &N_keys[i].key, sizeof(spx_key_t));
            G_have_key[i] = true;
        }
    }

    io_init();
    nbgl_useCaseHomeAndSettings(
        APPNAME, &C_home_pqbench_14px, "SPHINCS+ bench", INIT_HOME_PAGE, NULL, NULL, NULL, app_quit);

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
