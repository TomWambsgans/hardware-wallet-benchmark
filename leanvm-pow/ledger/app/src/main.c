// leanVM Verify: verify a leanVM proof on a Ledger Nano S Plus. The verifier is leanVM's, ported to run in the
// device's 40 KB of RAM (leanvm-pow/ledger/verifier, linked as a Rust static library); the proof is streamed
// over USB as the verifier reads it, and the program it is about (the bytecode) is compiled in.
//
// A research app for a test device: no on-screen confirmation, and the screen freezes during a verification.
//
// APDUs (CLA 0xE0; integers big-endian):
//   01 INFO     -> version (3 bytes)
//   10 VERIFY   P1 = 0: verify; 1: only receive the stream (the USB baseline)
//               data: the 32-byte public input || the stream's length (u32)
//               -> 01 (MORE): the device wants the next chunk; send it with 11 DATA
//               -> 00 (DONE) || result (u8: 0 accepted, else leanVM's error code) || bytes read (u32)
//                  || chunks received (u32) || peak stack (u32, bytes)
//   11 DATA     data: the next bytes of the stream (at most 255); answered as VERIFY is

#include <stdint.h>
#include <string.h>

#include "os.h"
#include "io.h"
#include "parser.h"
#include "nbgl_use_case.h"
#include "glyphs.h"

#include "keccak.h"

#define CLA 0xE0

enum {
    INS_INFO = 0x01,
    INS_VERIFY = 0x10,
    INS_DATA = 0x11,
};

#define SW_OK              0x9000
#define SW_WRONG_LENGTH    0x6700
#define SW_BAD_STATE       0x6985
#define SW_INS_UNSUPPORTED 0x6D00
#define SW_CLA_UNSUPPORTED 0x6E00

#define STATUS_DONE 0x00
#define STATUS_MORE 0x01

// The Rust verifier (leanvm-pow/ledger/ffi).
uint32_t leanvm_verify(const uint8_t public_input[32]);

// The stream as the verifier reads it: the current DATA chunk, and where the stream stands.
static struct {
    uint8_t  chunk[255];
    uint32_t chunk_len, chunk_at;
    uint32_t total, read, chunks;
    bool     failed;
} G_stream;

static void app_quit(void) {
    os_sched_exit(-1);
}

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t) (v >> 24);
    p[1] = (uint8_t) (v >> 16);
    p[2] = (uint8_t) (v >> 8);
    p[3] = (uint8_t) v;
}

static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | p[3];
}

// Answer the pending APDU with MORE, and take the next DATA chunk. False if the host sent anything else.
static bool next_chunk(void) {
    static const uint8_t more = STATUS_MORE;
    command_t            cmd;
    io_send_response_pointer(&more, 1, SW_OK);
    int input_len = io_recv_command();
    if (input_len < 0 || !apdu_parser(&cmd, G_io_apdu_buffer, input_len) || cmd.cla != CLA ||
        cmd.ins != INS_DATA || cmd.lc == 0) {
        return false;
    }
    memcpy(G_stream.chunk, cmd.data, cmd.lc);
    G_stream.chunk_len = cmd.lc;
    G_stream.chunk_at = 0;
    G_stream.chunks++;
    return true;
}

// The next `len` bytes of the proof stream (called by the verifier).
int32_t leanvm_read(uint8_t *out, uint32_t len) {
    if (G_stream.failed || len > G_stream.total - G_stream.read) {
        G_stream.failed = true;
        return 1;
    }
    while (len > 0) {
        if (G_stream.chunk_at == G_stream.chunk_len && !next_chunk()) {
            G_stream.failed = true;
            return 1;
        }
        uint32_t n = G_stream.chunk_len - G_stream.chunk_at;
        if (n > len) {
            n = len;
        }
        memcpy(out, G_stream.chunk + G_stream.chunk_at, n);
        G_stream.chunk_at += n;
        G_stream.read += n;
        out += n;
        len -= n;
    }
    return 0;
}

// The proof has been read whole: 0 if none of the stream is left.
int32_t leanvm_end(void) {
    return G_stream.read == G_stream.total && G_stream.chunk_at == G_stream.chunk_len ? 0 : 1;
}

// A Rust panic: a bug, never a rejection. Leave the app.
void leanvm_panic(void) {
    os_sched_exit(-1);
    for (;;) {
    }
}

// The stack's lowest address (SDK linker script), and a word painted below the caller's frame, to measure
// how deep a call goes.
extern uint32_t _stack;
#define STACK_PAINT 0xA5A5A5A5u

static uint32_t *paint_stack(void) {
    volatile uint32_t here;
    uint32_t         *top = (uint32_t *) &here - 64;  // leave this frame and its callees' first words alone
    for (uint32_t *p = &_stack + 4; p < top; p++) {   // past the SDK's canary
        *p = STACK_PAINT;
    }
    return top;
}

static uint32_t stack_used(const uint32_t *top) {
    const uint32_t *p = &_stack + 4;
    while (p < top && *p == STACK_PAINT) {
        p++;
    }
    return (uint32_t) ((const uint8_t *) top - (const uint8_t *) p);
}

static void verify(const command_t *cmd) {
    uint8_t out[14];
    if (cmd->lc != 36) {
        io_send_sw(SW_WRONG_LENGTH);
        return;
    }
    uint8_t public_input[32];
    memcpy(public_input, cmd->data, 32);
    memset(&G_stream, 0, sizeof(G_stream));
    G_stream.total = read_be32(cmd->data + 32);

    uint32_t *top = paint_stack();
    uint32_t  result;
    if (cmd->p1 == 1) {
        // The USB baseline: the same stream, read in the verifier's largest pieces, nothing computed.
        uint8_t sink[64];
        result = 0;
        while (G_stream.read < G_stream.total) {
            uint32_t n = G_stream.total - G_stream.read;
            if (leanvm_read(sink, n < sizeof(sink) ? n : sizeof(sink)) != 0) {
                result = 0xFF;
                break;
            }
        }
    } else {
        result = leanvm_verify(public_input);
    }
    uint32_t used = stack_used(top);
    if (G_stream.failed) {
        result = 0xFE;  // the transport broke: a DATA chunk was missing or the stream ran past its length
    }
    out[0] = STATUS_DONE;
    out[1] = (uint8_t) result;
    put_be32(out + 2, G_stream.read);
    put_be32(out + 6, G_stream.chunks);
    put_be32(out + 10, used);
    io_send_response_pointer(out, 14, SW_OK);
}

static void handle(const command_t *cmd) {
    if (cmd->cla != CLA) {
        io_send_sw(SW_CLA_UNSUPPORTED);
        return;
    }
    switch (cmd->ins) {
        case INS_INFO: {
            uint8_t out[3] = {MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION};
            io_send_response_pointer(out, 3, SW_OK);
            return;
        }
        case INS_VERIFY:
            verify(cmd);
            return;
        case INS_DATA:
            io_send_sw(SW_BAD_STATE);  // a chunk outside a verification
            return;
        default:
            io_send_sw(SW_INS_UNSUPPORTED);
            return;
    }
}

void app_main(void) {
    command_t cmd;

    keccak_setup();
    io_init();
    nbgl_useCaseHomeAndSettings(
        APPNAME, &C_home_leanvm_14px, "leanVM verifier", INIT_HOME_PAGE, NULL, NULL, NULL, app_quit);

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
