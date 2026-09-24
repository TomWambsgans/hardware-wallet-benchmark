# PQ Bench APDU protocol

CLA `0xE0`. Counters in responses are big-endian `u32`: BLAKE2s evaluations ("hashes") and
compression function calls.

| INS | name | P1 | P2 | data in | data out |
|---|---|---|---|---|---|
| `01` | INFO | – | – | – | `major minor patch have_key yield b2s_impl "O-level\0"` |
| `02` | KEYGEN | – | – | empty: seed from the TRNG; 32 B: master seed | `P(16) ‖ root(16) ‖ hashes ‖ compressions`; the key is stored in flash |
| `03` | SIGN | – | – | message (32 B) | `hashes ‖ compressions ‖ digest trials ‖ counter₀ ‖ counter₁ ‖ counter₂`; signature kept in RAM |
| `04` | GET_SIG | chunk index | – | – | bytes `[240·i, 240·i+240)` of the 4924-byte signature |
| `05` | BENCH | see P2 | 0: chain steps; 1: compressions of function P1; 2: WOTS public leaves; 3: iterations of timing probe P1 | count (`u32`) | `v(16) ‖ hashes ‖ compressions` |
| `06` | NOP | – | – | – | – (USB round-trip baseline) |
| `07` | HASH | – | – | any bytes | `BLAKE2s-256(data)` (with the selected implementation) |
| `08` | CONFIG | 1/0: service the event loop during long computations | BLAKE2s implementation the scheme uses (below) | – | – |
| `09` | COMPRESS | function (below) | – | `h (8 LE words) ‖ m (16 LE words)` [`‖ t ‖ f`, LE, BLAKE2s only] | `h` after one compression |

Functions (`INS_COMPRESS` P1, `INS_BENCH` P2 = 1):

| id | function |
|---|---|
| 0 | BLAKE2s, C (RFC 7693 loop) |
| 1 | BLAKE2s, Thumb-2 v1 (lazy rotation, straight-line) |
| 2 | BLAKE2s, Thumb-2 v2 (explicit rotation, straight-line) |
| 3 | BLAKE2s, Thumb-2 v3 (round loop), offset table in flash |
| 4 | BLAKE2s, Thumb-2 v3, offset table in RAM |
| 5 | BLAKE2s, Thumb-2 v4 (row pointer in a register), table in RAM |
| 6 | SHA-256, C |
| 7 | SHA-256, Thumb-2 v1 |
| 8 | SHA-256, Thumb-2 v2 |
| 9 | SHA-256, Thumb-2 v3 (loops), K in flash |
| 10 | SHA-256, Thumb-2 v3, K in RAM |
| 11 | SHA-256, OS library (`cx_sha256_*`, arbitrary IV by overwriting the context's state) |

BLAKE2s implementation for the scheme (`CONFIG` P2): 0 C, 1 v1, 2 v2, 3 v3 (flash), 4 v3 (RAM),
5 v4 — with 5, one-block hashes go through `b2s_th_asm4`.

The key (P, S, root and the 1 KB layer-0 cache) is written to the app's flash by KEYGEN and
reloaded when the app starts. SECRET KEY MATERIAL, unencrypted: a research app on a test device.

Status words: `9000` ok, `6700` wrong length, `6985` no key yet, `6A86` bad P1/P2,
`6D00` unknown INS, `6E00` wrong CLA, `6F02` the signature's hypertree walk did not
reach the public root.

There is no on-screen confirmation, and no event servicing during computations by default: the
screen freezes during keygen (~45 s) and signing (~6 s).
