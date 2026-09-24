# PQ Bench APDU protocol

CLA `0xE0`. BLAKE2s is the app's own (RFC 7693 compression, compiled at `CRYPTO_OPT`;
the Ledger OS has none). Counters in responses are big-endian `u32`: BLAKE2s evaluations ("hashes") and
compression function calls.

| INS | name | P1 | P2 | data in | data out |
|---|---|---|---|---|---|
| `01` | INFO | – | – | – | `major minor patch have_key yield "O-level\0"` |
| `02` | KEYGEN | – | – | empty: seed from the TRNG; 32 B: master seed | `P(16) ‖ root(16) ‖ hashes ‖ compressions` |
| `03` | SIGN | – | – | message (32 B) | `hashes ‖ compressions ‖ digest trials ‖ counter₀ ‖ counter₁ ‖ counter₂`; signature kept in RAM |
| `04` | GET_SIG | chunk index | – | – | bytes `[240·i, 240·i+240)` of the 4924-byte signature |
| `05` | BENCH | – | 0: chain steps, 1: bare compressions, 2: WOTS public leaves | count (`u32`) | `v(16) ‖ hashes ‖ compressions` |
| `06` | NOP | – | – | – | – (USB round-trip baseline) |
| `07` | HASH | – | – | any bytes | `BLAKE2s-256(data)` |
| `08` | CONFIG | 1/0: service the event loop during long computations or not | – | – | – |

The key (P, S, root and the 1 KB layer-0 cache) lives in RAM until the app exits.

Status words: `9000` ok, `6700` wrong length, `6985` no key yet, `6A86` bad P1/P2,
`6D00` unknown INS, `6E00` wrong CLA, `6F02` the signature's hypertree walk did not
reach the public root.

There is no on-screen confirmation: this is a research app for a device holding no funds.
