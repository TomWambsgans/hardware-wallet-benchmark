# hardware wallet benchmark

Benchmarks of post-quantum hash-based signatures running on hardware wallets.
First target: **Ledger Nano S Plus**. Scheme: leanVM's **SPHINCS+ variant over
BLAKE2s** with WOTS+C and FORS+C (leanVM `doc/sphincs/main.tex`, reference
`crates/sphincs`): n = 16, w = 3, v = 42, T = 191, d = 3 layers of heights
(12, 7, 7), a = 10, k = 15; 32-byte public key, 4924-byte signature,
2^24 signatures per key.

**Headline (Nano S Plus, firmware 1.6.1; details in [Results](#results)):**

| | C (`-O3`) | hand-written Thumb-2 |
|---|---|---|
| keygen | 57.6 s | **43.3 s** |
| sign (mean of 5) | 7.92 s | **5.60 s** |
| BLAKE2s compression | 37.0 µs (27.0K/s) | **30.0 µs (33.3K/s)** |
| SHA-256 compression | 45.2 µs (22.1K/s) | **41.0 µs (24.4K/s)** |

Every signature is checked byte for byte against a reference signer and verified; leanVM's own
vectors are reproduced on the device.

## Layout

| path | what |
|---|---|
| `ledger-app/` | the device app (C, Ledger secure SDK): keygen, sign, microbenchmarks |
| `ledger-app/src/crypto/sphincs.c` | the scheme, ported from `crates/sphincs`; streaming treehash, 1 KB layer-0 cache |
| `ledger-app/src/crypto/blake2s.c` | BLAKE2s-256 (RFC 7693 compression) and the one-block fast path |
| `host/sphincs_ref.py` | Python reference (keygen, sign, verify); reproduces leanVM's vectors byte for byte |
| `host/pqbench.py` | host client: `info`, `hashcheck`, `micro`, `vector`, `bench` |
| `host/probe.py` | what's plugged in: target id, firmware, running app |
| `tools/leanvm-vectors/` | Rust generator of `vectors/` from leanVM's `crates/sphincs` |
| `tools/native/` | runs the device's crypto natively against the vectors, before sideloading |
| `tools/emu/` | runs every compression under Unicorn (ARMv8-M): checks it against Python and the calling convention, counts instructions |
| `scripts/gen_asm.py` | generates the Thumb-2 BLAKE2s / SHA-256 compressions and the timing probes |
| `ledger-app/src/crypto/sha256.c`, `src/sha256_os.c` | SHA-256 compression in C, and through the OS library with any IV |
| `scripts/build.sh`, `scripts/load.sh` | build in Ledger's app-builder image, sideload over USB |
| `vectors/leanvm-sphincs-blake2s.json` | 3 keys × 2 messages, from leanVM `5fe073b` |
| `results/` | benchmark outputs (JSON), one file per run |
| `doc/PROTOCOL.md` | the app's APDU interface |

## Setup (macOS, Apple silicon)

```sh
brew install colima docker
colima start --vm-type vz --vz-rosetta --cpu 4 --memory 6
docker pull ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest   # arm64-native

uv venv .venv && uv pip install --python .venv/bin/python -r host/requirements.txt
.venv/bin/python host/probe.py            # device on its dashboard: target id and firmware
.venv/bin/python host/sphincs_ref.py      # Python reference == leanVM vectors
python3 tools/native/check_native.py      # device C code, built natively, == leanVM vectors
tools/emu/build.sh && .venv/bin/python tools/emu/run.py   # every compression: output, calling convention, insns
```

**Before sideloading new assembly, run `tools/emu/run.py`.** It checks that every function preserves
r4-r11 and sp and never writes above sp; a hand-written function that wrote one word past its
frame preceded a device wipe (seed phrase had to be re-entered).

Regenerating the vectors needs leanVM checked out next to the `zk` directory
(`../../leanVM` from this repo): `cd tools/leanvm-vectors && cargo run --release > ../../vectors/leanvm-sphincs-blake2s.json`.

The SDK branch must match the firmware's API level (`api_levels.json` in the SDK).
Nano S Plus firmware 1.6.x is API level 26, the default of `scripts/build.sh`
(`SDK_BRANCH=API_LEVEL_xx scripts/build.sh` otherwise).

| firmware | 1.1.1 | 1.2.0 | 1.3.x | 1.4.1 | 1.5.0 | 1.6.x |
|---|---|---|---|---|---|---|
| API level | 5 | 18 | 22 | 24 | 25 | 26 |

## Build, load, run

```sh
scripts/build.sh                 # crypto at -O3 (CRYPTO_OPT=z for the SDK's default -Oz)
scripts/load.sh                  # device unlocked; accept the two prompts on screen (closes/reopens the app)
.venv/bin/python host/pqbench.py hashcheck   # device BLAKE2s == hashlib
.venv/bin/python host/pqbench.py compcheck   # every compression function == Python reference
.venv/bin/python host/pqbench.py probes      # instruction timing probes
.venv/bin/python host/pqbench.py micro       # compression, chain step, WOTS leaf timings
.venv/bin/python host/pqbench.py vector --blake2s 5      # leanVM's key and signatures on the device
.venv/bin/python host/pqbench.py bench --blake2s 5 --sigs 5 --label nanosp-blake2s-v4
```

Timings are host wall-clock around each APDU minus the median USB round trip of a no-op
APDU. Every signature is compared byte for byte with the Python reference signer and verified.

## Results

Ledger Nano S Plus, firmware 1.6.1, SDK API level 26, no event servicing during computations.

### Signature scheme (leanVM BLAKE2s SPHINCS+)

Fresh random key, 5 signatures on random messages per row, each identical to the Python
reference signer's and verified (`results/2026-09-24-nanosp-blake2s-{v4,c}.json`). leanVM's own
key and signatures (`vectors/`) are reproduced byte for byte on the device with both.

| BLAKE2s | keygen (1.38M hashes) | sign, mean (min–max) | µs per compression while signing |
|---|---|---|---|
| C, `-O3` | 57.6 s | 7.92 s (6.67–9.03) | 40.8 |
| **Thumb-2 v4 + one-block entry** | **43.3 s** | **5.60 s (5.11–6.05)** | **30.6** |

Signing cost varies with the grinding (randomizer trials, WOTS counters): 158K–216K hashes here.
The key (P, S, root, 1 KB cache) is kept in the app's flash, so signing works right after reopening
the app.

### Compression functions

`pqbench.py micro`, `results/2026-09-24-compressions-v{3,4}.json`; every function is checked on
the device against a Python reference (`pqbench.py compcheck`).

| | µs | per second | cycles (~63 MHz) |
|---|---|---|---|
| BLAKE2s, C `-O3` | 37.0 | 27.0K | 2,344 |
| **BLAKE2s, Thumb-2 v4** | **30.0** | **33.3K** | **1,900** |
| SHA-256, C `-O3` | 45.2 | 22.1K | 2,863 |
| **SHA-256, Thumb-2 v3** | **41.0** | **24.4K** | **2,597** |
| SHA-256, OS library (`cx_sha256`, any IV via its context) | 388 | 2.6K | 24,560 |

### The core (timing probes, `results/2026-09-24-probes.json`)

ST33K1M5, Cortex-M35P at ~63 MHz, single issue:
- 1 cycle: 16- and 32-bit ALU ops, `ror #imm`, loads and stores from RAM — **inside a loop of
  at most ~2 KB**. There is a ~2 KB instruction cache: straight-line code beyond it is
  fetch-bound at ~0.6 cycles per byte (1.26 cycles per 16-bit, 2.5 per 32-bit instruction).
- 2 cycles: data-processing with a shifted/rotated register operand, `ldrd`.
- +1 cycle: a load used by the next instruction. Loads from flash: 1.5–2 cycles.

So the fast versions are compact loops (≈900 bytes) with explicit rotations, loads scheduled
ahead of use, and tables copied to RAM; "clever" straight-line assembly (rotations folded into
shifted operands, 4–7 KB) was slower than clang's C.

### Hand-written compressions (`scripts/gen_asm.py`)

| style | BLAKE2s insns | SHA-256 insns | notes |
|---|---|---|---|
| C `-O3` | 1,941 | 2,441 | compact loops |
| v1 lazy rotation | 1,158 | 1,916 | straight-line, shifted operands: slower |
| v2 explicit rotation | 1,472 | 2,492 | straight-line: fetch-bound |
| v3 loop, table in RAM | 1,845 | 2,478 | in cache |
| **v4 loop, row pointer in a register** | **1,718** | – | two spill slots, G order by exhaustive search |

BLAKE2s v4's remaining overhead over the 1,120 ALU operations of 80 G's: two loads per message word
(round-dependent permutation through a table: the round loop must stay in cache) and the spills of
6 of the 16 state words. SHA-256 v3 is 25 instructions a round (no shifted operands) plus a
17-instructions-a-word schedule.

## Design choices

- **BLAKE2s** (run time, `CONFIG` P2 / `--blake2s`): C, or the generated Thumb-2 versions; v4 (5) is
  the fastest, and routes the scheme's one-block Th through `b2s_th_asm4` (IV constants, 4-word
  output). The OS crypto library has no BLAKE2s.
- **Optimization level** of `src/crypto` (build time, `CRYPTO_OPT`): `-O3` by default; the SDK
  builds apps at `-Oz`.
- **Word-level Th**: every value is 4 little-endian words and every one-block input
  (chain step, PRF, node, encoding: 48–64 bytes) is laid out directly as the 16-word BLAKE2s block,
  one compression per call. WOTS leaves (704 B, 11 blocks) and FORS roots (256 B) are streamed.
- **Keys**: a fresh seed from the device TRNG, or one supplied by the host (to check against the
  reference). Not derived from the device's BIP-39 seed. The key and its 1 KB cache are stored,
  unencrypted, in the app's flash (NVM): a research app on a test device.
- **Signature** is computed into a 4924-byte RAM buffer, then read out in 240-byte chunks, so
  signing time excludes USB transfer.
- **No on-screen confirmation**, and no fault-attack countermeasures: numbers are for the bare scheme.
- **No event loop servicing during computations** (default). `io_seproxyhal_io_heartbeat()` blocks
  until the next event, i.e. up to the 100 ms ticker: called after each WOTS leaf it took a leaf
  from 15 ms to 100 ms. A 1-minute keygen completes fine without it. `--yield` re-enables it
  (after each WOTS leaf, every 64 FORS leaves, every 256 grinding attempts).

## Cost model (hash calls, from the spec)

- Keygen: 2^12 WOTS leaves × 337 (42 PRF + 294 chain steps + 1 leaf hash of 11 compressions)
  + 4095 nodes + 1 = 1,384,448 hashes.
- Signing, ≈190K hashes on average: randomizer grinding (2^10 trials × 2 hashes), FORS
  (14 × 3071), two height-7 trees (2 × 128 × 337), layer 0's 2^6-leaf subtree via the cache,
  and three WOTS encoding searches (≈2^13.6 attempts each).
