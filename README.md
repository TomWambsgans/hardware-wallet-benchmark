# hardware wallet benchmark

Benchmarks of post-quantum hash-based signatures running on hardware wallets.
First target: **Ledger Nano S Plus**. Scheme: leanVM's **SPHINCS+ variant over
BLAKE2s** with WOTS+C and FORS+C (leanVM `doc/sphincs/main.tex`, reference
`crates/sphincs`): n = 16, w = 3, v = 42, T = 191, d = 3 layers of heights
(12, 7, 7), a = 10, k = 15; 32-byte public key, 4924-byte signature,
2^24 signatures per key.

## Layout

| path | what |
|---|---|
| `ledger-app/` | the device app (C, Ledger secure SDK): keygen, sign, microbenchmarks |
| `ledger-app/src/crypto/sphincs.c` | the scheme, ported from `crates/sphincs`; streaming treehash, 1 KB layer-0 cache |
| `ledger-app/src/crypto/blake2s.c` | BLAKE2s-256, two run-time-selectable compression functions |
| `host/sphincs_ref.py` | Python reference (keygen, sign, verify); reproduces leanVM's vectors byte for byte |
| `host/pqbench.py` | host client: `info`, `hashcheck`, `micro`, `vector`, `bench` |
| `host/probe.py` | what's plugged in: target id, firmware, running app |
| `tools/leanvm-vectors/` | Rust generator of `vectors/` from leanVM's `crates/sphincs` |
| `tools/native/` | runs the device's crypto natively against the vectors, before sideloading |
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
```

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
scripts/load.sh                  # device unlocked, on the dashboard; accept the prompts on screen
# open "PQ Bench" on the device (or let pqbench open it), then:
.venv/bin/python host/pqbench.py hashcheck   # device BLAKE2s == hashlib, both implementations
.venv/bin/python host/pqbench.py micro       # compression, chain step, WOTS leaf timings
.venv/bin/python host/pqbench.py vector      # leanVM's key and signatures reproduced on the device
.venv/bin/python host/pqbench.py bench --sigs 5 --label o3
```

Timings are host wall-clock around each APDU minus the median USB round trip of a no-op
APDU. Every signature is compared byte for byte with the Python reference signer and verified.

## Design choices

- **BLAKE2s implementation** (run time, P1): RFC 7693 loop or fully unrolled. The OS crypto
  library has no BLAKE2s, so both are app code. The Nano S Plus core is a Cortex-M35P
  (ARMv8-M mainline, no DSP).
- **Optimization level** of `src/crypto` (build time, `CRYPTO_OPT`): `-O3` by default; the SDK
  builds apps at `-Oz`.
- **Word-level Th**: every value is 4 little-endian words and every one-block input
  (chain step, PRF, node, encoding: 48–64 bytes) is laid out directly as the 16-word BLAKE2s block,
  one compression per call. WOTS leaves (704 B, 11 blocks) and FORS roots (256 B) are streamed.
- **Keys**: a fresh seed from the device TRNG, or one supplied by the host (to check against the
  reference). Not derived from the device's BIP-39 seed, and nothing is persisted: the key and its
  1 KB cache live in RAM until the app exits, so every session starts with a 1.38M-hash keygen.
- **Signature** is computed into a 4924-byte RAM buffer, then read out in 240-byte chunks, so
  signing time excludes USB transfer.
- **No on-screen confirmation**, and no fault-attack countermeasures: numbers are for the bare scheme.
- **Event loop servicing**: the app calls `io_seproxyhal_io_heartbeat()` after each WOTS leaf,
  every 64 FORS leaves and every 256 grinding attempts; `bench --no-yield` turns it off.

## Cost model (hash calls, from the spec)

- Keygen: 2^12 WOTS leaves × 337 (42 PRF + 294 chain steps + 1 leaf hash of 11 compressions)
  + 4095 nodes + 1 = 1,384,448 hashes.
- Signing, ≈190K hashes on average: randomizer grinding (2^10 trials × 2 hashes), FORS
  (14 × 3071), two height-7 trees (2 × 128 × 337), layer 0's 2^6-leaf subtree via the cache,
  and three WOTS encoding searches (≈2^13.6 attempts each).
