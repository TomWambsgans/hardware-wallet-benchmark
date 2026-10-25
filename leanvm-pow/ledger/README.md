# Verifying the proof on a Ledger Nano S Plus

**leanVM Verify** is a Ledger app that verifies the `D = 18` proof of [`../README.md`](../README.md) on
the device. The proof (rate 1/4, 267 KiB) is streamed over USB as the verifier reads it, and the device
checks it against the guest's bytecode, which is compiled into the app. It is the same 128-bit, fully
non-interactive verification that leanVM's own verifier performs, ported to fit the device.

## Results

Not measured yet. Run step 3 below; it writes `results/ledger-verify.json`.

## Run it

> [!CAUTION]
> As with PQ Bench ([`../../README.md`](../../README.md), step 1), this installs an **unsigned,
> experimental app**. Use a test device that holds nothing you need. The app has no on-screen
> confirmation, and the screen freezes while it verifies. Removing it (step 4) is reversible.

You need everything PQ Bench needs (Docker, the repo's `.venv` with `host/requirements.txt`, and a
Nano S Plus on firmware 1.6.x, unlocked and on the dashboard), plus [rustup](https://rustup.rs). The
build installs the pinned nightly that `ffi/rust-toolchain.toml` names.

1. Build the app (the Rust verifier as a static library, then the C app in Ledger's pinned builder
   image, against the same SDK as PQ Bench):
   ```sh
   leanvm-pow/ledger/build.sh
   ```
2. Install it and open it (accept both prompts on the device):
   ```sh
   leanvm-pow/ledger/load.sh
   ```
3. Verify the proof three times, each time also streaming it with nothing verified, to get the USB
   baseline:
   ```sh
   .venv/bin/python leanvm-pow/ledger/host/verify.py leanvm-pow/ledger/proofs/d18-rate4.stream \
       --runs 3 --out leanvm-pow/results/ledger-verify.json
   ```
   Each run prints the verification time, the receive-only time, and the deepest the stack went. The
   script stops if the device rejects the proof.
4. Remove the app:
   ```sh
   .venv/bin/python -m ledgerblue.deleteApp --targetId 0x33100004 --appName "leanVM Verify"
   ```

`proofs/d18-rate4.stream` is what `keccak-pow --difficulty 18 --log-inv-rate 2 --ledger-stream <path>`
writes (proving is deterministic, so it regenerates byte for byte).

## How it fits

A Nano S Plus app gets 40 KB of RAM (its globals and the stack) and 400 KB of flash, on a ~63 MHz
Cortex-M35P with no DSP extension. leanVM's verifier keeps the whole proof and every query's Merkle path
in memory, about 1.4 MB natively.
[`verifier/`](verifier) is a `no_std` port that allocates nothing. It walks the same protocol in the same
order, and each module says which part of leanVM's verifier it ports. What changes is how it holds its data:

- **The proof is a stream.** [`transcript::Source`](verifier/src/transcript.rs) hands the verifier its
  scalars and Merkle data in the order it reads them. The app pulls 255-byte chunks over USB.
- **Merkle openings are folded as they arrive.** Each queried row is hashed and reduced to its value on
  the spot, so a WHIR level keeps only (position, digest, value) per query.
- **The Keccak GKR never builds its 1600-entry weight vectors.** They stay factored as an eq table over
  the bit position times a lane vector, and every sum the protocol takes reduces to correlations of two
  eq tables. Those come out of one carry-tracking pass over the 6 shift bits:
  [`keccak.rs`](verifier/src/keccak.rs).
- **The bus forms are evaluated, not built.** leanVM accumulates symbolic degree-2 polynomials per
  table. [`tables.rs`](verifier/src/tables.rs) evaluates each flush directly, coordinate by coordinate.
- **The bytecode is compiled in, sparse.** [`program.rs`](verifier/src/program.rs) holds its 6,185
  nonzero words (of 32,768) through a dictionary of 714 distinct ones, plus the transcript's IV, which
  binds the bytecode's hash. `keccak-pow --gen-ledger` generates it, and a test checks it against the guest.
- **Field arithmetic suits the core.** GF(2^64) carry-less products come from 32-bit integer multiplies
  on masked bit classes (16 `UMULL`s per 32×32 product). That routine is hand-scheduled assembly on ARM
  ([`field.rs`](verifier/src/field.rs)). Keccak-f[1600] is PQ Bench's assembly
  (`ledger-app/src/crypto`), on a state kept bit-interleaved.

The deepest call uses about 27.4 KB of stack. The app reports its own peak on every run, and the build
fails if the linker leaves it less than 30,000 bytes. The device holds the queries rate 1/4 draws (112
at the first WHIR level). Rate 1/2 proofs (225) are refused.

## Checks

- `cargo test --release` (in `leanvm-pow`) checks two things. The port accepts the shipped stream and
  rejects 300 single-bit corruptions of it. The compiled-in bytecode data is the guest's.
- `keccak-pow --ledger-check <stream>` checks the same with 3,000 corruptions, and a changed public input.
- `keccak-pow --ledger-stream <path>` verifies each new proof with the port before writing it.

## Files

| | |
|---|---|
| `verifier/` | the port, `no_std` (natively it is what `keccak-pow` checks against) |
| `ffi/` | the port as a C static library for the app: `leanvm_verify`, and the stream callbacks it calls |
| `app/` | the Ledger app: the APDUs (`app/src/main.c`), the USB stream, the stack measurement |
| `host/verify.py` | streams a proof to the device and times it |
| `proofs/` | the `D = 18`, rate-1/4 proof as the device reads it |
| `build.sh`, `load.sh` | build, install and open the app |

## Credits

The verifier is a port of leanVM's portable verifier (`vendor/leanVM/crates/verifier`,
[leanEthereum/leanVM](https://github.com/leanEthereum/leanVM), MIT / Apache-2.0). The protocol, its
constants (query tables, the RMFE embedding) and the structure of every check are leanVM's.
