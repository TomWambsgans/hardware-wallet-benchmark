# Hashes per second on a Ledger Nano S Plus and a Trezor Safe 3

BLAKE2s and SHA-256 compressions, and Keccak-f[1600] permutations (Keccak-256, as in
Ethereum), per second, measured during SPHINCS+ signing
([leanVM's variant](https://github.com/leanEthereum/leanMultisig/blob/5fe073bef6fb1cae20b3a2394c69f60489c2eacf/doc/sphincs/main.tex)).

| | BLAKE2s | SHA-256 | Keccak-256 |
|---|---|---|---|
| Trezor Safe 3 | **80.3K/s** | **56.5K/s** | — |
| Ledger Nano S Plus | **32.6K/s** | **23.6K/s** | **5.8K/s** |

Signatures match the test vectors. Raw data: `results/*.json`; table: `host/rates.py`. The
Trezor's firmware includes Keccak-256 but has not been reflashed and measured with it yet.

## The scheme

leanVM's [`doc/sphincs/main.tex`](https://github.com/leanEthereum/leanMultisig/blob/5fe073bef6fb1cae20b3a2394c69f60489c2eacf/doc/sphincs/main.tex), with its reference implementation
[`crates/sphincs`](https://github.com/leanEthereum/leanMultisig/tree/5fe073bef6fb1cae20b3a2394c69f60489c2eacf/crates/sphincs), both at leanMultisig commit `5fe073b`: n = 16 bytes, WOTS+C with
w = 3, v = 42, T = 191; d = 3 layers of heights (12, 7, 7); FORS+C with a = 10, k = 15. Every
hash is Th(P, tw, M) = H(tw ‖ P ‖ M)[:16] (the message digest keeps 22 bytes), with H

- **BLAKE2s**: BLAKE2s-256, as in leanVM. `vectors/blake2s.json` comes from leanVM's Rust code;
- **SHA-256**: the SHA-256 compression function applied from the standard IV to the input's
  64-byte blocks, the last one zero-padded, with no length padding; the digest is the final
  state, big-endian. Every input length is fixed by its tweak type, so each Th of at most
  64 bytes is one compression, as with BLAKE2s. This construction is this repository's (leanVM
  specifies only BLAKE2s); `vectors/sha256.json` comes from `host/sphincs_ref.py`;
- **Keccak-256**: Ethereum's `keccak256` (the original Keccak padding, not SHA3-256): one
  Keccak-f[1600] permutation per 136 bytes, so every Th is one permutation and a WOTS leaf
  (704 bytes) is 6 instead of 11. `vectors/keccak256.json` comes from `host/sphincs_ref.py`
  (pycryptodome).

Key generation builds layer 0's tree (2^12 WOTS leaves, 1.43M compressions) and keeps its 64
nodes at height 6: signing then rebuilds a 64-leaf subtree instead of the whole tree. The key
and this cache are stored in the app's flash, so signing works right after reopening the app.

## Verifying a leanVM proof on the Ledger

The same device also verifies a real zero-knowledge proof. [`leanvm-pow/`](leanvm-pow/README.md)
proves, in one [leanVM](https://github.com/leanEthereum/leanVM) proof, that 193,672 is the smallest
integer whose `keccak256(abi.encode(uint256(i)))` starts with 18 zero bits, and
[`leanvm-pow/ledger/`](leanvm-pow/ledger/README.md) checks that proof on a Nano S Plus: leanVM's
verifier ported to the 40 KB of RAM an app gets, with the 265 KiB proof streamed over USB as the
verifier reads it. It is the full 128-bit non-interactive verification, not a reduced one.

| | |
|---|---|
| verifying, on the device | **2.92 s** |
| receiving the proof over USB | 12.85 s |
| end to end | 15.77 s |
| peak stack | 27,432 bytes of the 39,224 the app gets |

Checking the proof costs the device less than a quarter of what receiving it does: the 21 KB/s USB
link is the bottleneck, not the ~63 MHz Cortex-M35P. The two figures separate cleanly: the app is
strictly serial, blocking while a chunk is in flight, so each run is also streamed with nothing
verified, and 2.92 s is the difference. Raw data: `leanvm-pow/results/ledger-verify.json`.

## Reproduce

> [!CAUTION]
> **Both benchmarks install unofficial, experimental code on a hardware wallet. Use dedicated
> test devices that hold no funds and no recovery phrase you need.** The Trezor procedure
> **permanently** removes the Trezor Safe 3's ability to prove it is genuine: it cannot be
> undone, by you or by Trezor. Read each device's warnings before you start.

### 0. Host (no device involved)

Needs Docker (on macOS e.g. `brew install colima docker && colima start`), Python 3 and network
access.

```sh
python3 -m venv .venv && .venv/bin/pip install -r host/requirements.txt
.venv/bin/python host/sphincs_ref.py                      # Python reference == vectors
python3 tests/native/check.py                             # device C code, built natively == vectors
tests/emu/build.sh && .venv/bin/python tests/emu/run.py   # Thumb-2 == reference, calling convention
```

### 1. Ledger Nano S Plus

> [!WARNING]
> **What this does to the Ledger:**
> - It installs ("sideloads") an **unsigned app**, which is not reviewed by Ledger. The device
>   asks you to allow an unsafe manager and to confirm the install.
> - The app **signs anything, with no on-screen confirmation**, and keeps its SPHINCS+ key
>   **unencrypted** in its flash. The benchmark derives that key from a public test seed sent
>   by the host; the app never reads the device's own recovery phrase.
> - The app runs hand-written assembly with no attack countermeasures. During development, a
>   (since fixed) bug in it hung a Nano S Plus, and recovering the device **wiped it**. **Keep
>   the device's recovery phrase, or keep nothing on the device.**
> - Otherwise it is reversible: removing the app (step 5) deletes it along with its key.

Needs a Nano S Plus on firmware 1.6.x (`scripts/load.sh` refuses anything else), unlocked with
its PIN, on the dashboard.

1. Build the app (Ledger's pinned builder image, pinned SDK):
   ```sh
   scripts/build.sh
   ```
   The build is deterministic: `ledger-app/build/nanos2/bin/app.elf` has SHA-256
   `9c8d57dfc6bf5a3067935f5eda5bb15195153344be68e4041106925fe528fad0`.
2. Install it and open it:
   ```sh
   scripts/load.sh
   ```
   On the device, accept both prompts: allow the unsafe manager, then confirm the install.
3. Run the benchmark (~11 minutes, Keccak-256 7 of them; writes `results/nanosp.json`):
   ```sh
   .venv/bin/python host/pqbench.py
   ```
   The screen freezes during key generation and signing, because the app does not service the
   event loop while it computes. That is expected. Do not unplug the device during the run.
4. The benchmark checks itself: it stops with an error if the public key or a vector signature
   differs from `vectors/`, or if a random-message signature fails to verify.
5. Remove the app when you are done, and confirm on the device:
   ```sh
   .venv/bin/python -m ledgerblue.deleteApp --targetId 0x33100004 --appName "PQ Bench"
   ```

### 2. Trezor Safe 3

> [!CAUTION]
> **Step 4 is IRREVERSIBLE. It permanently degrades the device. Do not do this to a Trezor you
> want to use as a wallet, ever again.**
>
> A Safe 3 runs non-Trezor firmware only after its bootloader is unlocked. Unlocking **erases
> the factory secret keys** from the chip's write-once secret area, and nothing can re-create
> them. The results:
> - **Trezor Suite's authenticity check fails forever.** The device can never again prove it is
>   a genuine Trezor.
> - Official firmware still installs and runs, but **without its paired secure element**, so
>   device attestation and FIDO attestation are **permanently lost**. We have not audited what
>   else this weakens: **treat the device as insecure from then on.**
> - **The device is erased**, both at the unlock and at the firmware install. Any wallet on it
>   is gone unless you hold its recovery phrase.
> - The bootloader now accepts **any firmware signed with Trezor's publicly known development
>   keys**, which anyone can produce. Anyone with physical access can install arbitrary code.
> - Every boot shows a red **"UNSAFE, DO NOT USE!"** vendor screen, which you dismiss with a
>   button.
>
> Going back to official firmware later works (step 8), but the bootloader stays unlocked and
> every point above still applies.

Needs a Trezor Safe 3 (T3B1) with bootloader 2.1.8 or later, the first that can be unlocked.
Installing the latest official firmware updates the bootloader. In bootloader mode,
`trezorctl get-features` shows the bootloader version as `major/minor/patch_version`. Tested
with bootloader 2.1.16 and official firmware 2.12.5.

1. Build the firmware: Trezor's production-test firmware (prodtest), with our commands added,
   signed with the development keys, under the unsafe vendor header. This runs Trezor's
   reproducible Docker build; the first run builds Trezor's Nix environment and takes a long
   time.
   ```sh
   trezor/build.sh
   ```
   It prints the image path: `trezor/trezor-firmware/build/core-T3B1/prodtest/prodtest.bin`.
2. Check the image offline (no device needed). It must say `T3B1 firmware image` and
   `Vendor header from UNSAFE, DO NOT USE!`:
   ```sh
   .venv/bin/trezorctl firmware verify trezor/trezor-firmware/build/core-T3B1/prodtest/prodtest.bin
   ```
3. Put the device in **bootloader mode**: unplug it, hold both buttons, plug it back in. If it
   runs official firmware, `.venv/bin/trezorctl device reboot-to-bootloader` does the same,
   after a confirmation on the device.
4. ⚠️ **IRREVERSIBLE: unlock the bootloader.** Read the caution above first.
   ```sh
   .venv/bin/trezorctl device unlock-bootloader
   ```
   Confirm on the device. It erases itself and restarts.
   `.venv/bin/trezorctl get-features` then shows `bootloader_locked: False`.
5. Bootloader mode again (step 3), then install the firmware (this **erases the device**):
   ```sh
   .venv/bin/trezorctl firmware update -f trezor/trezor-firmware/build/core-T3B1/prodtest/prodtest.bin
   ```
   Confirm the unofficial-firmware warning on the device. If it fails with "Firmware downgrade
   protection", the device has run official firmware newer than the trezor-firmware commit
   pinned in `trezor/build.sh`. Move that pin forward and rebuild.
6. The device restarts on the red "UNSAFE, DO NOT USE!" screen: press a button. Prodtest then
   runs and shows up as a USB serial port (`/dev/cu.usbmodem*` on macOS).
7. Run the benchmark (~5 minutes; writes `results/trezor-safe3.json`). It checks its results as
   the Ledger one does, and also checks the CPU clock against the host's clock.
   ```sh
   .venv/bin/python trezor/bench.py
   ```
   The key lives in RAM: every run generates it again.
8. To go back to official firmware: enter bootloader mode, then install official firmware with
   Trezor Suite, or run `.venv/bin/trezorctl firmware update` (which downloads it). **The
   bootloader stays unlocked, and the device stays unable to prove it is genuine.**

### 3. A leanVM proof on the Ledger Nano S Plus

Verifies the proof in `leanvm-pow/ledger/proofs/d18-rate4.stream` on the device. The same warning as
step 1 applies, since it is an unsigned, sideloaded app, but this one holds no key and signs
nothing: it reads a proof and answers whether it is valid. Needs everything step 1 needs, plus
[rustup](https://rustup.rs); the build installs the nightly that `leanvm-pow/ledger/ffi/rust-toolchain.toml`
pins.

1. Build the app (the Rust verifier as a static library, then the C app in Ledger's pinned image):
   ```sh
   leanvm-pow/ledger/build.sh
   ```
2. Check its hand-written assembly under the emulator, before it runs on a device (no device needed):
   ```sh
   .venv/bin/python tests/emu/run_leanvm.py
   ```
3. Install it and open it, accepting both prompts on the device:
   ```sh
   leanvm-pow/ledger/load.sh
   ```
4. Verify the proof three times (~2 minutes; writes `leanvm-pow/results/ledger-verify.json`):
   ```sh
   .venv/bin/python leanvm-pow/ledger/host/verify.py \
       leanvm-pow/ledger/proofs/d18-rate4.stream --runs 3 \
       --out leanvm-pow/results/ledger-verify.json
   ```
   Each run prints the verification time, the receive-only baseline and how deep the stack went. The
   screen freezes while the device verifies, as in step 1. The script stops if the device rejects the
   proof.
5. Remove the app when you are done, and confirm on the device:
   ```sh
   .venv/bin/python -m ledgerblue.deleteApp --targetId 0x33100004 --appName "leanVM Verify"
   ```

To prove the statement again on a laptop instead of using the shipped proof (no device; about 7
seconds, but 19 GiB of RAM):

```sh
cd leanvm-pow && cargo run --release -- --difficulty 18 --log-inv-rate 2
```

## Layout

| path | |
|---|---|
| `ledger-app/src/crypto/sphincs.c` | the scheme: WOTS+C, FORS+C, streaming treehash, layer-0 cache |
| `ledger-app/src/crypto/hash.c` | H for the selected hash: one-block Th, streaming for longer inputs |
| `ledger-app/src/crypto/{blake2s,sha256}.c` | compression functions: Thumb-2 on the device, C elsewhere |
| `ledger-app/src/crypto/keccak.c` | the Keccak-256 sponge; Keccak-f[1600] in Thumb-2 on the device, C elsewhere |
| `ledger-app/src/crypto/*_thumb2.S` | the Thumb-2 compressions and permutation, generated by `scripts/gen_asm.py` |
| `ledger-app/src/main.c` | the app: APDUs for keygen, sign, signature readout, compression benchmark, the OS's Keccak-256 |
| `host/sphincs_ref.py` | Python reference (keygen, sign, verify), the three hashes |
| `host/pqbench.py` | runs the benchmark against the Ledger |
| `host/rates.py` | the README table, from `results/*.json` |
| `trezor/` | the Trezor Safe 3 port: prodtest commands, build, benchmark |
| `tests/` | native and emulator checks; `leanvm-vectors/` regenerates `vectors/blake2s.json` |
| `leanvm-pow/` | the proof: the zkDSL guest, the prover run, leanVM vendored |
| `leanvm-pow/ledger/` | leanVM's verifier ported to the Nano S Plus, and the app that runs it |

## Notes

- **Compression functions.** Timing probes on the device showed a ~63 MHz Cortex-M35P with a
  ~2 KB instruction cache: straight-line code beyond it is fetch-bound (~0.6 cycle per byte),
  operands with a rotation cost 2 cycles, and loads from flash 1.5–2. So both compressions are
  small loops with explicit rotations, loads issued ahead of use, and tables copied to RAM
  (`scripts/gen_asm.py` documents the register allocation). The chip has no hash hardware, and
  the OS's own SHA-256 (`cx_sha256`) takes ~390 µs per compression.
- **Keccak-f[1600]** (163 µs, ~10.3K cycles, 6.1K/s in a loop) works on the bit-interleaved
  state, where each 64-bit rotation is two 32-bit ones. One round is the loop body (1.35 KB,
  inside the instruction cache): θ's column parities from the state, then each row's five
  words loaded, XORed with D, rotated, and χ'd into a second state, the two swapping each
  round. The ten D words live in six registers, with the row order picked by exhaustive
  search to reload as few as possible (7 per round). A one-block Th interleaves its input
  and de-interleaves its output: 174 µs. A WOTS chain step does neither (its output lanes are
  the next input's lanes, kept interleaved; only the position p is redone): 165 µs, all in
  the instruction cache. During signing: 5.8K/s, 6% under the loop (BLAKE2s: 3%). The OS's own Keccak-256 (`cx_keccak_init` + `cx_sha3_update` +
  `cx_sha3_final`, what Ledger's Ethereum app calls) takes 1.21 ms per 64-byte hash, 7.4x
  slower.
- **Trezor Safe 3.** The commands run inside Trezor's production-test firmware (a C command line
  over USB serial), so no Trezor firmware logic is involved; the key lives in RAM until the
  next reboot. The STM32U585 has a SHA-256 peripheral, not used here: it computes padded
  SHA-256, not this scheme's bare compression.
- **The SDK's `memset` and `memcpy` copy byte by byte** (~3 cycles a byte): the hot paths
  copy words instead.
- **Not production code**: no on-screen confirmation, no side-channel or fault-attack
  countermeasures, key unencrypted in flash.
