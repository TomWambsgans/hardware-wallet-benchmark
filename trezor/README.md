# SPHINCS+ on a Trezor Safe 3

The same scheme and code as the Ledger app (`ledger-app/src/crypto`: the C scheme and the
Thumb-2 BLAKE2s and SHA-256 compressions), run on a Trezor Safe 3 (T3B1: STM32U585,
Cortex-M33 at 160 MHz) as three commands added to Trezor's production-test firmware
(prodtest, C, a text command line over USB serial):

| command | |
|---|---|
| `sphincs-bench <hash> <count>` | time `count` compressions |
| `sphincs-keygen <hash> <seed>` | key generation (with the layer-0 cache) from a 32-byte hex seed |
| `sphincs-sign <hash> <message>` | sign a 32-byte hex message; the signature comes back as `PROGRESS` lines |

`<hash>` is `blake2s` or `sha256`; timings are CPU cycles (`systick_cycles()`).

## Build

```sh
trezor/build.sh
```

It fetches trezor-firmware at a pinned commit into `trezor/trezor-firmware/`, adds
`prodtest_sphincs.c`, the crypto and `prodtest-build.patch`, and runs Trezor's reproducible
Docker build. The image is non-production: signed with Trezor's public development keys under
the "unsafe" vendor header. The first build sets up Trezor's Nix environment and takes a while.

## Install and run

> [!CAUTION]
> Installing this firmware requires **permanently unlocking the Safe 3's bootloader**. Unlocking
> is irreversible: the device can never again prove it is genuine, and it loses its secure
> element's attestation for good. **Use a test device only.** The full procedure and every
> consequence are in the [top README, "Reproduce", section 2](../README.md#2-trezor-safe-3).

In short:
1. `trezor/build.sh`
2. Bootloader mode, then `trezorctl device unlock-bootloader` (**irreversible**).
3. Bootloader mode, then `trezorctl firmware update -f <prodtest.bin>`.
4. Press a button on the "UNSAFE" screen.
5. `.venv/bin/python trezor/bench.py`

## Results

`results/trezor-safe3.json` (bootloader 2.1.16, prodtest 0.3.10 at trezor-firmware 3227ea8):

| | BLAKE2s | SHA-256 |
|---|---|---|
| hashes/s, compression loop | **86.0K/s** (1,861 cycles, 11.6 µs) | **59.4K/s** (2,692 cycles, 16.8 µs) |
| hashes/s in SPHINCS+ keygen / signing | 81.5K/s / 80.3K/s | 57.1K/s / 56.5K/s |
| keygen (1.43M compressions) | 17.5 s | 25.0 s |
| sign, mean (min–max) | 2.47 s (2.25–2.84) | 3.70 s (3.10–4.17) |

## Notes

- The commands run inside prodtest, not Trezor's wallet firmware: no Trezor logic is on the
  path, and the key stays in RAM until the next reboot.
- `prodtest-build.patch` changes two files. `build.rs` compiles our sources.
  `build-docker.sh` skips the fingerprints Trezor computes for its signing ceremony, which
  have no label for the unsafe vendor header.
- T3B1 enables no watchdog, so a long command (a keygen takes up to 25 s) is not interrupted.
