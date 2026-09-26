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

## Install — irreversible

A Safe 3 runs such firmware only once its bootloader is unlocked, which is **irreversible**: the
device's attestation key becomes permanently inaccessible and Trezor Suite reports it as
non-authentic for good (see Trezor's "Unlocking the bootloader on Trezor Safe devices"). Use a
test device. Installing wipes the device.

1. Bootloader mode: disconnect, hold both buttons while reconnecting USB.
2. `.venv/bin/trezorctl device unlock-bootloader`, confirm on the device (once per device).
3. Bootloader mode again, then `.venv/bin/trezorctl firmware update -f <prodtest.bin>`, confirm.
4. At every start the device shows the red "UNSAFE" vendor screen: confirm with a button.

## Run

```sh
.venv/bin/python trezor/bench.py   # writes results/trezor-safe3.json
```
