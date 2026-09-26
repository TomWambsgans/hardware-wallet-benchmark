#!/usr/bin/env bash
# Build the device's hash code (ledger-app/src/crypto, Thumb-2 paths) for Unicorn, with
# the device's compiler flags. Output: tests/emu/build/emu.elf
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="${IMAGE:-ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest}"
docker run --rm -u "$(id -u):$(id -g)" -v "$ROOT:/w" -w /w "$IMAGE" bash -c '
set -e
B=tests/emu/build; S=ledger-app/src/crypto; mkdir -p $B
F="--sysroot=/usr/lib/arm-none-eabi --target=arm-none-eabi -mcpu=cortex-m35p+nodsp -mthumb -msoft-float -fropi -frwpi -ffreestanding -fno-builtin -mno-unaligned-access -O3 -Wall -Wextra"
for f in blake2s sha256; do clang $F -c $S/$f.c -o $B/$f.o; clang $F -c $S/${f}_thumb2.S -o $B/${f}_thumb2.o; done
clang $F -c tests/emu/shim.c -o $B/shim.o
ld.lld-21 -T tests/emu/emu.ld $B/*.o -o $B/emu.elf 2>&1 | grep -v "entry symbol" || true
'
