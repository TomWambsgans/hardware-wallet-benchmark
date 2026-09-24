#!/usr/bin/env bash
# Build the device's crypto sources for Unicorn, with the device's compiler flags
# (clang, Cortex-M35P, -fropi -frwpi, CRYPTO_OPT). Output: tools/emu/build/emu.elf
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="${IMAGE:-ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest}"
OPT="${CRYPTO_OPT:-3}"
docker run --rm -u "$(id -u):$(id -g)" -v "$ROOT:/w" -w /w "$IMAGE" bash -c "
set -e
mkdir -p tools/emu/build
F='--sysroot=/usr/lib/arm-none-eabi --target=arm-none-eabi -mcpu=cortex-m35p+nodsp -mthumb -mlittle-endian -msoft-float -fropi -frwpi -ffreestanding -fno-builtin -fomit-frame-pointer -mno-unaligned-access -Wall -Wextra'
S=ledger-app/src/crypto
clang \$F -O$OPT -c \$S/blake2s.c -o tools/emu/build/blake2s.o
clang \$F -O$OPT -c \$S/sha256.c -o tools/emu/build/sha256.o
clang \$F -O2 -c tools/emu/shim.c -o tools/emu/build/shim.o
clang \$F -c \$S/blake2s_thumb2.S -o tools/emu/build/blake2s_thumb2.o
clang \$F -c \$S/sha256_thumb2.S -o tools/emu/build/sha256_thumb2.o
ld.lld-21 -T tools/emu/emu.ld tools/emu/build/*.o -o tools/emu/build/emu.elf
llvm-nm -S --size-sort tools/emu/build/emu.elf | grep -E 'compress'
"
