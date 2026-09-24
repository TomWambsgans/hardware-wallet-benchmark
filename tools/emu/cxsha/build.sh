#!/usr/bin/env bash
# Build the SDK's own SHA-256 (lib_cxng/src/cx_sha256.c, the source of the OS
# library) for Unicorn at -Oz and -O3, with a byte-wise and a word-wise memmove.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
IMAGE="${IMAGE:-ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest}"
for OPT in z 3; do for MM in byte word; do
docker run --rm -u "$(id -u):$(id -g)" -v "$ROOT:/w" -w /w "$IMAGE" bash -c "
set -e
S=.sdk/API_LEVEL_26
F=\"--sysroot=/usr/lib/arm-none-eabi --target=arm-none-eabi -mcpu=cortex-m35p+nodsp -mthumb -msoft-float -fropi -frwpi -ffreestanding -fno-builtin -mno-unaligned-access -DHAVE_SHA256 -DHAVE_SHA224 -DHAVE_HASH -DARCH_LITTLE_ENDIAN -Itools/emu/cxsha -I\$S/lib_cxng/include -I\$S/lib_cxng/src -I\$S/include -I\$S/target/nanos2/include -Wno-everything\"
D=tools/emu/cxsha/build-$OPT-$MM; mkdir -p \$D
clang \$F -O$OPT -c \$S/lib_cxng/src/cx_sha256.c -o \$D/cx_sha256.o
clang \$F -O$OPT -c \$S/lib_cxng/src/cx_utils.c -o \$D/cx_utils.o
clang \$F -O2 $([ $MM = word ] && echo -DWORD_MEMMOVE) -c tools/emu/cxsha/shim.c -o \$D/shim.o
ld.lld-21 -T tools/emu/emu.ld \$D/cx_sha256.o \$D/cx_utils.o \$D/shim.o -o \$D/cx.elf 2>&1 | grep -v 'entry symbol' || true
"
done; done
