#!/usr/bin/env bash
# Build the leanVM Verify app for the Nano S Plus: the Rust verifier as a static library (rustup, the
# nightly ffi/rust-toolchain.toml pins), then the C app in Ledger's app-builder image, against the same
# pinned SDK as PQ Bench (scripts/build.sh). Output: ledger/app/build/nanos2/bin/app.{elf,apdu}
set -euo pipefail

LEDGER="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$LEDGER/../.." && pwd)"
IMAGE="ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite@sha256:442b6fa0407e243333a1be723f6d817c775ac78db198b56f63b833acf0930160"
SDK_COMMIT="d56084c98523794c7920ca5c5b55a703381ba680"  # ledger-secure-sdk, branch API_LEVEL_26
SDK_DIR="$ROOT/.sdk"

# 1. The verifier, for the device's Cortex-M35P (no DSP extension), position independent like the app (ROPI/RWPI);
#    a panic is an abort, so no panic machinery (and its pointer tables) reaches the flash.
(
    cd "$LEDGER/ffi"
    RUSTFLAGS="-C relocation-model=ropi-rwpi -C target-cpu=cortex-m35p -C target-feature=-dsp -Zunstable-options -Cpanic=immediate-abort" \
        cargo build --release --target thumbv8m.main-none-eabi -Zbuild-std=core
)

# 2. The app.
if [ "$(git -C "$SDK_DIR" rev-parse HEAD 2>/dev/null)" != "$SDK_COMMIT" ]; then
    rm -rf "$SDK_DIR"
    git init -q "$SDK_DIR"
    git -C "$SDK_DIR" fetch -q --depth 1 https://github.com/LedgerHQ/ledger-secure-sdk.git "$SDK_COMMIT"
    git -C "$SDK_DIR" checkout -q FETCH_HEAD
fi
rm -rf "$LEDGER/app/glyphs" && mkdir -p "$LEDGER/app/glyphs"
docker run --rm -u "$(id -u):$(id -g)" -v "$ROOT:/work" -w /work/leanvm-pow/ledger/app \
    -e BOLOS_SDK=/work/.sdk -e TARGET=nanos2 "$IMAGE" \
    bash -c "set -o pipefail; make clean >/dev/null 2>&1 && make -j 2>&1 | grep -v 'No names found'"
