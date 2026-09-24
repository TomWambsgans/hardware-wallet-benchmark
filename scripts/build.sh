#!/usr/bin/env bash
# Build the Ledger app for the Nano S Plus inside Ledger's app-builder image.
#
#   scripts/build.sh                 # crypto at -O3 (default)
#   scripts/build.sh CRYPTO_OPT=z    # crypto at the SDK's default -Oz
#
# The SDK branch must match the device firmware's API level (see README.md).
# Output: ledger-app/build/nanos2/bin/app.elf (+ app.apdu, app.hex).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${IMAGE:-ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest}"
SDK_BRANCH="${SDK_BRANCH:-API_LEVEL_26}"
SDK_DIR="$ROOT/.sdk/$SDK_BRANCH"

if [ ! -d "$SDK_DIR" ]; then
    git clone --depth 1 -b "$SDK_BRANCH" https://github.com/LedgerHQ/ledger-secure-sdk.git "$SDK_DIR"
fi
git -C "$SDK_DIR" log -1 --format='SDK %H (%cd)'

# The SDK writes the generated home-screen icon here.
mkdir -p "$ROOT/ledger-app/glyphs"

docker run --rm -u "$(id -u):$(id -g)" \
    -v "$ROOT:/work" -w /work/ledger-app \
    -e BOLOS_SDK="/work/.sdk/$SDK_BRANCH" -e TARGET=nanos2 \
    "$IMAGE" \
    bash -c "make clean >/dev/null && make -j VERBOSE=${VERBOSE:-} $*"

ls -la "$ROOT/ledger-app/build/nanos2/bin/"
