#!/usr/bin/env bash
# Build the Ledger app for the Nano S Plus in Ledger's app-builder image, against the
# secure SDK for firmware 1.6.x (API level 26). Both are pinned to what produced
# results/nanosp.json. Output: ledger-app/build/nanos2/bin/app.{elf,apdu}
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite@sha256:442b6fa0407e243333a1be723f6d817c775ac78db198b56f63b833acf0930160"
SDK_COMMIT="d56084c98523794c7920ca5c5b55a703381ba680"  # ledger-secure-sdk, branch API_LEVEL_26
SDK_DIR="$ROOT/.sdk"

if [ "$(git -C "$SDK_DIR" rev-parse HEAD 2>/dev/null)" != "$SDK_COMMIT" ]; then
    rm -rf "$SDK_DIR"
    git init -q "$SDK_DIR"
    git -C "$SDK_DIR" fetch -q --depth 1 https://github.com/LedgerHQ/ledger-secure-sdk.git "$SDK_COMMIT"
    git -C "$SDK_DIR" checkout -q FETCH_HEAD
fi

mkdir -p "$ROOT/ledger-app/glyphs"  # the SDK writes the home-screen icon there
docker run --rm -u "$(id -u):$(id -g)" -v "$ROOT:/work" -w /work/ledger-app \
    -e BOLOS_SDK=/work/.sdk -e TARGET=nanos2 "$IMAGE" \
    bash -c "set -o pipefail; make clean >/dev/null 2>&1 && make -j 2>&1 | grep -v 'No names found'"
