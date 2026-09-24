#!/usr/bin/env bash
# Sideload the built app onto a USB-connected, unlocked Nano S Plus sitting on
# its dashboard. The device asks to allow the (unsigned) manager, then shows
# the app's identifier: accept both. The script's first APDU deletes any app
# with the same name, so re-running replaces the previous build.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/ledger-app/build/nanos2/bin"
PY="${PY:-$ROOT/.venv/bin/python}"

"$PY" -m ledgerblue.runScript --scp --fileName "$BIN/app.apdu" --elfFile "$BIN/app.elf"
