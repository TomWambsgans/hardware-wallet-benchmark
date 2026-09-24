#!/usr/bin/env bash
# Sideload the built app onto a USB-connected, unlocked Nano S Plus. A running
# app is closed first (the install fails silently otherwise). The device asks to
# allow the (unsigned) manager, then shows the app's identifier: accept both. The
# script's first APDU deletes any app with the same name, so re-running replaces
# the previous build. Then the app is opened.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/ledger-app/build/nanos2/bin"
PY="${PY:-$ROOT/.venv/bin/python}"

cd "$ROOT/host"
"$PY" - <<'PYEOF'
import time
from ledger_hid import Ledger
d = Ledger()
name, _ = d.running_app()
if name != "BOLOS":
    d.quit_app()
    d.close()
    time.sleep(2)
    d = Ledger()
    name, _ = d.running_app()
d.close()
assert name == "BOLOS", f"still running {name}"
PYEOF
"$PY" -m ledgerblue.runScript --scp --fileName "$BIN/app.apdu" --elfFile "$BIN/app.elf"
"$PY" - <<'PYEOF'
import time
from ledger_hid import ApduError, Ledger
d = Ledger()
d.open_app("PQ Bench")
d.close()
for _ in range(10):
    time.sleep(1.5)
    try:
        d = Ledger()
        print("running:", d.running_app())
        d.close()
        break
    except ApduError as e:
        print("waiting for the app:", e)
        d.close()
PYEOF
