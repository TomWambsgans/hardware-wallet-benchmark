#!/usr/bin/env bash
# Install the built app on a USB-connected, unlocked Nano S Plus, then open it.
# The device asks to allow the unsigned manager, then to confirm the install: accept both.
# A running app is closed first; an earlier PQ Bench is replaced.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/ledger-app/build/nanos2/bin"
PY="$ROOT/.venv/bin/python"

cd "$ROOT/host"
"$PY" - <<'PYEOF'
import time
from ledger_hid import Ledger
d = Ledger()
if d.running_app()[0] != "BOLOS":
    d.quit_app()
    d.close()
    time.sleep(2)
    d = Ledger()
v = d.device_version()
d.close()
print(f"device: target {v['target_id']}, firmware {v['se_version']}")
if v["target_id"] != "0x33100004" or not v["se_version"].startswith("1.6."):
    raise SystemExit("expected a Nano S Plus (0x33100004) on firmware 1.6.x, the SDK this repo builds with")
PYEOF
"$PY" -m ledgerblue.runScript --scp --fileName "$BIN/app.apdu" --elfFile "$BIN/app.elf" 2>&1 | grep -v "b'04"
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
        name = d.running_app()[0]
        d.close()
        if name == "PQ Bench":
            print("PQ Bench is open")
            break
    except ApduError:
        d.close()
else:
    raise SystemExit("could not open PQ Bench: open it on the device")
PYEOF
