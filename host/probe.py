"""Print what is plugged in: USB ids, target, firmware, and the running app.

    .venv/bin/python host/probe.py
"""

import hid

from ledger_hid import LEDGER_VID, ApduError, Ledger

for d in hid.enumerate(LEDGER_VID):
    print(f"usb: pid=0x{d['product_id']:04x} iface={d['interface_number']} product={d['product_string']!r}")

dev = Ledger()
name, version = dev.running_app()
print(f"running app: {name} {version}")
if name == "BOLOS":
    try:
        print("device:", dev.device_version())
    except ApduError as e:
        print("GET_VERSION failed:", e)
dev.close()
