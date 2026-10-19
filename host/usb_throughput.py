"""USB throughput between the host and the Nano S Plus (PQ Bench open): the cost of moving
proof data, e.g. for a verifier on the device.

    .venv/bin/python host/usb_throughput.py      # -> results/usb-nanosp.json

host -> device: NOP APDUs carrying n bytes (the app ignores them), n = 0..255.
device -> host: GET_SIG APDUs, each returning 240 bytes of the signature buffer.
Each APDU is a full round trip (HID reports of 64 bytes, framing included).
"""

from __future__ import annotations

import datetime
import json
import pathlib
import statistics
import time

from ledger_hid import Ledger

CLA, INS_GET_SIG, INS_NOP = 0xE0, 0x04, 0x06
REPS = 200
REPO = pathlib.Path(__file__).resolve().parent.parent


def median_s(fn) -> float:
    times = []
    for _ in range(REPS):
        t0 = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t0)
    return statistics.median(times)


def main():
    dev = Ledger()
    name, _ = dev.running_app()
    if name != "PQ Bench":
        raise SystemExit(f"open PQ Bench on the device first (running: {name})")
    res = {"date": datetime.datetime.now().isoformat(timespec="seconds"), "device": "Ledger Nano S Plus",
           "apdus_per_point": REPS, "host_to_device": {}, "device_to_host": {}}

    print("host -> device (NOP with n data bytes)")
    for n in (0, 32, 57, 58, 121, 122, 185, 186, 249, 250, 255):
        s = median_s(lambda: dev.apdu(CLA, INS_NOP, 0, 0, bytes(n)))
        res["host_to_device"][n] = s * 1e3
        print(f"  {n:3d} B: {s * 1e3:5.2f} ms per APDU -> {n / s / 1e3:5.1f} KB/s")

    print("device -> host (GET_SIG, 240 bytes)")
    s = median_s(lambda: dev.apdu(CLA, INS_GET_SIG, 0))
    res["device_to_host"][240] = s * 1e3
    print(f"  240 B: {s * 1e3:5.2f} ms per APDU -> {240 / s / 1e3:5.1f} KB/s")
    dev.close()

    best_in = max(n / (ms / 1e3) for n, ms in res["host_to_device"].items() if n)
    res["host_to_device_max_bytes_per_s"] = best_in
    res["device_to_host_bytes_per_s"] = 240 / (res["device_to_host"][240] / 1e3)
    out = REPO / "results" / "usb-nanosp.json"
    out.write_text(json.dumps(res, indent=2) + "\n")
    print(f"max host -> device {best_in / 1e3:.1f} KB/s; wrote {out.relative_to(REPO)}")


if __name__ == "__main__":
    main()
