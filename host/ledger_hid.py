"""Minimal Ledger USB-HID transport (no ledgerblue dependency for exchanges).

Framing: 64-byte reports, channel 0x0101, tag 0x05, a big-endian sequence
number, and the APDU length on the first packet.
"""

from __future__ import annotations

import struct

import hid

LEDGER_VID = 0x2C97


class ApduError(Exception):
    def __init__(self, sw: int, data: bytes):
        super().__init__(f"status word 0x{sw:04X}")
        self.sw = sw
        self.data = data


class Ledger:
    def __init__(self):
        devs = [d for d in hid.enumerate(LEDGER_VID) if d["interface_number"] == 0 or d["usage_page"] == 0xFFA0]
        if not devs:
            raise RuntimeError("no Ledger device found (plugged in and unlocked?)")
        self.info = devs[0]
        self.dev = hid.device()
        self.dev.open_path(devs[0]["path"])

    def close(self):
        self.dev.close()

    def exchange_raw(self, apdu: bytes, timeout_s: float = 5.0) -> bytes:
        data = struct.pack(">H", len(apdu)) + apdu
        seq = off = 0
        while off < len(data):
            hdr = struct.pack(">HBH", 0x0101, 0x05, seq)
            chunk = data[off : off + 64 - len(hdr)]
            pkt = hdr + chunk
            self.dev.write(b"\x00" + pkt + b"\x00" * (64 - len(pkt)))
            off += len(chunk)
            seq += 1
        resp, seq, total = b"", 0, None
        while total is None or len(resp) < total:
            r = bytes(self.dev.read(64, int(timeout_s * 1000)))
            if not r:
                raise TimeoutError(f"no response within {timeout_s}s")
            if seq == 0:
                total = struct.unpack(">H", r[5:7])[0]
                resp += r[7:]
            else:
                resp += r[5:]
            seq += 1
        return resp[:total]

    def apdu(self, cla: int, ins: int, p1: int = 0, p2: int = 0, data: bytes = b"", timeout_s: float = 5.0) -> bytes:
        raw = self.exchange_raw(bytes([cla, ins, p1, p2, len(data)]) + data, timeout_s)
        sw = int.from_bytes(raw[-2:], "big")
        if sw != 0x9000:
            raise ApduError(sw, raw[:-2])
        return raw[:-2]

    def device_version(self) -> dict:
        """GET_VERSION (dashboard only): target id and firmware versions."""
        b = self.apdu(0xE0, 0x01)
        target, i = b[:4].hex(), 4
        fields = []
        for _ in range(3):
            n = b[i]
            fields.append(b[i + 1 : i + 1 + n])
            i += 1 + n
        return {
            "target_id": "0x" + target,
            "se_version": fields[0].decode(),
            "flags": fields[1].hex(),
            "mcu_version": fields[2].rstrip(b"\x00").decode(),
        }

    def running_app(self) -> tuple[str, str]:
        b = self.apdu(0xB0, 0x01)
        n = b[1]
        name = b[2 : 2 + n].decode()
        m = b[2 + n]
        return name, b[3 + n : 3 + n + m].decode()

    def quit_app(self):
        """Ask the running app to exit to the dashboard (B0 A7, handled by the SDK)."""
        try:
            self.apdu(0xB0, 0xA7)
        except (ApduError, TimeoutError, OSError):
            pass  # the device re-enumerates as the app exits

    def open_app(self, name: str):
        """Ask the dashboard to start an installed app (E0 D8)."""
        try:
            self.apdu(0xE0, 0xD8, data=name.encode(), timeout_s=30)
        except (ApduError, TimeoutError, OSError):
            pass
