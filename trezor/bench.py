"""Benchmark SPHINCS+ on a Trezor Safe 3 running the prodtest firmware of trezor/build.sh.

    .venv/bin/python trezor/bench.py                  # both hashes -> results/trezor-safe3.json
    .venv/bin/python trezor/bench.py --hash sha256 --sigs 1

Talks to prodtest's text command line over its USB serial port. For each hash:
compression throughput; keygen on the seed of vectors/<hash>.json, public key checked;
the vector messages signed and compared byte for byte; --sigs random messages signed
and verified with the Python reference. Timings are the device's CPU cycles.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import statistics
import subprocess
import sys
import time

import serial
from serial.tools import list_ports

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "host"))
import sphincs_ref  # noqa: E402

CPU_HZ = 160_000_000  # STM32U585 as configured by the Trezor firmware (systick_cycles)


class Prodtest:
    def __init__(self, port: str | None = None):
        if port is None:
            ports = [p.device for p in list_ports.comports() if p.vid == 0x1209]
            if not ports:
                raise SystemExit("no Trezor serial port found: is the prodtest firmware running?")
            port = ports[0]
        self.port = port
        self.ser = serial.Serial(port, 115200, timeout=600)
        self.ser.reset_input_buffer()

    def cmd(self, line: str) -> tuple[list[str], list[str]]:
        """Send a command; return (OK fields, PROGRESS lines)."""
        self.ser.write((line + "\r\n").encode())
        progress = []
        while True:
            reply = self.ser.readline().decode(errors="replace").strip()
            if not reply:
                raise TimeoutError(f"no reply to {line.split()[0]}")
            if reply.startswith("OK"):
                return reply.split()[1:], progress
            if reply.startswith("ERROR"):
                raise RuntimeError(f"{line.split()[0]}: {reply}")
            if reply.startswith("PROGRESS"):
                progress.append(reply)
            # '#' traces and the echo of interactive mode are ignored

    @staticmethod
    def cycles(hi: str, lo: str) -> int:
        return (int(hi) << 32) | int(lo)


def run(dev: Prodtest, hash_name: str, n_random: int) -> dict:
    ref = sphincs_ref.Sphincs(hash_name)
    vectors = sphincs_ref.load_vectors(hash_name)
    r = {}

    count = 50000
    t0 = time.perf_counter()
    hi, lo, _ = dev.cmd(f"sphincs-bench {hash_name} {count}")[0]
    wall = time.perf_counter() - t0
    cyc = dev.cycles(hi, lo) / count
    r["measured_hz"] = dev.cycles(hi, lo) / wall  # slightly low: includes the USB round trip
    assert abs(r["measured_hz"] / CPU_HZ - 1) < 0.05, f"CPU clock is not {CPU_HZ} Hz: {r['measured_hz']:.0f}"
    r["compression_cycles"], r["compression_us"] = cyc, cyc / CPU_HZ * 1e6
    print(f"{hash_name}: {cyc:.0f} cycles = {r['compression_us']:.2f} us per compression "
          f"({CPU_HZ / cyc:,.0f}/s)")

    seed = vectors[0]["seed"]
    pp, root, hi, lo, comps = dev.cmd(f"sphincs-keygen {hash_name} {seed.hex()}")[0]
    assert (bytes.fromhex(pp), bytes.fromhex(root)) == (vectors[0]["public_param"], vectors[0]["root"]), \
        "public key differs from the vector"
    r["keygen_s"], r["keygen_compressions"] = dev.cycles(hi, lo) / CPU_HZ, int(comps)
    print(f"  keygen {r['keygen_s']:.2f} s ({int(comps):,} compressions), public key = vector's")

    def sign(msg: bytes):
        (hi, lo, comps, *_), progress = dev.cmd(f"sphincs-sign {hash_name} {msg.hex()}")
        sig = b"".join(bytes.fromhex(p.split()[3]) for p in progress if p.split()[1] == "sig")
        return sig, dev.cycles(hi, lo) / CPU_HZ, int(comps)

    r["signatures"] = []
    for v in (v for v in vectors if v["seed"] == seed):
        sig, dt, comps = sign(v["message"])
        assert sig == v["signature"], "signature differs from the vector"
        r["signatures"].append({"message": "vector", "s": dt, "compressions": comps})
        print(f"  sign {dt:5.2f} s ({comps:,} compressions), vector message: identical to the vector")
    for _ in range(n_random):
        msg = os.urandom(32)
        sig, dt, comps = sign(msg)
        assert ref.verify(bytes.fromhex(pp), bytes.fromhex(root), msg, sig), "signature does not verify"
        r["signatures"].append({"message": msg.hex(), "s": dt, "compressions": comps})
        print(f"  sign {dt:5.2f} s ({comps:,} compressions), random message: verifies")
    times = [s["s"] for s in r["signatures"]]
    r["sign_s_mean"], r["sign_s_min"], r["sign_s_max"] = statistics.fmean(times), min(times), max(times)
    return r


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--hash", choices=["blake2s", "sha256", "both"], default="both")
    p.add_argument("--sigs", type=int, default=3, help="random-message signatures per hash (default 3)")
    p.add_argument("--port", help="serial port (default: the first Trezor one)")
    p.add_argument("--out", default="results/trezor-safe3.json")
    args = p.parse_args()

    dev = Prodtest(args.port)
    commit = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"], capture_output=True,
                            text=True).stdout.strip()
    res = {"date": datetime.datetime.now().isoformat(timespec="seconds"), "device": "Trezor Safe 3 (T3B1)",
           "firmware": "prodtest + SPHINCS+ commands (trezor/build.sh)", "cpu_hz": CPU_HZ,
           "repo_commit": commit, "hashes": {}}
    for h in ["blake2s", "sha256"] if args.hash == "both" else [args.hash]:
        res["hashes"][h] = run(dev, h, args.sigs)

    print(f"\n{'hash':8s} {'compression':>16s} {'per second':>11s} {'keygen':>8s} {'sign (mean, min-max)':>24s}")
    for h, r in res["hashes"].items():
        print(f"{h:8s} {r['compression_us']:6.2f} us ({r['compression_cycles']:4.0f} c) "
              f"{1e6 / r['compression_us']:11,.0f} {r['keygen_s']:6.2f} s "
              f"{r['sign_s_mean']:8.2f} s ({r['sign_s_min']:.2f}-{r['sign_s_max']:.2f})")
    out = REPO / args.out
    out.write_text(json.dumps(res, indent=2) + "\n")
    print(f"wrote {out.relative_to(REPO)}")


if __name__ == "__main__":
    main()
