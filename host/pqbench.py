"""Benchmark the PQ Bench app on a Nano S Plus (the app must be open: scripts/load.sh does it).

    .venv/bin/python host/pqbench.py                 # both hashes -> results/nanosp.json
    .venv/bin/python host/pqbench.py --hash sha256 --sigs 1

For each hash:
  1. compression throughput (BENCH, minus the USB round trip of a no-op APDU);
  2. keygen on the seed of vectors/<hash>.json, public key checked against it;
  3. the vector messages signed, signatures compared byte for byte;
  4. --sigs random messages signed, each verified with the Python reference.
Timings are host wall-clock around each APDU minus the USB round trip.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import statistics
import subprocess
import time

import sphincs_ref
from ledger_hid import Ledger

CLA = 0xE0
INS_INFO, INS_KEYGEN, INS_SIGN, INS_GET_SIG, INS_BENCH, INS_NOP = range(1, 7)
HASHES = {"blake2s": 0, "sha256": 1}
SIG_CHUNK = 240
REPO = pathlib.Path(__file__).resolve().parent.parent


def be32(b: bytes, i: int) -> int:
    return int.from_bytes(b[4 * i : 4 * i + 4], "big")


class App:
    def __init__(self):
        self.dev = Ledger()
        name, version = self.dev.running_app()
        if name != "PQ Bench":
            raise SystemExit(f"open PQ Bench on the device first (running: {name}); scripts/load.sh opens it")
        self.version = version
        self.rtt = statistics.median(self.timed(INS_NOP)[1] for _ in range(50))

    def timed(self, ins: int, p1: int = 0, data: bytes = b""):
        t0 = time.perf_counter()
        out = self.dev.apdu(CLA, ins, p1, 0, data, timeout_s=600)
        return out, time.perf_counter() - t0

    def compression_us(self, hash_id: int, count: int = 4000) -> float:
        _, dt = self.timed(INS_BENCH, hash_id, count.to_bytes(4, "big"))
        return (dt - self.rtt) / count * 1e6

    def keygen(self, hash_id: int, seed: bytes):
        out, dt = self.timed(INS_KEYGEN, hash_id, seed)
        return out[:16], out[16:32], be32(out, 8), dt - self.rtt

    def sign(self, hash_id: int, msg: bytes):
        out, dt = self.timed(INS_SIGN, hash_id, msg)
        sig = b"".join(self.dev.apdu(CLA, INS_GET_SIG, i) for i in range(-(-sphincs_ref.SIG_SIZE // SIG_CHUNK)))
        return sig, be32(out, 0), dt - self.rtt


def run(app: App, hash_name: str, n_random: int) -> dict:
    hid = HASHES[hash_name]
    ref = sphincs_ref.Sphincs(hash_name)
    vectors = sphincs_ref.load_vectors(hash_name)
    r = {"compression_us": app.compression_us(hid)}
    print(f"{hash_name}: {r['compression_us']:.1f} us per compression ({1e6 / r['compression_us']:,.0f}/s)")

    seed = vectors[0]["seed"]
    pp, root, comps, dt = app.keygen(hid, seed)
    assert (pp, root) == (vectors[0]["public_param"], vectors[0]["root"]), "public key differs from the vector"
    r["keygen_s"], r["keygen_compressions"] = dt, comps
    print(f"  keygen {dt:.1f} s ({comps:,} compressions), public key = vector's")

    r["signatures"] = []
    for v in (v for v in vectors if v["seed"] == seed):
        sig, comps, dt = app.sign(hid, v["message"])
        assert sig == v["signature"], "signature differs from the vector"
        r["signatures"].append({"message": "vector", "s": dt, "compressions": comps})
        print(f"  sign {dt:5.2f} s ({comps:,} compressions), vector message: identical to the vector")
    for _ in range(n_random):
        msg = os.urandom(32)
        sig, comps, dt = app.sign(hid, msg)
        assert ref.verify(pp, root, msg, sig), "signature does not verify"
        r["signatures"].append({"message": msg.hex(), "s": dt, "compressions": comps})
        print(f"  sign {dt:5.2f} s ({comps:,} compressions), random message: verifies")
    times = [s["s"] for s in r["signatures"]]
    r["sign_s_mean"], r["sign_s_min"], r["sign_s_max"] = statistics.fmean(times), min(times), max(times)
    return r


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--hash", choices=[*HASHES, "both"], default="both")
    p.add_argument("--sigs", type=int, default=3, help="random-message signatures per hash (default 3)")
    p.add_argument("--out", default="results/nanosp.json")
    args = p.parse_args()

    app = App()
    commit = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"], capture_output=True,
                            text=True).stdout.strip()
    res = {"date": datetime.datetime.now().isoformat(timespec="seconds"), "device": "Ledger Nano S Plus",
           "app_version": app.version, "repo_commit": commit, "usb_roundtrip_ms": app.rtt * 1e3, "hashes": {}}
    for h in HASHES if args.hash == "both" else [args.hash]:
        res["hashes"][h] = run(app, h, args.sigs)
    app.dev.close()

    print(f"\n{'hash':8s} {'compression':>12s} {'per second':>11s} {'keygen':>8s} {'sign (mean, min-max)':>24s}")
    for h, r in res["hashes"].items():
        print(f"{h:8s} {r['compression_us']:9.1f} us {1e6 / r['compression_us']:11,.0f} {r['keygen_s']:6.1f} s "
              f"{r['sign_s_mean']:8.2f} s ({r['sign_s_min']:.2f}-{r['sign_s_max']:.2f})")
    out = REPO / args.out
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(res, indent=2) + "\n")
    print(f"wrote {out.relative_to(REPO)}")


if __name__ == "__main__":
    main()
