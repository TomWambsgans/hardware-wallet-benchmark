"""Host client for the PQ Bench Ledger app (see doc/PROTOCOL.md).

    .venv/bin/python host/pqbench.py info
    .venv/bin/python host/pqbench.py hashcheck                 # device BLAKE2s == host, every implementation
    .venv/bin/python host/pqbench.py micro                     # per-compression / per-hash / per-leaf timings
    .venv/bin/python host/pqbench.py vector                    # leanVM vectors reproduced on the device
    .venv/bin/python host/pqbench.py bench --sigs 5 --label o3 # keygen + signing -> results/<date>-<label>.json

Every signature the device returns is compared byte for byte with the Python
reference signer (itself checked against leanVM), and verified.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import statistics
import subprocess
import time

import sphincs_ref as ref
from ledger_hid import ApduError, Ledger

CLA = 0xE0
INS_INFO, INS_KEYGEN, INS_SIGN, INS_GET_SIG, INS_BENCH, INS_NOP, INS_HASH, INS_CONFIG = range(1, 9)
IMPLS = {0: "blake2s-ref", 1: "blake2s-unrolled"}
SIG_CHUNK = 240
LONG = 1800.0  # seconds: key generation is 1.38M hashes

REPO = pathlib.Path(__file__).resolve().parent.parent


def be32(b: bytes, i: int) -> int:
    return int.from_bytes(b[4 * i : 4 * i + 4], "big")


class App:
    def __init__(self):
        self.dev = Ledger()
        name, version = self.dev.running_app()
        if name != "PQ Bench":
            raise SystemExit(f"open the PQ Bench app on the device first (running: {name} {version})")

    def info(self) -> dict:
        b = self.dev.apdu(CLA, INS_INFO)
        return {
            "app_version": f"{b[0]}.{b[1]}.{b[2]}",
            "impls": b[3],
            "impl": b[4],
            "have_key": bool(b[5]),
            "yield": bool(b[6]),
            "crypto_opt": "-O" + b[7:].rstrip(b"\x00").decode(),
        }

    def timed(self, ins: int, p1: int = 0, p2: int = 0, data: bytes = b"", timeout_s: float = LONG):
        t0 = time.perf_counter()
        out = self.dev.apdu(CLA, ins, p1, p2, data, timeout_s)
        return out, time.perf_counter() - t0

    def nop_latency(self, n: int = 50) -> float:
        return statistics.median(self.timed(INS_NOP, timeout_s=5)[1] for _ in range(n))

    def set_yield(self, on: bool):
        self.dev.apdu(CLA, INS_CONFIG, int(on))

    def keygen(self, impl: int, seed: bytes = b""):
        out, dt = self.timed(INS_KEYGEN, impl, data=seed)
        return {"pp": out[:16], "root": out[16:32], "hashes": be32(out, 8), "compressions": be32(out, 9), "s": dt}

    def sign(self, impl: int, msg: bytes):
        out, dt = self.timed(INS_SIGN, impl, data=msg)
        return {"hashes": be32(out, 0), "compressions": be32(out, 1), "digest_trials": be32(out, 2),
                "counters": [be32(out, 3 + i) for i in range(3)], "s": dt}

    def get_sig(self) -> bytes:
        n = -(-ref.SIG_SIZE // SIG_CHUNK)
        return b"".join(self.dev.apdu(CLA, INS_GET_SIG, i) for i in range(n))

    def bench(self, impl: int, mode: int, count: int):
        out, dt = self.timed(INS_BENCH, impl, mode, count.to_bytes(4, "big"))
        return be32(out, 4), be32(out, 5), dt

    def hash(self, impl: int, data: bytes) -> bytes:
        return self.dev.apdu(CLA, INS_HASH, impl, data=data)


def impls_arg(s: str) -> list[int]:
    return list(IMPLS) if s == "all" else [int(x) for x in s.split(",")]


def cmd_info(app: App, _args):
    print(json.dumps(app.info(), indent=2))


def cmd_hashcheck(app: App, args):
    for i in impls_arg(args.impls):
        for n in list(range(0, 256, 17)) + [63, 64, 65, 128, 255]:
            data = os.urandom(n)
            assert app.hash(i, data) == hashlib.blake2s(data).digest(), f"{IMPLS[i]}: BLAKE2s mismatch at {n} bytes"
        print(f"{IMPLS[i]}: BLAKE2s-256 matches hashlib on 21 lengths")


def micro(app: App, impl: int, nop: float, n: int) -> dict:
    r = {}
    _, comps, dt = app.bench(impl, 1, n)
    r["compression_us"] = (dt - nop) / comps * 1e6
    _, comps, dt = app.bench(impl, 0, n)
    r["chain_step_us"] = (dt - nop) / comps * 1e6
    leaves = max(1, n // 400)
    hashes, comps, dt = app.bench(impl, 2, leaves)
    r["ots_leaf_ms"] = (dt - nop) / leaves * 1e3
    r["ots_leaf_hashes"], r["ots_leaf_compressions"] = hashes // leaves, comps // leaves
    return r


def cmd_micro(app: App, args):
    app.set_yield(args.yield_)
    nop = app.nop_latency()
    print(f"usb round trip {nop * 1e3:.2f} ms")
    for i in impls_arg(args.impls):
        r = micro(app, i, nop, args.n)
        print(f"{IMPLS[i]:18s} compression {r['compression_us']:6.1f} us   chain step {r['chain_step_us']:6.1f} us"
              f"   WOTS leaf {r['ots_leaf_ms']:6.1f} ms ({r['ots_leaf_hashes']} hashes)")


def check_signature(app: App, name: str, key: tuple, msg: bytes) -> dict:
    """Fetch the device's last signature; compare with the reference signer and verify."""
    pp, root, seed, cache = key
    sig = app.get_sig()
    want, stats = ref.sign(pp, root, seed, cache, msg)
    assert sig == want, f"{name}: signature differs from the reference signer"
    assert ref.verify(pp, root, msg, sig), f"{name}: signature does not verify"
    return stats


def cmd_vector(app: App, args):
    app.set_yield(args.yield_)
    vectors = ref.load_vectors()
    seeds = list(dict.fromkeys(v["seed"] for v in vectors))[: args.keys]
    for i in impls_arg(args.impls):
        for seed in seeds:
            kg = app.keygen(i, seed)
            vs = [v for v in vectors if v["seed"] == seed]
            assert (kg["pp"], kg["root"]) == (vs[0]["public_param"], vs[0]["root"]), f"{IMPLS[i]}: public key mismatch"
            print(f"{IMPLS[i]}: key {seed[:4].hex()}.. matches leanVM (keygen {kg['s']:.1f} s, {kg['hashes']} hashes)")
            for v in vs:
                s = app.sign(i, v["message"])
                assert app.get_sig() == v["signature"], f"{IMPLS[i]}: signature differs from leanVM's"
                print(f"  message {v['message'][:4].hex()}..: signature identical to leanVM's "
                      f"(sign {s['s']:.1f} s, {s['hashes']} hashes, counters {s['counters']})")


def git_rev(path: pathlib.Path) -> str:
    try:
        return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return "unknown"


def cmd_bench(app: App, args):
    app.set_yield(args.yield_)
    info = app.info()
    nop = app.nop_latency()
    res = {
        "date": datetime.datetime.now().isoformat(timespec="seconds"),
        "label": args.label,
        "device": args.device,
        "firmware": args.firmware,
        "app": info,
        "yield": args.yield_,
        "repo_commit": git_rev(REPO),
        "sdk_commit": git_rev(REPO / ".sdk" / "API_LEVEL_26"),
        "scheme": "leanVM SPHINCS+ (BLAKE2s, WOTS+C w=3 v=42 T=191, d=3 (12,7,7), FORS+C a=10 k=15), sig 4924 B",
        "usb_nop_roundtrip_ms": nop * 1e3,
        "impls": {},
    }
    print(f"{info}  usb round trip {nop * 1e3:.2f} ms  yield={'on' if args.yield_ else 'off'}")
    for i in impls_arg(args.impls):
        name = IMPLS[i]
        r = micro(app, i, nop, args.micro_n)
        print(f"{name}: compression {r['compression_us']:.1f} us, chain step {r['chain_step_us']:.1f} us, "
              f"WOTS leaf {r['ots_leaf_ms']:.1f} ms")
        # Keygen on a host-chosen seed, checked against the reference.
        seed = os.urandom(32)
        kg = app.keygen(i, seed)
        pp, root, cache = ref.key_gen_from_seed(seed)
        assert (kg["pp"], kg["root"]) == (pp, root), f"{name}: keygen mismatch"
        r["keygen_s"] = kg["s"] - nop
        r["keygen_hashes"], r["keygen_compressions"] = kg["hashes"], kg["compressions"]
        print(f"  keygen {r['keygen_s']:.1f} s ({kg['hashes']} hashes, {kg['compressions']} compressions), matches reference")
        sigs = []
        for _ in range(args.sigs):
            msg = os.urandom(32)
            s = app.sign(i, msg)
            stats = check_signature(app, name, (pp, root, seed, cache), msg)
            assert stats["counters"] == s["counters"] and stats["digest_trials"] == s["digest_trials"]
            s["s"] -= nop
            sigs.append(s)
            print(f"  sign {s['s']:6.2f} s  {s['hashes']:6d} hashes {s['compressions']:6d} compressions  "
                  f"digest trials {s['digest_trials']:4d}  counters {s['counters']}  identical to reference, verifies")
        r["signatures"] = sigs
        times = [s["s"] for s in sigs]
        r["sign_s_median"] = statistics.median(times)
        r["sign_s_mean"] = statistics.fmean(times)
        r["sign_hashes_mean"] = statistics.fmean(s["hashes"] for s in sigs)
        r["sign_us_per_compression"] = sum(times) / sum(s["compressions"] for s in sigs) * 1e6
        res["impls"][name] = r
        print(f"  => sign mean {r['sign_s_mean']:.2f} s, median {r['sign_s_median']:.2f} s over {len(sigs)} "
              f"({r['sign_us_per_compression']:.1f} us per compression)")
    out = REPO / "results" / f"{datetime.date.today()}-{args.label}.json"
    out.write_text(json.dumps(res, indent=2) + "\n")
    print(f"wrote {out.relative_to(REPO)}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info")
    for name in ("hashcheck", "micro", "vector", "bench"):
        s = sub.add_parser(name)
        s.add_argument("--impls", default="all", help="comma-separated ids (0 blake2s-ref, 1 blake2s-unrolled) or 'all'")
        if name in ("micro", "vector", "bench"):
            s.add_argument("--yield", dest="yield_", action="store_true",
                           help="service the event loop during computations (blocks up to 100 ms per call)")
        if name == "micro":
            s.add_argument("--n", type=int, default=4000)
        if name == "vector":
            s.add_argument("--keys", type=int, default=1, help="how many of the vector keys to regenerate (1.38M hashes each)")
        if name == "bench":
            s.add_argument("--sigs", type=int, default=5)
            s.add_argument("--micro-n", type=int, default=4000)
            s.add_argument("--label", default="run")
            s.add_argument("--device", default="Ledger Nano S Plus")
            s.add_argument("--firmware", default="1.6.1")
    args = p.parse_args()
    app = App()
    try:
        {"info": cmd_info, "hashcheck": cmd_hashcheck, "micro": cmd_micro, "vector": cmd_vector, "bench": cmd_bench}[args.cmd](app, args)
    except ApduError as e:
        raise SystemExit(f"device error: {e}")
    finally:
        app.dev.close()


if __name__ == "__main__":
    main()
