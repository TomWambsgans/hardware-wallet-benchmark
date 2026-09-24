"""Host client for the PQ Bench Ledger app (see doc/PROTOCOL.md).

    .venv/bin/python host/pqbench.py info
    .venv/bin/python host/pqbench.py hashcheck                 # device BLAKE2s == hashlib
    .venv/bin/python host/pqbench.py compcheck                 # every compression function == Python reference
    .venv/bin/python host/pqbench.py micro                     # clock calibration, compression timings
    .venv/bin/python host/pqbench.py vector                    # leanVM vectors reproduced on the device
    .venv/bin/python host/pqbench.py bench --sigs 5 --label x  # keygen + signing -> results/<date>-<label>.json

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

import struct

import sphincs_ref as ref
from compress_ref import M32, b2s_compress_ref, sha256_compress_ref
from ledger_hid import ApduError, Ledger

CLA = 0xE0
INS_INFO, INS_KEYGEN, INS_SIGN, INS_GET_SIG, INS_BENCH, INS_NOP, INS_HASH, INS_CONFIG, INS_COMPRESS = range(1, 10)
# INS_COMPRESS / INS_BENCH functions (FN_* in main.c), and which are BLAKE2s.
FNS = {0: "blake2s-c", 1: "blake2s-asm", 2: "blake2s-asm2", 3: "blake2s-asm3", 4: "blake2s-asm3r",
       5: "blake2s-asm4r", 6: "sha256-c", 7: "sha256-asm", 8: "sha256-asm2", 9: "sha256-asm3", 10: "sha256-asm3r",
       11: "sha256-os"}
B2S_FNS = (0, 1, 2, 3, 4, 5)
OS_FN = 11
# CONFIG P2: the BLAKE2s implementation the scheme uses.
B2S_IMPLS = {0: "c", 1: "asm", 2: "asm2", 3: "asm3", 4: "asm3r", 5: "asm4r"}
# INS_BENCH modes (P2).
B_CHAIN, B_COMPRESS, B_LEAF, B_PROBE = range(4)
PROBES = json.loads((pathlib.Path(__file__).resolve().parent / "probes.json").read_text())
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
            "have_key": bool(b[3]),
            "yield": bool(b[4]),
            "blake2s": B2S_IMPLS.get(b[5], str(b[5])),
            "crypto_opt": "-O" + b[6:].rstrip(b"\x00").decode(),
        }

    def timed(self, ins: int, p1: int = 0, p2: int = 0, data: bytes = b"", timeout_s: float = LONG):
        t0 = time.perf_counter()
        out = self.dev.apdu(CLA, ins, p1, p2, data, timeout_s)
        return out, time.perf_counter() - t0

    def nop_latency(self, n: int = 50) -> float:
        return statistics.median(self.timed(INS_NOP, timeout_s=5)[1] for _ in range(n))

    def config(self, yield_: bool, b2s_impl: int):
        self.dev.apdu(CLA, INS_CONFIG, int(yield_), b2s_impl)

    def compress(self, fn: int, h: list[int], m: list[int], t: int = 0, f: int = 0) -> list[int]:
        data = struct.pack("<8I16I", *h, *m) + (struct.pack("<II", t, f) if fn in B2S_FNS else b"")
        return list(struct.unpack("<8I", self.dev.apdu(CLA, INS_COMPRESS, fn, data=data)))

    def keygen(self, seed: bytes = b""):
        out, dt = self.timed(INS_KEYGEN, data=seed)
        return {"pp": out[:16], "root": out[16:32], "hashes": be32(out, 8), "compressions": be32(out, 9), "s": dt}

    def sign(self, msg: bytes):
        out, dt = self.timed(INS_SIGN, data=msg)
        return {"hashes": be32(out, 0), "compressions": be32(out, 1), "digest_trials": be32(out, 2),
                "counters": [be32(out, 3 + i) for i in range(3)], "s": dt}

    def get_sig(self) -> bytes:
        n = -(-ref.SIG_SIZE // SIG_CHUNK)
        return b"".join(self.dev.apdu(CLA, INS_GET_SIG, i) for i in range(n))

    def bench(self, mode: int, count: int, p1: int = 0):
        out, dt = self.timed(INS_BENCH, p1, mode, count.to_bytes(4, "big"))
        return be32(out, 4), be32(out, 5), dt

    def per_call_us(self, mode: int, count: int, nop: float, p1: int = 0) -> float:
        return (self.bench(mode, count, p1)[2] - nop) / count * 1e6

    def hash(self, data: bytes) -> bytes:
        return self.dev.apdu(CLA, INS_HASH, data=data)


def cmd_info(app: App, _args):
    print(json.dumps(app.info(), indent=2))


def cmd_hashcheck(app: App, _args):
    for n in list(range(0, 256, 17)) + [63, 64, 65, 128, 255]:
        data = os.urandom(n)
        assert app.hash(data) == hashlib.blake2s(data).digest(), f"BLAKE2s mismatch at {n} bytes"
    print("BLAKE2s-256 matches hashlib on 21 lengths")


def micro(app: App, nop: float, n: int, b2s_impl: int) -> dict:
    """Per-call timings of the scheme's building blocks, with the BLAKE2s implementation given."""
    app.config(False, b2s_impl)
    r = {"blake2s": B2S_IMPLS[b2s_impl]}
    _, comps, dt = app.bench(B_CHAIN, n)
    r["chain_step_us"] = (dt - nop) / comps * 1e6
    leaves = max(1, n // 400)
    hashes, comps, dt = app.bench(B_LEAF, leaves)
    r["ots_leaf_ms"] = (dt - nop) / leaves * 1e3
    r["ots_leaf_hashes"], r["ots_leaf_compressions"] = hashes // leaves, comps // leaves
    return r


def probes(app: App, nop: float, target_insns: int = 4_000_000) -> dict:
    """Cycles per instruction of each timing probe. The clock is taken from probe 0
    (dependent 16-bit adds), assumed to be one cycle each."""
    us_per_iter = {}
    for pr in PROBES:
        iters = max(1, target_insns // pr["insns_per_iter"])
        us_per_iter[pr["id"]] = app.per_call_us(B_PROBE, iters, nop, pr["id"])
    mhz = PROBES[0]["insns_per_iter"] / us_per_iter[0]
    out = {"clock_mhz": mhz}
    for pr in PROBES:
        cycles = us_per_iter[pr["id"]] * mhz
        body = len(pr["body"]) * pr["reps"]
        out[pr["name"]] = {"cycles_per_body_insn": (cycles - (pr["insns_per_iter"] - body)) / body,
                           "body": pr["body"], "reps": pr["reps"]}
    return out


def compressions(app: App, nop: float, n: int) -> dict:
    """Microseconds per compression, every implementation."""
    return {name: app.per_call_us(B_COMPRESS, n if fn != OS_FN else n // 8, nop, fn) for fn, name in FNS.items()}


def cmd_probes(app: App, args):
    nop = app.nop_latency()
    r = probes(app, nop)
    print(f"clock ~{r['clock_mhz']:.1f} MHz (probe 0 = 1 cycle per instruction)")
    for name, v in r.items():
        if name != "clock_mhz":
            print(f"  {name:18s} {v['cycles_per_body_insn']:5.2f} cycles/insn   {' ; '.join(v['body'])}  (x{v['reps']})")
    if args.save:
        out = REPO / "results" / f"{datetime.date.today()}-probes.json"
        out.write_text(json.dumps(r, indent=2) + "\n")
        print(f"wrote {out.relative_to(REPO)}")


def cmd_micro(app: App, args):
    nop = app.nop_latency()
    print(f"usb round trip {nop * 1e3:.2f} ms")
    comp = compressions(app, nop, args.n)
    for name, us in comp.items():
        print(f"  {name:13s} {us:6.1f} us per compression   {1e6 / us:8.0f} per second   {us * 63.3:6.0f} cycles @63.3MHz")
    scheme = {}
    for impl in B2S_IMPLS:
        r = micro(app, nop, args.n, impl)
        scheme[B2S_IMPLS[impl]] = r
        print(f"  scheme with blake2s-{B2S_IMPLS[impl]}: chain step {r['chain_step_us']:.1f} us, "
              f"WOTS leaf {r['ots_leaf_ms']:.2f} ms ({r['ots_leaf_hashes']} hashes)")
    if args.save:
        out = REPO / "results" / f"{datetime.date.today()}-{args.label}.json"
        out.write_text(json.dumps({"date": datetime.datetime.now().isoformat(timespec="seconds"),
                                   "repo_commit": git_rev(REPO), "app": app.info(),
                                   "usb_nop_roundtrip_ms": nop * 1e3, "compression_us": comp,
                                   "scheme_micro": scheme}, indent=2) + "\n")
        print(f"wrote {out.relative_to(REPO)}")


def cmd_compcheck(app: App, args):
    for fn, name in FNS.items():
        for _ in range(args.n):
            h = list(struct.unpack("<8I", os.urandom(32)))
            m = list(struct.unpack("<16I", os.urandom(64)))
            if fn in B2S_FNS:
                t, f = int.from_bytes(os.urandom(4), "little"), (0, M32)[os.urandom(1)[0] & 1]
                assert app.compress(fn, h, m, t, f) == b2s_compress_ref(h, m, t, f), f"{name}: mismatch"
            else:
                assert app.compress(fn, h, m) == sha256_compress_ref(h, m), f"{name}: mismatch"
        print(f"{name:12s} matches the Python reference on {args.n} random (IV, block) pairs")


def cmd_vector(app: App, args):
    app.config(args.yield_, args.blake2s)
    vectors = ref.load_vectors()
    for seed in list(dict.fromkeys(v["seed"] for v in vectors))[: args.keys]:
        kg = app.keygen(seed)
        vs = [v for v in vectors if v["seed"] == seed]
        assert (kg["pp"], kg["root"]) == (vs[0]["public_param"], vs[0]["root"]), "public key mismatch"
        print(f"key {seed[:4].hex()}.. matches leanVM (keygen {kg['s']:.1f} s, {kg['hashes']} hashes)")
        for v in vs:
            s = app.sign(v["message"])
            assert app.get_sig() == v["signature"], "signature differs from leanVM's"
            print(f"  message {v['message'][:4].hex()}..: signature identical to leanVM's "
                  f"(sign {s['s']:.1f} s, {s['hashes']} hashes, counters {s['counters']})")


def git_rev(path: pathlib.Path) -> str:
    try:
        return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return "unknown"


def cmd_bench(app: App, args):
    nop = app.nop_latency()
    comp = compressions(app, nop, args.micro_n)
    micro_r = micro(app, nop, args.micro_n, args.blake2s)
    app.config(args.yield_, args.blake2s)
    info = app.info()
    r = {
        "date": datetime.datetime.now().isoformat(timespec="seconds"),
        "label": args.label,
        "device": args.device,
        "firmware": args.firmware,
        "app": info,
        "repo_commit": git_rev(REPO),
        "sdk_commit": git_rev(REPO / ".sdk" / "API_LEVEL_26"),
        "scheme": "leanVM SPHINCS+ (BLAKE2s, WOTS+C w=3 v=42 T=191, d=3 (12,7,7), FORS+C a=10 k=15), sig 4924 B",
        "usb_nop_roundtrip_ms": nop * 1e3,
        "compression_us": comp,
    }
    print(f"{info}  usb round trip {nop * 1e3:.2f} ms")
    print("us per compression: " + ", ".join(f"{k} {v:.1f}" for k, v in comp.items()))
    r.update(micro_r)
    b2s_fn = "blake2s-" + B2S_IMPLS[args.blake2s]
    print(f"blake2s-{B2S_IMPLS[args.blake2s]}: compression {comp[b2s_fn]:.1f} us, "
          f"chain step {r['chain_step_us']:.1f} us, WOTS leaf {r['ots_leaf_ms']:.1f} ms")

    # Keygen on a host-chosen seed, checked against the reference.
    seed = os.urandom(32)
    kg = app.keygen(seed)
    pp, root, cache = ref.key_gen_from_seed(seed)
    assert (kg["pp"], kg["root"]) == (pp, root), "keygen mismatch"
    r["keygen_s"] = kg["s"] - nop
    r["keygen_hashes"], r["keygen_compressions"] = kg["hashes"], kg["compressions"]
    print(f"keygen {r['keygen_s']:.1f} s ({kg['hashes']} hashes, {kg['compressions']} compressions), matches reference")

    # Signatures on random messages, each compared with the reference signer and verified.
    sigs = []
    for _ in range(args.sigs):
        msg = os.urandom(32)
        s = app.sign(msg)
        sig = app.get_sig()
        want, stats = ref.sign(pp, root, seed, cache, msg)
        assert sig == want, "signature differs from the reference signer"
        assert ref.verify(pp, root, msg, sig), "signature does not verify"
        assert stats["counters"] == s["counters"] and stats["digest_trials"] == s["digest_trials"]
        s["s"] -= nop
        sigs.append(s)
        print(f"sign {s['s']:6.2f} s  {s['hashes']:6d} hashes {s['compressions']:6d} compressions  "
              f"digest trials {s['digest_trials']:4d}  counters {s['counters']}  identical to reference, verifies")
    times = [s["s"] for s in sigs]
    r["signatures"] = sigs
    r["sign_s_median"] = statistics.median(times)
    r["sign_s_mean"] = statistics.fmean(times)
    r["sign_hashes_mean"] = statistics.fmean(s["hashes"] for s in sigs)
    r["sign_us_per_compression"] = sum(times) / sum(s["compressions"] for s in sigs) * 1e6
    print(f"=> sign mean {r['sign_s_mean']:.2f} s, median {r['sign_s_median']:.2f} s over {len(sigs)} "
          f"({r['sign_us_per_compression']:.1f} us per compression)")
    out = REPO / "results" / f"{datetime.date.today()}-{args.label}.json"
    out.write_text(json.dumps(r, indent=2) + "\n")
    print(f"wrote {out.relative_to(REPO)}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info")
    sub.add_parser("hashcheck")
    sub.add_parser("compcheck").add_argument("--n", type=int, default=50)
    m = sub.add_parser("micro")
    m.add_argument("--n", type=int, default=4000)
    m.add_argument("--save", action="store_true")
    m.add_argument("--label", default="compressions")
    sub.add_parser("probes").add_argument("--save", action="store_true")
    for name in ("vector", "bench"):
        s = sub.add_parser(name)
        s.add_argument("--yield", dest="yield_", action="store_true",
                       help="service the event loop during computations (blocks up to 100 ms per call)")
        s.add_argument("--blake2s", type=int, default=0, choices=list(B2S_IMPLS),
                       help="BLAKE2s compression the scheme uses: 0 C, 1 asm, 2 asm2, 3 asm3 (flash table), 4 asm3r (RAM table), 5 asm4r")
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
        {"info": cmd_info, "hashcheck": cmd_hashcheck, "compcheck": cmd_compcheck, "micro": cmd_micro,
         "probes": cmd_probes,
         "vector": cmd_vector, "bench": cmd_bench}[args.cmd](app, args)
    except ApduError as e:
        raise SystemExit(f"device error: {e}")
    finally:
        app.dev.close()


if __name__ == "__main__":
    main()
