"""Verify a leanVM proof on a Ledger Nano S Plus running leanVM Verify (ledger/load.sh installs and opens it).

    python leanvm-pow/ledger/host/verify.py leanvm-pow/ledger/proofs/d18-rate4.stream
    python leanvm-pow/ledger/host/verify.py <stream> --runs 3 --out leanvm-pow/results/ledger-verify.json

The stream is what `keccak-pow --ledger-stream` writes: the 32-byte public input, then the proof in the order the
device's verifier reads it. Each run streams it twice: once to be verified, once only received (the USB
baseline), so that the verification's own time is the difference. The device reports whether it accepts the
proof, how many bytes it read, and the deepest its stack went.
"""

from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import statistics
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "host"))
from ledger_hid import Ledger  # noqa: E402

CLA = 0xE0
INS_INFO, INS_VERIFY, INS_DATA = 0x01, 0x10, 0x11
STATUS_DONE, STATUS_MORE = 0x00, 0x01
CHUNK = 255
APP_NAME = "leanVM Verify"

# leanVM's verifier errors, as the device's verifier numbers them (ledger/verifier/src/lib.rs, `Error`).
ERRORS = [
    "accepted", "DigestHalf", "MultilinearSize", "NotPowerOfTwo", "StreamExhausted", "StreamNotConsumed",
    "GrindingNonce", "MerkleOpeningShape", "MerkleRootMismatch", "GkrLayer", "BusCountZero",
    "TableSumcheckTerminal", "AnnouncedTableSizes", "AnnouncedHighLimb", "PcsInverseRate", "CommittedSize",
    "WhirShape", "QueryCountLadder", "WhirTerminal", "KeccakProduct", "KeccakLayer", "KeccakOutputOpening",
    "KeccakInputOpening", "Transport",
]


def describe(result: int) -> str:
    if result < len(ERRORS):
        return ERRORS[result]
    return {0xFE: "transport (a chunk missing, or the stream past its length)", 0xFF: "transport"}.get(result, f"error {result}")


def run(device, recorded: bytes, receive_only: bool = False) -> dict:
    """One pass over the stream: VERIFY, then a DATA chunk each time the device asks for one."""
    public_input, stream = recorded[:32], recorded[32:]
    started = time.perf_counter()
    reply = device.apdu(CLA, INS_VERIFY, 1 if receive_only else 0, 0, public_input + len(stream).to_bytes(4, "big"), timeout_s=600)
    sent = 0
    while reply[0] == STATUS_MORE:
        chunk = stream[sent : sent + CHUNK]
        if not chunk:
            raise SystemExit("the device asked for more than the stream holds")
        sent += len(chunk)
        reply = device.apdu(CLA, INS_DATA, 0, 0, chunk, timeout_s=600)
    elapsed = time.perf_counter() - started
    if reply[0] != STATUS_DONE or len(reply) != 14:
        raise SystemExit(f"unexpected reply {reply.hex()}")
    return {
        "seconds": elapsed,
        "result": reply[1],
        "bytes_read": int.from_bytes(reply[2:6], "big"),
        "chunks": int.from_bytes(reply[6:10], "big"),
        "stack_bytes": int.from_bytes(reply[10:14], "big"),
    }


def benchmark(device, recorded: bytes, runs: int) -> dict:
    verified, received = [], []
    for i in range(runs):
        v = run(device, recorded)
        r = run(device, recorded, receive_only=True)
        print(
            f"run {i + 1}: verify {v['seconds']:.2f} s ({describe(v['result'])}), receive only {r['seconds']:.2f} s, "
            f"{v['chunks']} chunks, stack {v['stack_bytes']:,} bytes"
        )
        if v["result"] != 0:
            raise SystemExit(f"the device rejects the proof: {describe(v['result'])}")
        verified.append(v)
        received.append(r)
    verify_s = statistics.median(v["seconds"] for v in verified)
    receive_s = statistics.median(r["seconds"] for r in received)
    return {
        "verify_s": verify_s,
        "receive_only_s": receive_s,
        "compute_s": verify_s - receive_s,
        "stream_bytes": len(recorded) - 32,
        "chunks": verified[0]["chunks"],
        "stack_bytes": max(v["stack_bytes"] for v in verified),
        "runs": verified,
        "receive_runs": received,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("stream", type=pathlib.Path, help="the stream keccak-pow --ledger-stream wrote")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--out", type=pathlib.Path, help="write the results as JSON")
    args = parser.parse_args()
    recorded = args.stream.read_bytes()

    device = Ledger()
    name, version = device.running_app()
    if name != APP_NAME:
        raise SystemExit(f"open {APP_NAME} on the device first (running: {name}); ledger/load.sh opens it")
    print(f"{APP_NAME} {version}: {len(recorded) - 32:,}-byte proof stream, {args.runs} runs")
    results = benchmark(device, recorded, args.runs)
    print(
        f"verify {results['verify_s']:.2f} s = receive {results['receive_only_s']:.2f} s + compute "
        f"{results['compute_s']:.2f} s (medians); stack {results['stack_bytes']:,} bytes"
    )
    if args.out:
        record = {
            "date": datetime.datetime.now().isoformat(timespec="seconds"),
            "device": "Ledger Nano S Plus",
            "app_version": version,
            "stream": args.stream.name,
            **results,
        }
        args.out.write_text(json.dumps(record, indent=1) + "\n")
        print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
