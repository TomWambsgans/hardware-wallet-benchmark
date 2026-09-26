"""Hashes per second from results/*.json: in a compression loop, and inside SPHINCS+.

    .venv/bin/python host/rates.py      # prints the README's table (markdown)

One hash is one compression-function call; every SPHINCS+ hash (Th) is exactly one.
Inside SPHINCS+, the rate is the compressions the device counted divided by the time of
the whole operation, so it includes all the signer's other work.
"""

import json
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
DEVICES = [("Trezor Safe 3", "results/trezor-safe3.json"), ("Ledger Nano S Plus", "results/nanosp.json")]
NAMES = {"blake2s": "BLAKE2s", "sha256": "SHA-256"}


def k(rate: float) -> str:
    return f"{rate / 1e3:.1f}K/s"


def main():
    print("| device | hash | compression loop | in SPHINCS+ keygen | in SPHINCS+ signing |")
    print("|---|---|---|---|---|")
    for device, path in DEVICES:
        for h, r in json.loads((REPO / path).read_text())["hashes"].items():
            loop = 1e6 / r["compression_us"]
            keygen = r["keygen_compressions"] / r["keygen_s"]
            sigs = r["signatures"]
            sign = sum(s["compressions"] for s in sigs) / sum(s["s"] for s in sigs)
            print(f"| {device} | {NAMES[h]} | **{k(loop)}** ({r['compression_us']:.1f} µs) "
                  f"| {k(keygen)} ({keygen / loop:.0%}) | {k(sign)} ({sign / loop:.0%}) |")


if __name__ == "__main__":
    main()
