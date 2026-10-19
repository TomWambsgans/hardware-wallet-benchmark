"""Hashes per second during SPHINCS+ signing, from results/*.json (the README's table).
A Keccak-256 hash is counted per Keccak-f[1600] permutation.

    .venv/bin/python host/rates.py
"""

import json
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
DEVICES = [("Trezor Safe 3", "results/trezor-safe3.json"), ("Ledger Nano S Plus", "results/nanosp.json")]
HASHES = [("blake2s", "BLAKE2s"), ("sha256", "SHA-256"), ("keccak256", "Keccak-256")]

print("| | " + " | ".join(title for _, title in HASHES) + " |\n" + "|---" * (len(HASHES) + 1) + "|")
for device, path in DEVICES:
    hashes = json.loads((REPO / path).read_text())["hashes"]
    cells = []
    for h, _ in HASHES:
        if h not in hashes:
            cells.append("—")
            continue
        sigs = hashes[h]["signatures"]
        cells.append(f"**{sum(s['compressions'] for s in sigs) / sum(s['s'] for s in sigs) / 1e3:.1f}K/s**")
    print(f"| {device} | " + " | ".join(cells) + " |")
