"""Hashes per second during SPHINCS+ signing, from results/*.json (the README's table).

    .venv/bin/python host/rates.py
"""

import json
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
DEVICES = [("Trezor Safe 3", "results/trezor-safe3.json"), ("Ledger Nano S Plus", "results/nanosp.json")]

print("| | BLAKE2s | SHA-256 |\n|---|---|---|")
for device, path in DEVICES:
    hashes = json.loads((REPO / path).read_text())["hashes"]
    rates = []
    for h in ("blake2s", "sha256"):
        sigs = hashes[h]["signatures"]
        rates.append(sum(s["compressions"] for s in sigs) / sum(s["s"] for s in sigs))
    print(f"| {device} | " + " | ".join(f"**{r / 1e3:.1f}K/s**" for r in rates) + " |")
