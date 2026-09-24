"""Build the device crypto natively and check it against leanVM's vectors.

    python tools/native/check_native.py
"""

import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "ledger-app" / "src" / "crypto"
BIN = ROOT / "tools" / "native" / "spx_native"

subprocess.run(
    ["cc", "-O2", "-Wall", "-Wextra", "-I", str(SRC), str(ROOT / "tools/native/spx_native.c"),
     str(SRC / "blake2s.c"), str(SRC / "sphincs.c"), "-o", str(BIN)],
    check=True,
)
vectors = json.loads((ROOT / "vectors" / "leanvm-sphincs-blake2s.json").read_text())["vectors"]
for impl in (0, 1):
    for v in vectors:
        out = subprocess.run([str(BIN), str(impl), "sign", v["seed"], v["message"]], check=True,
                             capture_output=True, text=True).stdout.split()
        sig, ok, hashes, comps, trials, *counters = out
        assert ok == "1", "root mismatch"
        assert [int(c) for c in counters] == v["counters"], (counters, v["counters"])
        assert sig == v["signature"], f"impl {impl}: signature differs"
        print(f"impl {impl} seed {v['seed'][:8]}.. msg {v['message'][:8]}..: identical "
              f"({hashes} hashes, {comps} compressions, {trials} digest trials, counters {counters})")
