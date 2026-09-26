"""The device's scheme code, built natively (portable C), against vectors/ (both hashes).

    python3 tests/native/check.py
"""

import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "ledger-app" / "src" / "crypto"
BIN = ROOT / "tests" / "native" / "spx_native"

subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-I", str(SRC), str(ROOT / "tests/native/spx_native.c"),
                *(str(SRC / f) for f in ("hash.c", "blake2s.c", "sha256.c", "sphincs.c")), "-o", str(BIN)],
               check=True)
for hash_name in ("blake2s", "sha256"):
    vectors = json.loads((ROOT / "vectors" / f"{hash_name}.json").read_text())["vectors"]
    for v in vectors:
        pp, root, sig = subprocess.run([str(BIN), hash_name, v["seed"], v["message"]], check=True,
                                       capture_output=True, text=True).stdout.split()
        assert (pp, root) == (v["public_param"], v["root"]), f"{hash_name}: public key differs"
        assert sig == v["signature"], f"{hash_name}: signature differs"
    print(f"{hash_name}: {len(vectors)} vectors reproduced (public key and signature, byte for byte)")
