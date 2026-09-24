"""Instruction counts of the SDK's own SHA-256 (the OS library's source), used the
way the app uses the OS library: cx_sha256_init_no_throw, overwrite the state,
cx_sha256_update on one 64-byte block.

    tools/emu/cxsha/build.sh && .venv/bin/python tools/emu/cxsha/run.py
"""

import collections
import os
import pathlib
import struct
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[2] / "host"))
import run as emu_run  # noqa: E402
from compress_ref import sha256_compress_ref  # noqa: E402
from unicorn import UC_HOOK_CODE  # noqa: E402

CTX, BLOCK = 0x2000F400, 0x2000F600
ACC_OFF = 12 + 4 + 64  # cx_sha256_t: header (info ptr, counter; 8 B, +4 padding?) checked below

for build in sorted(HERE.glob("build-*")):
    emu = emu_run.Emu(build / "cx.elf")
    per_fn = collections.Counter()

    def where(uc, addr, size, user):
        for lo, hi, name in emu.funcs:
            if lo <= addr < hi:
                per_fn[name] += 1
                return
        per_fn["?"] += 1

    emu.uc.hook_add(UC_HOOK_CODE, where)
    # Locate acc in the context: init writes the SHA-256 IV there.
    emu.call("cx_sha256_init_no_throw", CTX)
    raw = bytes(emu.uc.mem_read(CTX, 128))
    acc_off = raw.find(struct.pack("<I", 0x6A09E667))
    assert acc_off > 0
    h = list(struct.unpack("<8I", os.urandom(32)))
    block = os.urandom(64)
    emu.uc.mem_write(CTX + acc_off, struct.pack("<8I", *h))
    emu.uc.mem_write(BLOCK, block)
    per_fn.clear()
    n_update = emu.call("cx_sha256_update", CTX, BLOCK, 64)
    out = list(struct.unpack("<8I", emu.uc.mem_read(CTX + acc_off, 32)))
    assert out == sha256_compress_ref(h, list(struct.unpack(">16I", block))), f"{build.name}: wrong"
    per_fn.clear()
    n_init = emu.call("cx_sha256_init_no_throw", CTX)
    opt, mm = build.name.split("-")[1:]
    print(f"-O{opt}, {mm} memmove: init {n_init:4d} + update {n_update:5d} instructions (correct);  "
          f"memmove {sum(v for k, v in per_fn.items() if k == 'memmove')}")
    emu.uc.mem_write(CTX + acc_off, struct.pack("<8I", *h))
    per_fn.clear()
    emu.call("cx_sha256_update", CTX, BLOCK, 64)
    print("    update by function: " + ", ".join(f"{k} {v}" for k, v in per_fn.most_common(6)))
