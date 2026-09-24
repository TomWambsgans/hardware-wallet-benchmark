"""Run the device's compression functions under Unicorn (ARMv8-M, Cortex-M33 model):
check them against Python references and count the instructions they execute.

    tools/emu/build.sh && .venv/bin/python tools/emu/run.py
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import struct
import sys

from elftools.elf.elffile import ELFFile
from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_MCLASS, UC_MODE_THUMB, Uc
from unicorn.arm_const import (UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                               UC_ARM_REG_R9, UC_ARM_REG_SP, UC_CPU_ARM_CORTEX_M33)

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "host"))
from compress_ref import M32, b2s_compress_ref, check_references, sha256_compress_ref  # noqa: E402

ELF = pathlib.Path(__file__).resolve().parent / "build" / "emu.elf"

# --- Emulator -----------------------------------------------------------------

RET = 0x7FFF0000
STACK_TOP = 0x2000F000
BUF_H, BUF_M = 0x2000F100, 0x2000F200


class Emu:
    def __init__(self):
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M33)
        self.uc.mem_map(0x00010000, 0x40000)
        self.uc.mem_map(0x20000000, 0x10000)
        self.uc.mem_map(RET, 0x1000)
        with open(ELF, "rb") as fh:
            elf = ELFFile(fh)
            for seg in elf.iter_segments():
                if seg["p_type"] == "PT_LOAD" and seg["p_filesz"]:
                    self.uc.mem_write(seg["p_vaddr"], seg.data())
            symtab = elf.get_section_by_name(".symtab")
            self.sym = {s.name: s["st_value"] for s in symtab.iter_symbols() if s.name}
        self.count = 0
        self.uc.hook_add(UC_HOOK_CODE, self._tick)

    def _tick(self, uc, addr, size, user):
        self.count += 1

    def call(self, name, *args):
        uc = self.uc
        for reg, val in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), args):
            uc.reg_write(reg, val & M32)
        if len(args) > 4:  # AAPCS: further arguments on the stack
            uc.mem_write(STACK_TOP, struct.pack(f"<{len(args) - 4}I", *[a & M32 for a in args[4:]]))
        uc.reg_write(UC_ARM_REG_SP, STACK_TOP)
        uc.reg_write(UC_ARM_REG_R9, self.sym["_sb"])  # -frwpi static base
        uc.reg_write(UC_ARM_REG_LR, RET | 1)
        self.count = 0
        uc.emu_start(self.sym[name] | 1, RET)
        return self.count

    def words(self, addr, n):
        return list(struct.unpack(f"<{n}I", self.uc.mem_read(addr, 4 * n)))

    def put(self, addr, words):
        self.uc.mem_write(addr, struct.pack(f"<{len(words)}I", *words))


def main():
    check_references()
    emu = Emu()
    emu.call("crypto_tables_init")
    counts = {}
    for name in ("b2s_compress_c", "b2s_compress_asm", "b2s_compress_asm2", "b2s_compress_asm3", "b2s_compress_asm3r",
                 "b2s_compress_asm4r"):
        for _ in range(200):
            h = list(struct.unpack("<8I", os.urandom(32)))
            m = list(struct.unpack("<16I", os.urandom(64)))
            t, f = int.from_bytes(os.urandom(4), "little"), (0, M32)[os.urandom(1)[0] & 1]
            emu.put(BUF_H, h)
            emu.put(BUF_M, m)
            counts[name] = emu.call(name, BUF_H, BUF_M, t, f)
            assert emu.words(BUF_H, 8) == b2s_compress_ref(h, m, t, f), f"{name}: wrong output"
    for name in ("sha256_compress_c", "sha256_compress_asm", "sha256_compress_asm2", "sha256_compress_asm3",
                 "sha256_compress_asm3r"):
        for _ in range(200):
            h = list(struct.unpack("<8I", os.urandom(32)))
            m = list(struct.unpack("<16I", os.urandom(64)))
            emu.put(BUF_H, h)
            emu.put(BUF_M, m)
            counts[name] = emu.call(name, BUF_H, BUF_M)
            assert emu.words(BUF_H, 8) == sha256_compress_ref(h, m), f"{name}: wrong output"
    table = emu.sym["g_sigma_ram"]
    for _ in range(200):
        n = os.urandom(1)[0] % 65
        msg = os.urandom(n)
        emu.put(BUF_M, list(struct.unpack("<16I", msg.ljust(64, b"\0"))))
        counts["b2s_th_asm4"] = emu.call("b2s_th_asm4", BUF_H, BUF_M, n, table)
        assert struct.pack("<4I", *emu.words(BUF_H, 4)) == hashlib.blake2s(msg).digest()[:16], "b2s_th_asm4: wrong"
    print("Python references match hashlib; all functions match them on 200 random inputs each")
    for name, n in counts.items():
        print(f"{name:22s} {n:5d} instructions per compression")


if __name__ == "__main__":
    main()
