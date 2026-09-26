"""Run the device's Thumb-2 compression functions under Unicorn (ARMv8-M): check each one
against a Python reference and the calling convention, and count its instructions.

    tests/emu/build.sh && .venv/bin/python tests/emu/run.py
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import struct
import sys

from elftools.elf.elffile import ELFFile
from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_MCLASS, UC_MODE_THUMB, Uc
from unicorn import arm_const as R

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "host"))
from sphincs_ref import SHA256_IV, sha256_compress, sha256_raw  # noqa: E402

ELF = pathlib.Path(__file__).resolve().parent / "build" / "emu.elf"
M32 = 0xFFFFFFFF

# --- BLAKE2s compression reference (any state, counter and flag) ---------------------

B2S_IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4], [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13], [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11], [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5], [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
]


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


def b2s_compress_ref(h, m, t, f):
    v = list(h) + B2S_IV[:]
    v[12] ^= t
    v[14] ^= f

    def g(a, b, c, d, x, y):
        v[a] = (v[a] + v[b] + x) & M32
        v[d] = rotr(v[d] ^ v[a], 16)
        v[c] = (v[c] + v[d]) & M32
        v[b] = rotr(v[b] ^ v[c], 12)
        v[a] = (v[a] + v[b] + y) & M32
        v[d] = rotr(v[d] ^ v[a], 8)
        v[c] = (v[c] + v[d]) & M32
        v[b] = rotr(v[b] ^ v[c], 7)

    for s in SIGMA:
        for i, (a, b, c, d) in enumerate([(0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                                          (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)]):
            g(a, b, c, d, m[s[2 * i]], m[s[2 * i + 1]])
    return [h[i] ^ v[i] ^ v[i + 8] for i in range(8)]


# --- Emulator ---------------------------------------------------------------------------

RET = 0x7FFF0000
STACK_TOP = 0x2000EF00  # sp at the call; the CALLER_FRAME bytes above it stand for the caller's frame
CALLER_FRAME = 0x100
BUF_H, BUF_M = 0x2000F100, 0x2000F200
CALLEE_SAVED = (R.UC_ARM_REG_R4, R.UC_ARM_REG_R5, R.UC_ARM_REG_R6, R.UC_ARM_REG_R7, R.UC_ARM_REG_R8,
                R.UC_ARM_REG_R9, R.UC_ARM_REG_R10, R.UC_ARM_REG_R11)


class Emu:
    def __init__(self):
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        self.uc.ctl_set_cpu_model(R.UC_CPU_ARM_CORTEX_M33)
        self.uc.mem_map(0x00010000, 0x40000)
        self.uc.mem_map(0x20000000, 0x10000)
        self.uc.mem_map(RET, 0x1000)
        with open(ELF, "rb") as fh:
            elf = ELFFile(fh)
            for seg in elf.iter_segments():
                if seg["p_type"] == "PT_LOAD" and seg["p_filesz"]:
                    self.uc.mem_write(seg["p_vaddr"], seg.data())
            self.sym = {s.name: s["st_value"] for s in elf.get_section_by_name(".symtab").iter_symbols() if s.name}
        self.count = 0
        self.uc.hook_add(UC_HOOK_CODE, lambda uc, addr, size, user: setattr(self, "count", self.count + 1))

    def call(self, name, *args):
        """Call per the AAPCS and check the callee honours it: r4-r11 and sp preserved, and
        nothing written above sp (the caller's frame, stack arguments included)."""
        uc = self.uc
        for reg, val in zip((R.UC_ARM_REG_R0, R.UC_ARM_REG_R1, R.UC_ARM_REG_R2, R.UC_ARM_REG_R3), args):
            uc.reg_write(reg, val & M32)
        stack_args = struct.pack(f"<{len(args) - 4}I", *args[4:]) if len(args) > 4 else b""
        canary = stack_args + os.urandom(CALLER_FRAME - len(stack_args))
        uc.mem_write(STACK_TOP, canary)
        uc.reg_write(R.UC_ARM_REG_SP, STACK_TOP)
        saved = {reg: int.from_bytes(os.urandom(4), "little") for reg in CALLEE_SAVED}
        saved[R.UC_ARM_REG_R9] = self.sym["_sb"]  # -frwpi static base
        for reg, val in saved.items():
            uc.reg_write(reg, val)
        uc.reg_write(R.UC_ARM_REG_LR, RET | 1)
        self.count = 0
        uc.emu_start(self.sym[name] | 1, RET)
        for reg, val in saved.items():
            assert uc.reg_read(reg) == val, f"{name}: callee-saved register not preserved"
        assert uc.reg_read(R.UC_ARM_REG_SP) == STACK_TOP, f"{name}: sp not restored"
        assert bytes(uc.mem_read(STACK_TOP, CALLER_FRAME)) == canary, f"{name}: wrote into the caller's frame"
        return self.count

    def put(self, addr, data: bytes):
        self.uc.mem_write(addr, data)

    def get(self, addr, n) -> bytes:
        return bytes(self.uc.mem_read(addr, n))


def main():
    emu = Emu()
    emu.call("blake2s_setup")
    emu.call("sha256_setup")
    sigma, k = emu.sym["g_sigma"], emu.sym["g_k"]  # the RAM tables, as on the device
    counts = {}
    for _ in range(300):
        h = struct.unpack("<8I", os.urandom(32))
        block = os.urandom(64)
        m = struct.unpack("<16I", block)
        t, f = int.from_bytes(os.urandom(4), "little"), (0, M32)[os.urandom(1)[0] & 1]
        n = os.urandom(1)[0] % 65
        msg = block[:n]

        emu.put(BUF_H, struct.pack("<8I", *h))
        emu.put(BUF_M, block)
        counts["b2s_compress_asm"] = emu.call("b2s_compress_asm", BUF_H, BUF_M, t, f, sigma)
        assert list(struct.unpack("<8I", emu.get(BUF_H, 32))) == b2s_compress_ref(h, m, t, f)

        emu.put(BUF_M, msg.ljust(64, b"\0"))
        counts["b2s_oneblock16_asm"] = emu.call("b2s_oneblock16_asm", BUF_H, BUF_M, n, sigma)
        assert emu.get(BUF_H, 16) == hashlib.blake2s(msg).digest()[:16]

        emu.put(BUF_H, struct.pack("<8I", *h))
        emu.put(BUF_M, block)
        counts["sha256_compress_asm"] = emu.call("sha256_compress_asm", BUF_H, BUF_M, k)
        assert struct.unpack("<8I", emu.get(BUF_H, 32)) == sha256_compress(h, block)

        emu.put(BUF_M, msg.ljust(64, b"\0"))
        counts["sha256_oneblock16_asm"] = emu.call("sha256_oneblock16_asm", BUF_H, BUF_M, k)
        assert emu.get(BUF_H, 16) == sha256_raw(msg.ljust(64, b"\0"))[:16]
    assert sha256_compress(SHA256_IV, bytes(64))  # reference sanity
    print("all 4 functions match the reference on 300 random inputs and honour the calling convention")
    for name, c in counts.items():
        print(f"  {name:22s} {c:5d} instructions")


if __name__ == "__main__":
    main()
