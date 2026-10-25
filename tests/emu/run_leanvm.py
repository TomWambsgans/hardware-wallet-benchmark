"""Run the leanVM verifier's hand-written Thumb-2 routine under Unicorn (ARMv8-M): check
`leanvm_clmul32` against a carry-less reference and against the calling convention, and
count its instructions.

It reads the routine out of the static library the device app links, so what runs here is
what ships:

    leanvm-pow/ledger/build.sh   (step 1 is enough)
    .venv/bin/python tests/emu/run_leanvm.py
"""

from __future__ import annotations

import io
import os
import pathlib
import struct

from elftools.elf.elffile import ELFFile
from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_MODE_MCLASS, UC_MODE_THUMB, Uc
from unicorn import arm_const as R

ROOT = pathlib.Path(__file__).resolve().parents[2]
LIB = ROOT / "leanvm-pow/ledger/ffi/target/thumbv8m.main-none-eabi/release/libleanvm_ledger_ffi.a"
FUNC = "leanvm_clmul32"

M32 = 0xFFFFFFFF
CODE_BASE = 0x00010000
RET = 0x7FFF0000
STACK_TOP = 0x2000EF00  # sp at the call; the CALLER_FRAME bytes above it stand for the caller's frame
CALLER_FRAME = 0x100
STATIC_BASE = 0x20001000  # what -frwpi keeps in r9
CALLEE_SAVED = (R.UC_ARM_REG_R4, R.UC_ARM_REG_R5, R.UC_ARM_REG_R6, R.UC_ARM_REG_R7, R.UC_ARM_REG_R8,
                R.UC_ARM_REG_R9, R.UC_ARM_REG_R10, R.UC_ARM_REG_R11)


def clmul32_ref(a: int, b: int) -> int:
    """The carry-less product itself: shift-and-xor, no field tricks."""
    out = 0
    for i in range(32):
        if a >> i & 1:
            out ^= b << i
    return out


def ar_members(lib: pathlib.Path):
    """Each member of a `ar` archive, as bytes (the names are of no interest here)."""
    data = lib.read_bytes()
    assert data[:8] == b"!<arch>\n", f"{lib}: not an archive"
    at = 8
    while at + 60 <= len(data):
        size = int(data[at + 48:at + 58].decode().strip())
        body = data[at + 60:at + 60 + size]
        at += 60 + size + (size & 1)
        yield body


def load_func(lib: pathlib.Path, name: str) -> bytes:
    """The bytes of `name` as the app links them, out of the static library."""
    if not lib.exists():
        raise SystemExit(f"{lib} is missing: run leanvm-pow/ledger/build.sh first")
    for body in ar_members(lib):
        if body[:4] != b"\x7fELF":
            continue
        elf = ELFFile(io.BytesIO(body))
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            continue
        for sym in symtab.iter_symbols():
            if sym.name != name or sym["st_shndx"] == "SHN_UNDEF":
                continue
            sec = elf.get_section(sym["st_shndx"])
            if sec.data_size == 0:
                continue
            # Pure register code: no relocation reaches it.
            rela = elf.get_section_by_name(".rel" + sec.name) or elf.get_section_by_name(".rela" + sec.name)
            assert rela is None or rela.num_relocations() == 0, f"{name}: unexpected relocations"
            return sec.data()[sym["st_value"] & ~1:]
    raise SystemExit(f"{name} not found in {lib}")


class Emu:
    def __init__(self, code: bytes):
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        self.uc.ctl_set_cpu_model(R.UC_CPU_ARM_CORTEX_M33)
        self.uc.mem_map(CODE_BASE, 0x10000)
        self.uc.mem_map(0x20000000, 0x10000)
        self.uc.mem_map(RET, 0x1000)
        self.uc.mem_write(CODE_BASE, code)
        self.count = 0
        self.low_water = STACK_TOP
        self.uc.hook_add(UC_HOOK_CODE, lambda uc, addr, size, user: setattr(self, "count", self.count + 1))
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._wrote)

    def _wrote(self, uc, access, addr, size, value, user):
        if addr < self.low_water:
            self.low_water = addr

    def call(self, *args):
        """Call per the AAPCS and check the callee honours it: r4-r11 (r9 is the -frwpi static
        base) and sp preserved, and nothing written above sp -- the caller's frame."""
        uc = self.uc
        for reg, val in zip((R.UC_ARM_REG_R0, R.UC_ARM_REG_R1, R.UC_ARM_REG_R2, R.UC_ARM_REG_R3), args):
            uc.reg_write(reg, val & M32)
        canary = os.urandom(CALLER_FRAME)
        uc.mem_write(STACK_TOP, canary)
        uc.reg_write(R.UC_ARM_REG_SP, STACK_TOP)
        saved = {reg: int.from_bytes(os.urandom(4), "little") for reg in CALLEE_SAVED}
        saved[R.UC_ARM_REG_R9] = STATIC_BASE
        for reg, val in saved.items():
            uc.reg_write(reg, val)
        uc.reg_write(R.UC_ARM_REG_LR, RET | 1)
        self.count = 0
        self.low_water = STACK_TOP
        uc.emu_start(CODE_BASE | 1, RET)
        for reg, val in saved.items():
            assert uc.reg_read(reg) == val, f"{FUNC}: callee-saved register not preserved"
        assert uc.reg_read(R.UC_ARM_REG_SP) == STACK_TOP, f"{FUNC}: sp not restored"
        assert bytes(uc.mem_read(STACK_TOP, CALLER_FRAME)) == canary, f"{FUNC}: wrote into the caller's frame"
        return uc.reg_read(R.UC_ARM_REG_R0) | uc.reg_read(R.UC_ARM_REG_R1) << 32


def main():
    code = load_func(LIB, FUNC)
    emu = Emu(code)

    cases = [(0, 0), (0, M32), (M32, 0), (M32, M32), (1, M32), (M32, 1), (0x80000000, 0x80000000)]
    cases += [(1 << i, 1 << j) for i in (0, 1, 7, 31) for j in (0, 1, 7, 31)]
    cases += [struct.unpack("<2I", os.urandom(8)) for _ in range(300)]

    deepest = 0
    for a, b in cases:
        got = emu.call(a, b)
        want = clmul32_ref(a, b)
        assert got == want, f"{FUNC}({a:#010x}, {b:#010x}) = {got:#018x}, want {want:#018x}"
        deepest = max(deepest, STACK_TOP - emu.low_water)

    print(f"{FUNC}: matches the carry-less reference on {len(cases)} inputs "
          f"(300 random, {len(cases) - 300} edge cases)")
    print(f"  calling convention: r4-r11 and sp preserved, caller's frame untouched")
    print(f"  {emu.count} instructions per call, {deepest} bytes of stack")


if __name__ == "__main__":
    main()
