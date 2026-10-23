# Proof of the smallest proof of work (zkDSL, see vendor/leanVM/crates/lean_compiler/zkDSL.md).
#
# Statement: the public input encodes an integer i < 2^24, and i is the SMALLEST
# integer whose hash keccak256(abi.encode(uint256(i))) starts with D zero bits
# (Solidity's keccak256 of the 32-byte big-endian word). The program hashes every
# j <= i, proves that no j < i is a hit and that i is.
#
# ---- encoding ----------------------------------------------------------------
# The 32-byte message is two 16-byte cells: the first is zero, the second holds
# bytes 16..31, i.e. lane 2 (zero) and lane 3 = bytes 24..31 read little-endian.
# For j = 2^16·h + 2^8·p + q (h, p, q bytes) those bytes are 0 0 0 0 0 h p q, so the
# cell is y·(x^40·h + x^48·p + x^56·q), each byte read as a polynomial of degree < 8.
#
# The digest's first 8 bytes are lane 0 of the output, L0, the low limb of out[0]
# (out[0] = L0 + y·L1). "Starts with D zero bits" reads bytes 0, 1, .. most
# significant bit first, so it is a mask on L0: bits 0..15 (bytes 0 and 1, all of
# them since D >= 16) and, from byte 2, the D - 16 bits MASK1 lists (bit 23 first).
#
# ---- the lookup ----------------------------------------------------------------
# L0 is decomposed into four 16-bit chunks, L0 = r0 + x^16·r1 + x^32·r2 + x^48·r3,
# each chunk proven to be a polynomial of degree < 16 by a lookup: the prover hints
# an address a = g^k, the program reads r = m[a] and proves k <= TOP_INDEX by the
# range check in the exponent (q = g^TOP / a must also be an address). Every cell
# m[0..TOP_INDEX] holds a polynomial of degree < 16: m[0] and m[1] are the public
# input, checked to be such polynomials below, and m[2..2+2^16) is the table T,
# T[e] = e, written by the program itself into main's frame. A decomposition into
# four such chunks is unique, so r0 IS the low 16 bits of L0, and so on.
#
# A digest is not a hit iff r0 != 0 or one of the MASK1 bits of r1 is set. Almost
# always r0 != 0, which a block of B digests proves at once (their product is
# nonzero). A block holding a digest with r0 == 0 (probability ~B·2^-16) takes the
# slow path instead, which also decomposes r1 into bits. The prover picks the path
# with an unconstrained hint: both are sound, the fast one is merely incomplete.
from snark_lib import *

D = D_PLACEHOLDER  # 16 <= D <= 32
MASK1 = MASK1_PLACEHOLDER  # MASK1[k] == 1 iff bit k of r1 is one of the D leading bits
B = 16  # digests per block: a block is a run of j sharing all but their low 4 bits
TABLE = 65536
TOP = GEN ** 65537  # the last cell a lookup may read: m[0], m[1], then T
X16 = GEN ** 16
X32 = GEN ** 32
X48 = GEN ** 48
YY = f192(0, 1, 0)
YX40 = f192(0, 1099511627776, 0)  # y·x^40: byte h of j
YX48 = f192(0, 281474976710656, 0)  # y·x^48: byte p
YX56 = f192(0, 72057594037927936, 0)  # y·x^56: byte q
YX60 = f192(0, 1152921504606846976, 0)  # y·x^60: the high nibble of q
STEP = STEP_PLACEHOLDER  # STEP[t] = y·x^56·((t - 1) ^ t), the move from j's low nibble t - 1 to t


@inline
def lookup(a):
    # m[a] for a hinted address a = g^k, with k <= 65537: reading through a proves
    # k < 2^log_mem, reading through q = g^(65537 - k) proves 65537 - k >= 0.
    r = a[1]
    q = TOP / a
    unused = q[1]
    return r


@inline
def masked_bits(r1):
    # The MASK1 bits of the chunk r1 (a polynomial of degree < 16), as a polynomial.
    bits = StackBuf(16)
    hint_decompose_bits(bits, r1, 16)
    acc = 0
    m = 0
    for k in unroll(0, 16):
        b = bits[k]
        bits[k] = b * b
        term = b * GEN ** k
        acc += term
        if const(MASK1[k] == 1):
            m += term
    assert acc == r1
    return m


def digest_chunks(inp):
    # Hash the 32-byte message (0, inp) and return its digest's chunks r0 and r1.
    h = StackBuf(5)
    hint_witness(h, "w")
    out = StackBuf(13)
    keccak([0, inp], [0, 0], out, len=32)
    r0 = lookup(h[0])
    r1 = lookup(h[1])
    r2 = lookup(h[2])
    r3 = lookup(h[3])
    l1 = h[4]
    assert_in_k(l1, l1)
    out[0] = r0 + X16 * r1 + X32 * r2 + X48 * r3 + YY * l1
    return r0, r1


def slow_hash(inp):
    # j is not a hit: r0 != 0 or a MASK1 bit of r1 is set.
    r0, r1 = digest_chunks(inp)
    m1 = masked_bits(r1)
    assert r0 + X16 * m1 != 0
    return


def hit_hash(inp):
    # i is a hit: r0 == 0 and no MASK1 bit of r1 is set.
    r0, r1 = digest_chunks(inp)
    m1 = masked_bits(r1)
    assert r0 == 0
    assert m1 == 0
    return


def fast_block(inb):
    # B consecutive j, the first one's input cell inb: every r0 is nonzero.
    prod = GEN ** 0
    inp = inb
    for t in unroll(0, B):
        if const(t != 0):
            # j's low nibble goes t-1 -> t: XOR y·x^56·((t-1) ^ t).
            inp = inp + STEP[t]
        h = StackBuf(5)
        hint_witness(h, "w")
        out = StackBuf(13)
        keccak([0, inp], [0, 0], out, len=32)
        r0 = lookup(h[0])
        r1 = lookup(h[1])
        r2 = lookup(h[2])
        r3 = lookup(h[3])
        l1 = h[4]
        if const(t % 2 == 1):
            assert_in_k(l1_prev, l1)
        l1_prev = l1
        out[0] = r0 + X16 * r1 + X32 * r2 + X48 * r3 + YY * l1
        prod = prod * r0
    assert prod != 0
    return


def slow_block(tp, inb):
    for t in mul_range(1, GEN ** B):
        slow_hash(inb + YX56 * tp[t])
    return


def blocks_loop(tp, pbase, rend):
    # Blocks r in [0, rend) of the byte run pbase (h and p fixed).
    for r in mul_range(1, rend):
        inb = pbase + YX60 * tp[r]
        slow = hint_witness("slow")
        if slow == 1:
            slow_block(tp, inb)
        else:
            fast_block(inb)
    return


def bytes_loop(tp, hbase, pend):
    # Byte runs p in [0, pend) of hbase (h fixed), each one 256 j.
    for p in mul_range(1, pend):
        blocks_loop(tp, hbase + YX48 * tp[p], GEN ** 16)
    return


def main():
    # ---- the table: T[e] = e at m[2 + e], main's frame cells from offset 2 ----
    T = StackBuf(TABLE)
    tp = addr(T)
    assert tp == GEN ** 2
    for t in unroll(0, 16):
        T[t] = t
    for k in mul_range(GEN, GEN ** 4096):
        base = tp[k] * GEN ** 4
        row = tp * k ** 16
        for t in unroll(0, 16):
            row[GEN ** t] = base + t

    # ---- the public input: m[0] = i mod 2^16, m[1] = i >> 16 (< 2^8) ----
    # Decomposing both into bits proves them polynomials of degree < 16, which the
    # lookup's soundness needs, and gives i's bytes in the exponent.
    pub = GEN ** 0
    lo = pub[1]
    hi = pub[GEN]
    bits = StackBuf(16)
    hint_decompose_bits(bits, lo, 16)
    hbits = StackBuf(8)
    hint_decompose_bits(hbits, hi, 8)
    acc_lo = 0
    acc_hi = 0
    gt = GEN ** 0  # g^(i & 15)
    gr = GEN ** 0  # g^((i >> 4) & 15)
    gp = GEN ** 0  # g^((i >> 8) & 255)
    gh = GEN ** 0  # g^(i >> 16)
    for k in unroll(0, 16):
        b = bits[k]
        bits[k] = b * b
        acc_lo += b * GEN ** k
        if const(k // 4 == 0):
            gt *= 1 + b * (1 + GEN ** (2 ** k))
        if const(k // 4 == 1):
            gr *= 1 + b * (1 + GEN ** (2 ** (k - 4)))
        if const(k // 8 == 1):
            gp *= 1 + b * (1 + GEN ** (2 ** (k - 8)))
    for k in unroll(0, 8):
        b = hbits[k]
        hbits[k] = b * b
        acc_hi += b * GEN ** k
        gh *= 1 + b * (1 + GEN ** (2 ** k))
    assert acc_lo == lo
    assert acc_hi == hi

    # ---- every j < i, in order, then i ----
    for h in mul_range(1, gh):
        bytes_loop(tp, YX40 * tp[h], GEN ** 256)
    hbase = YX40 * tp[gh]
    bytes_loop(tp, hbase, gp)
    pbase = hbase + YX48 * tp[gp]
    blocks_loop(tp, pbase, gr)
    rbase = pbase + YX60 * tp[gr]
    for t in mul_range(1, gt):
        slow_hash(rbase + YX56 * tp[t])
    hit_hash(rbase + YX56 * tp[gt])
    return
