"""Python reference of leanVM's SPHINCS+ variant (WOTS+C, FORS+C), with two hashes.

A straight port of leanVM `crates/sphincs` (spec: leanVM `doc/sphincs/main.tex`):
n = 16, w = 3, v = 42, T = 191, d = 3 layers of heights (12, 7, 7) numbered from the top,
a = 10, k = 15 (k - 1 trees, the last index ground to zero). Every hash is
Th(P, tw, M) = H(tw || P || M)[:16] (the message digest keeps 22 bytes), with H either

  - "blake2s": BLAKE2s-256 (leanVM's scheme), or
  - "sha256":  the SHA-256 compression function (FIPS 180-4) applied from the standard IV to
               the input's 64-byte blocks, the last one zero-padded, with no length padding;
               the digest is the final state, big-endian. Every input length here is fixed by
               its tweak type, so one compression per call of at most 64 bytes, like BLAKE2s.

    python host/sphincs_ref.py                          # check against vectors/ (seconds)
    python host/sphincs_ref.py --make-sha256-vectors    # regenerate vectors/sha256.json (minutes)
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import struct
import sys

N = 16
W, CHAIN_LEN, V, TARGET_SUM = 3, 8, 42, 191
D, HEIGHTS, H = 3, (12, 7, 7), 26
A, K = 10, 15
NUM_FTS_TREES = K - 1
SPLIT_LEVEL = 6  # layer-0 level whose 2^6 nodes the signer caches (1 KB)
SIG_SIZE = N + NUM_FTS_TREES * (1 + A) * N + D * (4 + V * N) + H * N
assert SIG_SIZE == 4924
SUFFIX = [sum(HEIGHTS[lay:]) for lay in range(D + 1)]  # [26, 14, 7, 0]

PRF, CHAIN, LEAF, NODE, ENC, PARAMETER = 0, 1, 2, 3, 4, 5
RANDOMIZER, FTS_PRF, FTS_LEAF, FTS_NODE, FTS_ROOTS, MSG = 7, 8, 9, 10, 11, 12

# --- SHA-256 compression (FIPS 180-4) -------------------------------------------

M32 = 0xFFFFFFFF
SHA256_IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
SHA256_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


def sha256_compress(h: tuple, block: bytes) -> tuple:
    """One SHA-256 compression of a 64-byte block from chaining value h (8 words)."""
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        x, y = w[i - 15], w[i - 2]
        s0 = ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3)
        s1 = ((y >> 17) | (y << 15)) ^ ((y >> 19) | (y << 13)) ^ (y >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & M32)
    a, b, c, d, e, f, g, hh = h
    for i in range(64):
        s1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
        t1 = (hh + (s1 & M32) + (g ^ (e & (f ^ g))) + SHA256_K[i] + w[i]) & M32
        s0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
        t2 = ((s0 & M32) + ((a & b) | (c & (a | b)))) & M32
        hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & M32, c, b, a, (t1 + t2) & M32
    return tuple((x + y) & M32 for x, y in zip(h, (a, b, c, d, e, f, g, hh)))


def sha256_raw(data: bytes) -> bytes:
    """H for the SHA-256 scheme: compressions over zero-padded 64-byte blocks, no length padding."""
    h = SHA256_IV
    for i in range(0, len(data), 64):
        h = sha256_compress(h, data[i : i + 64].ljust(64, b"\0"))
    return struct.pack(">8I", *h)


HASHES = {
    "blake2s": lambda data: hashlib.blake2s(data).digest(),
    "sha256": sha256_raw,
}


def tweak(t: int, lay: int, tau: int, p: int, j: int) -> bytes:
    """[domain_sep=1 | type | layer | 0 | p:LE32 | tree:LE32 | index:LE32]."""
    return bytes([1, t, lay, 0]) + struct.pack("<III", p, tau, j)


def tree_of(idx: int, lay: int) -> int:
    return idx >> SUFFIX[lay]


def leaf_of(idx: int, lay: int) -> int:
    return (idx >> SUFFIX[lay + 1]) & ((1 << HEIGHTS[lay]) - 1)


def codeword(digest: bytes):
    """Each 64-bit half holds 21 3-bit positions and a zero top bit; the 42 sum to T."""
    x = []
    for q in range(2):
        d = int.from_bytes(digest[8 * q : 8 * q + 8], "little")
        if d >> (W * V // 2):
            return None
        x += [(d >> (W * r)) & (CHAIN_LEN - 1) for r in range(V // 2)]
    return x if sum(x) == TARGET_SUM else None


class Sphincs:
    def __init__(self, hash_name: str):
        self.hash_name = hash_name
        self.H = HASHES[hash_name]

    def th(self, pp: bytes, tw: bytes, payload: bytes) -> bytes:
        return self.H(tw + pp + payload)[:N]

    # --- WOTS+C -----------------------------------------------------------------

    def chain(self, pp, lay, tau, e, i, start, steps, value):
        for step in range(1, steps + 1):
            value = self.th(pp, tweak(CHAIN, lay, tau, CHAIN_LEN * i + start + step - 1, e), value)
        return value

    def ots_secret(self, pp, master, lay, tau, e, i):
        return self.th(pp, tweak(PRF, lay, tau, i, e), master)

    def ots_leaf_hash(self, pp, lay, tau, e, tips):
        return self.th(pp, tweak(LEAF, lay, tau, 0, e), b"".join(tips))

    def encode(self, pp, lay, tau, e, m, c):
        return codeword(self.th(pp, tweak(ENC, lay, tau, 0, e), m + struct.pack("<I", c)))

    def ots_sign(self, pp, master, lay, tau, e, m):
        c = 0
        while (x := self.encode(pp, lay, tau, e, m, c)) is None:
            c += 1
        return c, [self.chain(pp, lay, tau, e, i, 0, x[i], self.ots_secret(pp, master, lay, tau, e, i))
                   for i in range(V)]

    def ots_leaf(self, pp, lay, tau, e, m, c, sigma):
        x = self.encode(pp, lay, tau, e, m, c)
        if x is None:
            return None
        tips = [self.chain(pp, lay, tau, e, i, x[i], CHAIN_LEN - 1 - x[i], sigma[i]) for i in range(V)]
        return self.ots_leaf_hash(pp, lay, tau, e, tips)

    def ots_public_leaf(self, pp, master, lay, tau, e):
        tips = [self.chain(pp, lay, tau, e, i, 0, CHAIN_LEN - 1, self.ots_secret(pp, master, lay, tau, e, i))
                for i in range(V)]
        return self.ots_leaf_hash(pp, lay, tau, e, tips)

    # --- Merkle trees -----------------------------------------------------------

    def node(self, pp, lay, tau, level, j, left, right):
        return self.th(pp, tweak(NODE, lay, tau, level, j), left + right)

    def build_up(self, pp, lay, tau, bottom, from_level, to_level, first):
        layers = [bottom]
        for level in range(from_level + 1, to_level + 1):
            base = first >> (level - from_level)
            ch = layers[-1]
            layers.append([self.node(pp, lay, tau, level, base + j, ch[2 * j], ch[2 * j + 1])
                           for j in range(len(ch) // 2)])
        return layers

    def tree_fold(self, pp, lay, tau, e, leaf, path):
        cur = leaf
        for level, sib in enumerate(path):
            left, right = (cur, sib) if (e >> level) & 1 == 0 else (sib, cur)
            cur = self.node(pp, lay, tau, level + 1, e >> (level + 1), left, right)
        return cur

    # --- FORS+C -----------------------------------------------------------------

    def fts_leaf(self, pp, idx, kappa, j, secret):
        return self.th(pp, tweak(FTS_LEAF, kappa, idx, 0, j), secret)

    def fts_node(self, pp, idx, kappa, level, j, left, right):
        return self.th(pp, tweak(FTS_NODE, kappa, idx, level, j), left + right)

    def fts_key_of_roots(self, pp, idx, roots):
        return self.th(pp, tweak(FTS_ROOTS, 0, idx, 0, 0), b"".join(roots))

    def fts_open(self, pp, master, idx, u):
        secrets, paths, roots = [], [], []
        for kappa in range(NUM_FTS_TREES):
            sks = [self.th(pp, tweak(FTS_PRF, kappa, idx, 0, j), master) for j in range(1 << A)]
            nodes = [self.fts_leaf(pp, idx, kappa, j, sks[j]) for j in range(1 << A)]
            secrets.append(sks[u[kappa]])
            path = []
            for level in range(A):
                path.append(nodes[(u[kappa] >> level) ^ 1])
                nodes = [self.fts_node(pp, idx, kappa, level + 1, j, nodes[2 * j], nodes[2 * j + 1])
                         for j in range(len(nodes) // 2)]
            paths.append(path)
            roots.append(nodes[0])
        return self.fts_key_of_roots(pp, idx, roots), secrets, paths

    def fts_recover(self, pp, idx, u, secrets, paths):
        roots = []
        for kappa in range(NUM_FTS_TREES):
            cur = self.fts_leaf(pp, idx, kappa, u[kappa], secrets[kappa])
            for level, sib in enumerate(paths[kappa]):
                left, right = (cur, sib) if (u[kappa] >> level) & 1 == 0 else (sib, cur)
                cur = self.fts_node(pp, idx, kappa, level + 1, u[kappa] >> (level + 1), left, right)
            roots.append(cur)
        return self.fts_key_of_roots(pp, idx, roots)

    # --- The scheme -------------------------------------------------------------

    def message_digest(self, pp, root, rho, m):
        n = int.from_bytes(self.H(tweak(MSG, 0, 0, 0, 0) + pp + rho + root + m)[: (H + K * A) // 8], "little")
        return n & ((1 << H) - 1), [(n >> (H + kappa * A)) & ((1 << A) - 1) for kappa in range(K)]

    def keygen(self, seed: bytes):
        """Returns (P, root, cache): cache is layer 0's 64 nodes at SPLIT_LEVEL."""
        pp = self.th(bytes(N), tweak(PARAMETER, 0, 0, 0, 0), seed)
        leaves = [self.ots_public_leaf(pp, seed, 0, 0, e) for e in range(1 << HEIGHTS[0])]
        layers = self.build_up(pp, 0, 0, leaves, 0, HEIGHTS[0], 0)
        return pp, layers[HEIGHTS[0]][0], layers[SPLIT_LEVEL]

    def tree_path_and_root(self, pp, master, lay, tau, e):
        leaves = [self.ots_public_leaf(pp, master, lay, tau, leaf) for leaf in range(1 << HEIGHTS[lay])]
        layers = self.build_up(pp, lay, tau, leaves, 0, HEIGHTS[lay], 0)
        return [layers[level][(e >> level) ^ 1] for level in range(HEIGHTS[lay])], layers[HEIGHTS[lay]][0]

    def cached_path_and_root(self, pp, master, cache, e):
        first = (e >> SPLIT_LEVEL) << SPLIT_LEVEL
        leaves = [self.ots_public_leaf(pp, master, 0, 0, leaf) for leaf in range(first, first + (1 << SPLIT_LEVEL))]
        below = self.build_up(pp, 0, 0, leaves, 0, SPLIT_LEVEL, first)
        above = self.build_up(pp, 0, 0, list(cache), SPLIT_LEVEL, HEIGHTS[0], 0)
        path = [below[lv][((e >> lv) ^ 1) - (first >> lv)] if lv < SPLIT_LEVEL else above[lv - SPLIT_LEVEL][(e >> lv) ^ 1]
                for lv in range(HEIGHTS[0])]
        return path, above[HEIGHTS[0] - SPLIT_LEVEL][0]

    def sign(self, pp, root, master, cache, m) -> bytes:
        trial = 0
        while True:
            rho = self.H(tweak(RANDOMIZER, 0, 0, trial, 0) + pp + master + m)[:N]
            idx, u = self.message_digest(pp, root, rho, m)
            if u[K - 1] == 0:
                break
            trial += 1
        fts_key, secrets, fpaths = self.fts_open(pp, master, idx, u)
        msg_of_layer = fts_key
        counters, ots, paths = [0] * D, [None] * D, [None] * D
        for lay in reversed(range(D)):
            tau, e = tree_of(idx, lay), leaf_of(idx, lay)
            counters[lay], ots[lay] = self.ots_sign(pp, master, lay, tau, e, msg_of_layer)
            if lay == 0:
                paths[lay], msg_of_layer = self.cached_path_and_root(pp, master, cache, e)
            else:
                paths[lay], msg_of_layer = self.tree_path_and_root(pp, master, lay, tau, e)
        assert msg_of_layer == root
        out = [rho]
        for kappa in range(NUM_FTS_TREES):
            out += [secrets[kappa]] + fpaths[kappa]
        for lay in range(D):
            out += [struct.pack("<I", counters[lay])] + ots[lay] + paths[lay]
        return b"".join(out)

    def verify(self, pp: bytes, root: bytes, m: bytes, sig: bytes) -> bool:
        if len(sig) != SIG_SIZE:
            return False
        at = 0

        def take(n):
            nonlocal at
            at += n
            return sig[at - n : at]

        rho = take(N)
        secrets, fpaths = [], []
        for _ in range(NUM_FTS_TREES):
            secrets.append(take(N))
            fpaths.append([take(N) for _ in range(A)])
        idx, u = self.message_digest(pp, root, rho, m)
        if u[K - 1] != 0:
            return False
        msg_of_layer = self.fts_recover(pp, idx, u, secrets, fpaths)
        layers = []
        for lay in range(D):
            c = struct.unpack("<I", take(4))[0]
            layers.append((c, [take(N) for _ in range(V)], [take(N) for _ in range(HEIGHTS[lay])]))
        for lay in reversed(range(D)):
            tau, e = tree_of(idx, lay), leaf_of(idx, lay)
            c, sigma, path = layers[lay]
            leaf = self.ots_leaf(pp, lay, tau, e, msg_of_layer, c, sigma)
            if leaf is None:
                return False
            msg_of_layer = self.tree_fold(pp, lay, tau, e, leaf, path)
        return msg_of_layer == root


# --- Vectors --------------------------------------------------------------------

VECTORS = pathlib.Path(__file__).resolve().parent.parent / "vectors"


def load_vectors(hash_name: str) -> list[dict]:
    raw = json.loads((VECTORS / f"{hash_name}.json").read_text())["vectors"]
    return [{k: (bytes.fromhex(x) if isinstance(x, str) else x) for k, x in v.items()} for v in raw]


def make_sha256_vectors():
    """vectors/sha256.json from this reference: one key, two messages (pure Python: minutes)."""
    s = Sphincs("sha256")
    seed = bytes([0x11] * 32)
    pp, root, cache = s.keygen(seed)
    entries = []
    for m in (bytes((i * 5 + 3) & 0xFF for i in range(32)), bytes([0xFF] * 32)):
        sig = s.sign(pp, root, seed, cache, m)
        assert s.verify(pp, root, m, sig)
        entries.append({"seed": seed.hex(), "public_param": pp.hex(), "root": root.hex(), "message": m.hex(),
                        "signature": sig.hex()})
    doc = {"scheme": "leanVM SPHINCS+ variant with H = raw SHA-256 compression (host/sphincs_ref.py)",
           "signature_bytes": SIG_SIZE, "vectors": entries}
    (VECTORS / "sha256.json").write_text(json.dumps(doc, indent=2) + "\n")


if __name__ == "__main__":
    if "--make-sha256-vectors" in sys.argv:
        make_sha256_vectors()
        print("wrote vectors/sha256.json")
        sys.exit()
    # BLAKE2s: the full scheme against leanVM's vectors (hashlib: fast).
    s = Sphincs("blake2s")
    keys = {}
    for v in load_vectors("blake2s"):
        if v["seed"] not in keys:
            keys[v["seed"]] = s.keygen(v["seed"])
        pp, root, cache = keys[v["seed"]]
        assert (pp, root) == (v["public_param"], v["root"]), "public key differs from leanVM's"
        assert s.sign(pp, root, v["seed"], cache, v["message"]) == v["signature"], "signature differs from leanVM's"
        assert s.verify(pp, root, v["message"], v["signature"])
    print("blake2s: keys, signatures and verification match leanVM's vectors")
    # SHA-256: the compression against hashlib, then verification of the stored vectors.
    for n in (0, 3, 55):
        msg = b"x" * n
        block = msg + b"\x80" + bytes(55 - n) + struct.pack(">Q", 8 * n)
        assert struct.pack(">8I", *sha256_compress(SHA256_IV, block)) == hashlib.sha256(msg).digest()
    s = Sphincs("sha256")
    for v in load_vectors("sha256"):
        assert s.verify(v["public_param"], v["root"], v["message"], v["signature"])
    print("sha256: compression matches hashlib; vectors/sha256.json signatures verify")
