"""Python reference for leanVM's SPHINCS+ variant (BLAKE2s, WOTS+C, FORS+C).

A straight port of leanVM `crates/sphincs` (spec: leanVM `doc/sphincs/main.tex`):
Th(P, tw, M) = BLAKE2s-256(tw || P || M)[:16]; w = 3, v = 42, T = 191; d = 3 layers
of heights (12, 7, 7) numbered from the top; a = 10, k = 15 (k - 1 trees, the last
index ground to zero). Used on the host to check what the device produces.

    python host/sphincs_ref.py      # reproduce vectors/leanvm-sphincs-blake2s.json
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import struct

N = 16
W, CHAIN_LEN, V, TARGET_SUM = 3, 8, 42, 191
D, HEIGHTS, H = 3, (12, 7, 7), 26
A, K = 10, 15
NUM_FTS_TREES = K - 1
SPLIT_LEVEL = 6  # layer-0 level whose 2^6 nodes the signer caches (1 KB)
MAX_ATTEMPTS = 1 << 32
SIG_SIZE = N + NUM_FTS_TREES * (1 + A) * N + D * (4 + V * N) + H * N
assert SIG_SIZE == 4924

PRF, CHAIN, LEAF, NODE, ENC, PARAMETER = 0, 1, 2, 3, 4, 5
RANDOMIZER, FTS_PRF, FTS_LEAF, FTS_NODE, FTS_ROOTS, MSG = 7, 8, 9, 10, 11, 12

SUFFIX = [sum(HEIGHTS[lay:]) for lay in range(D + 1)]  # [26, 14, 7, 0]


def blake2s(data: bytes) -> bytes:
    return hashlib.blake2s(data).digest()


def tweak(t: int, lay: int, tau: int, p: int, j: int) -> bytes:
    """[domain_sep=1 | type | layer | 0 | p:LE32 | tree:LE32 | index:LE32]."""
    return bytes([1, t, lay, 0]) + struct.pack("<III", p, tau, j)


def th(pp: bytes, tw: bytes, payload: bytes) -> bytes:
    return blake2s(tw + pp + payload)[:N]


def tree_of(idx: int, lay: int) -> int:
    return idx >> SUFFIX[lay]


def leaf_of(idx: int, lay: int) -> int:
    return (idx >> SUFFIX[lay + 1]) & ((1 << HEIGHTS[lay]) - 1)


# --- WOTS+C ------------------------------------------------------------------


def ots_secret(pp, master, lay, tau, e, i):
    return th(pp, tweak(PRF, lay, tau, i, e), master)


def chain(pp, lay, tau, e, i, start, steps, value):
    for step in range(1, steps + 1):
        value = th(pp, tweak(CHAIN, lay, tau, CHAIN_LEN * i + start + step - 1, e), value)
    return value


def ots_leaf_hash(pp, lay, tau, e, tips):
    return th(pp, tweak(LEAF, lay, tau, 0, e), b"".join(tips))


def codeword(digest: bytes):
    x = []
    for q in range(2):
        d = int.from_bytes(digest[8 * q : 8 * q + 8], "little")
        if d >> (W * V // 2):
            return None
        x += [(d >> (W * r)) & (CHAIN_LEN - 1) for r in range(V // 2)]
    return x if sum(x) == TARGET_SUM else None


def encode(pp, lay, tau, e, m, c):
    return codeword(th(pp, tweak(ENC, lay, tau, 0, e), m + struct.pack("<I", c)))


def ots_sign(pp, master, lay, tau, e, m):
    for c in range(MAX_ATTEMPTS):
        x = encode(pp, lay, tau, e, m, c)
        if x is not None:
            return c, [chain(pp, lay, tau, e, i, 0, x[i], ots_secret(pp, master, lay, tau, e, i)) for i in range(V)]
    raise RuntimeError("no admissible encoding")


def ots_leaf(pp, lay, tau, e, m, c, sigma):
    x = encode(pp, lay, tau, e, m, c)
    if x is None:
        return None
    tips = [chain(pp, lay, tau, e, i, x[i], CHAIN_LEN - 1 - x[i], sigma[i]) for i in range(V)]
    return ots_leaf_hash(pp, lay, tau, e, tips)


def ots_public_leaf(pp, master, lay, tau, e):
    tips = [chain(pp, lay, tau, e, i, 0, CHAIN_LEN - 1, ots_secret(pp, master, lay, tau, e, i)) for i in range(V)]
    return ots_leaf_hash(pp, lay, tau, e, tips)


# --- Merkle trees ------------------------------------------------------------


def node(pp, lay, tau, level, j, left, right):
    return th(pp, tweak(NODE, lay, tau, level, j), left + right)


def build_up(pp, lay, tau, bottom, from_level, to_level, first):
    layers = [bottom]
    for level in range(from_level + 1, to_level + 1):
        base = first >> (level - from_level)
        ch = layers[-1]
        layers.append([node(pp, lay, tau, level, base + j, ch[2 * j], ch[2 * j + 1]) for j in range(len(ch) // 2)])
    return layers


def tree_fold(pp, lay, tau, e, leaf, path):
    cur = leaf
    for level, sib in enumerate(path):
        left, right = (cur, sib) if (e >> level) & 1 == 0 else (sib, cur)
        cur = node(pp, lay, tau, level + 1, e >> (level + 1), left, right)
    return cur


# --- FORS+C ------------------------------------------------------------------


def fts_leaf(pp, idx, kappa, j, secret):
    return th(pp, tweak(FTS_LEAF, kappa, idx, 0, j), secret)


def fts_node(pp, idx, kappa, level, j, left, right):
    return th(pp, tweak(FTS_NODE, kappa, idx, level, j), left + right)


def fts_key_of_roots(pp, idx, roots):
    return th(pp, tweak(FTS_ROOTS, 0, idx, 0, 0), b"".join(roots))


def fts_open(pp, master, idx, u):
    secrets, paths, roots = [], [], []
    for kappa in range(NUM_FTS_TREES):
        opened = u[kappa]
        sks = [th(pp, tweak(FTS_PRF, kappa, idx, 0, j), master) for j in range(1 << A)]
        nodes = [fts_leaf(pp, idx, kappa, j, sks[j]) for j in range(1 << A)]
        secrets.append(sks[opened])
        path = []
        for level in range(A):
            path.append(nodes[(opened >> level) ^ 1])
            nodes = [fts_node(pp, idx, kappa, level + 1, j, nodes[2 * j], nodes[2 * j + 1]) for j in range(len(nodes) // 2)]
        paths.append(path)
        roots.append(nodes[0])
    return fts_key_of_roots(pp, idx, roots), secrets, paths


def fts_recover(pp, idx, u, secrets, paths):
    roots = []
    for kappa in range(NUM_FTS_TREES):
        opened = u[kappa]
        cur = fts_leaf(pp, idx, kappa, opened, secrets[kappa])
        for level, sib in enumerate(paths[kappa]):
            left, right = (cur, sib) if (opened >> level) & 1 == 0 else (sib, cur)
            cur = fts_node(pp, idx, kappa, level + 1, opened >> (level + 1), left, right)
        roots.append(cur)
    return fts_key_of_roots(pp, idx, roots)


# --- The scheme --------------------------------------------------------------


def message_digest(pp, root, rho, m):
    digest = blake2s(tweak(MSG, 0, 0, 0, 0) + pp + rho + root + m)[: (H + K * A) // 8]
    nbits = int.from_bytes(digest, "little")
    idx = nbits & ((1 << H) - 1)
    u = [(nbits >> (H + kappa * A)) & ((1 << A) - 1) for kappa in range(K)]
    return idx, u


def derive_public_param(seed: bytes) -> bytes:
    return th(bytes(N), tweak(PARAMETER, 0, 0, 0, 0), seed)


def key_gen_from_seed(seed: bytes):
    """Returns (public_param, root, cache): cache is layer 0's 64 nodes at SPLIT_LEVEL."""
    pp = derive_public_param(seed)
    leaves = [ots_public_leaf(pp, seed, 0, 0, e) for e in range(1 << HEIGHTS[0])]
    layers = build_up(pp, 0, 0, leaves, 0, HEIGHTS[0], 0)
    return pp, layers[HEIGHTS[0]][0], layers[SPLIT_LEVEL]


def tree_path_and_root(pp, master, lay, tau, e):
    leaves = [ots_public_leaf(pp, master, lay, tau, leaf) for leaf in range(1 << HEIGHTS[lay])]
    layers = build_up(pp, lay, tau, leaves, 0, HEIGHTS[lay], 0)
    return [layers[level][(e >> level) ^ 1] for level in range(HEIGHTS[lay])], layers[HEIGHTS[lay]][0]


def cached_path_and_root(pp, master, cache, e):
    first = (e >> SPLIT_LEVEL) << SPLIT_LEVEL
    leaves = [ots_public_leaf(pp, master, 0, 0, leaf) for leaf in range(first, first + (1 << SPLIT_LEVEL))]
    below = build_up(pp, 0, 0, leaves, 0, SPLIT_LEVEL, first)
    above = build_up(pp, 0, 0, list(cache), SPLIT_LEVEL, HEIGHTS[0], 0)
    path = []
    for level in range(HEIGHTS[0]):
        index = (e >> level) ^ 1
        path.append(below[level][index - (first >> level)] if level < SPLIT_LEVEL else above[level - SPLIT_LEVEL][index])
    return path, above[HEIGHTS[0] - SPLIT_LEVEL][0]


def sign(pp, root, master, cache, m):
    """Returns (signature bytes, stats)."""
    for trial in range(MAX_ATTEMPTS):
        rho = blake2s(tweak(RANDOMIZER, 0, 0, trial, 0) + pp + master + m)[:N]
        idx, u = message_digest(pp, root, rho, m)
        if u[K - 1] == 0:
            break
    fts_key, secrets, fpaths = fts_open(pp, master, idx, u)
    msg_of_layer = fts_key
    counters, ots, paths = [0] * D, [None] * D, [None] * D
    for lay in reversed(range(D)):
        tau, e = tree_of(idx, lay), leaf_of(idx, lay)
        counters[lay], ots[lay] = ots_sign(pp, master, lay, tau, e, msg_of_layer)
        if lay == 0:
            paths[lay], msg_of_layer = cached_path_and_root(pp, master, cache, e)
        else:
            paths[lay], msg_of_layer = tree_path_and_root(pp, master, lay, tau, e)
    assert msg_of_layer == root
    out = [rho]
    for kappa in range(NUM_FTS_TREES):
        out += [secrets[kappa]] + fpaths[kappa]
    for lay in range(D):
        out += [struct.pack("<I", counters[lay])] + ots[lay] + paths[lay]
    sig = b"".join(out)
    assert len(sig) == SIG_SIZE
    return sig, {"digest_trials": trial + 1, "counters": counters, "idx": idx}


def parse(sig: bytes):
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
    counters, ots, paths = [], [], []
    for lay in range(D):
        counters.append(struct.unpack("<I", take(4))[0])
        ots.append([take(N) for _ in range(V)])
        paths.append([take(N) for _ in range(HEIGHTS[lay])])
    assert at == SIG_SIZE
    return rho, secrets, fpaths, counters, ots, paths


def verify(pp: bytes, root: bytes, m: bytes, sig: bytes) -> bool:
    if len(sig) != SIG_SIZE:
        return False
    rho, secrets, fpaths, counters, ots, paths = parse(sig)
    idx, u = message_digest(pp, root, rho, m)
    if u[K - 1] != 0:
        return False
    msg_of_layer = fts_recover(pp, idx, u, secrets, fpaths)
    for lay in reversed(range(D)):
        tau, e = tree_of(idx, lay), leaf_of(idx, lay)
        leaf = ots_leaf(pp, lay, tau, e, msg_of_layer, counters[lay], ots[lay])
        if leaf is None:
            return False
        msg_of_layer = tree_fold(pp, lay, tau, e, leaf, paths[lay])
    return msg_of_layer == root


# ---------------------------------------------------------------------------

REPO = pathlib.Path(__file__).resolve().parent.parent
VECTORS = REPO / "vectors" / "leanvm-sphincs-blake2s.json"


def load_vectors() -> list[dict]:
    out = []
    for v in json.loads(VECTORS.read_text())["vectors"]:
        out.append({k: (bytes.fromhex(x) if isinstance(x, str) else x) for k, x in v.items()})
    return out


if __name__ == "__main__":
    import time

    vectors = load_vectors()
    keys = {}
    for v in vectors:
        if v["seed"] not in keys:
            t0 = time.perf_counter()
            keys[v["seed"]] = key_gen_from_seed(v["seed"])
            print(f"keygen {v['seed'][:4].hex()}..: {time.perf_counter() - t0:.1f}s")
        pp, root, cache = keys[v["seed"]]
        assert (pp, root) == (v["public_param"], v["root"]), "public key mismatch"
        assert verify(pp, root, v["message"], v["signature"]), "vector does not verify"
        sig, stats = sign(pp, root, v["seed"], cache, v["message"])
        assert sig == v["signature"], "signer does not reproduce the vector"
        assert stats["counters"] == v["counters"]
        bad = bytearray(v["message"])
        bad[0] ^= 1
        assert not verify(pp, root, bytes(bad), v["signature"])
    print(f"all {len(vectors)} vectors: keys, signatures (byte for byte) and verification match leanVM")
