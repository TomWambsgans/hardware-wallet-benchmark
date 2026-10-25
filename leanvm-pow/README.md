# keccak-pow: proving the smallest proof of work with leanVM

A benchmark in which a laptop proves, in one [leanVM](https://github.com/leanEthereum/leanVM)
proof, that `i` is the **smallest** integer such that

    keccak256(abi.encode(uint256(i)))   starts with D zero bits

(Solidity's `keccak256` of the 32-byte big-endian word). The program hashes every `j <= i` and
proves that no `j < i` is a hit and that `i` is. For `D = 18`, `i = 193,672`
(`keccak256 = 0x00003d8ca97d…`), which is 193,673 hashes proven.

From this directory:

```bash
cargo run --release -- --difficulty 18 --log-inv-rate 2      # rate 1/4
cargo run --release -- --difficulty 18 --log-inv-rate 1      # rate 1/2
cargo test --release                                         # false claims and forged advice are rejected
```

## Results

`D = 18` (5,404,594 cycles, 2^27.52 committed, bytecode 2,048 instructions), on an AMD Ryzen 7 PRO
8700GE (8 cores / 16 threads, AVX-512, shared with other jobs):

| rate | proof size | proving time | peak memory | verifying |
|---|---|---|---|---|
| 1/4 | **267.2 KiB** | 6.6 s | 19.0 GiB | 12.9 ms |
| 1/2 | 365.6 KiB | 6.2 s | 19.0 GiB | 14.4 ms |

Full outputs: [`results/`](results).

```
smallest i with keccak256(abi.encode(uint256(i))) starting with 18 zero bits
  i                           : 193,672
  keccak256                   : 0x00003d8ca97d7cb7bb09caa2b51034824f0593f8075c825135b0fa2923f44340
  hashes proven               : 193,673
  bytecode                    : 2,048 instructions
  cycles (VM steps)           : 5,404,594
    details                   : MUL 2^20.89 (36.0%)  DEREF 2^20.678 (31.0%)  XOR 2^20.033 (19.9%)  SET 2^18.474 (6.7%)  KECCAK 2^17.563 (3.6%)  JUMP 2^17.226 (2.8%)  MEMORY 2^23.134  BYTECODE 2^10.077  TOTAL_COMMITTED 2^27.524
  rate                        : 1/4
  proof size                  : 267.2 KiB
  proving time                : 6.623 s      peak memory 18.959 GiB
  verifying                   : 12.918 ms
```

`D = 16` (`i = 43,786`): 1.44M cycles, 2^25.6 committed, 330 KiB, 12.2 s, 4.8 GiB.

The bytecode is 2,048 instructions (the lookup table is built by a loop at run time, not
unrolled), so the verifier's bytecode evaluation stays cheap.

## Why not D = 20

One hash costs about 28 cycles, 47 memory cells and 630 committed field elements (the KECCAK
and its 13 output cells alone are about 200). `D = 20` (`i = 1,258,904`) would commit about
2^29.6 elements, beyond leanVM's `MAX_MU = 28` and about 80 GB of prover memory. That needs
recursion: leaves proving ranges of `j`, merged 2-to-1.

## The statement

The guest is [`pow/guest/pow.py`](pow/guest/pow.py) (zkDSL). Its public input is
`m[0] = i mod 2^16`, `m[1] = i >> 16`, with `i < 2^24` and `16 <= D <= 32`. `D` is compiled into
the bytecode.

- **Encoding.** The message is two 16-byte cells: zero, then `y·(x^40·h + x^48·p + x^56·q)` for
  `j = 2^16·h + 2^8·p + q`. The loops walk `h`, `p` and the blocks of `q` with g-power counters,
  and turn each counter into its byte with a table read.
- **The check.** "Starts with D zero bits" is a mask on lane 0 of the digest, `L0`, the low limb
  of `out[0] = L0 + y·L1`:
  - bits 0..15 (bytes 0 and 1),
  - then the next `D - 16` bits of byte 2, most significant first.
- **Decomposition by lookup.** `L0 = r0 + x^16·r1 + x^32·r2 + x^48·r3`. Each chunk is read at a
  hinted address `a = g^k` and range-checked in the exponent (`TOP / a` must be an address too,
  so `k <= 65537`). Every cell `m[0..65537]` holds a polynomial of degree < 16:
  - `m[0]` and `m[1]` are the public input, bit-decomposed once to prove it;
  - `m[2..2+2^16)` is the table `T[e] = e`, written by the program into `main`'s frame.

  So the decomposition is unique, and `L1` is pinned in `K` by `assert_in_k`. Cost: 3
  instructions per chunk.
- **Not a hit.** For each `j < i`, `r0 != 0` or a masked bit of `r1` is set.
  - Fast path: a block of 16 digests proves every `r0 != 0` with one product.
  - Slow path: a block holding a digest with `r0 == 0` (about 1 in 4096 blocks) loops over its
    digests one at a time and bit-decomposes `r1`.

  The prover picks the path with an unconstrained hint, since both paths are sound.
- **Hit.** For `i`, `r0 == 0` and no masked bit of `r1` is set.

## Credits

The VM, its zkDSL compiler and the proof system are
[leanEthereum/leanVM](https://github.com/leanEthereum/leanVM) (MIT / Apache-2.0), vendored
unmodified under [`vendor/leanVM`](vendor/README.md).
