//! Prove, with leanVM, that `i` is the smallest integer whose
//! `keccak256(abi.encode(uint256(i)))` starts with `D` zero bits.
//!
//! The statement is the guest `guest/pow.py` (zkDSL) together with the public
//! input `(i mod 2^16, i >> 16)`; this binary finds `i` natively, computes the
//! prover's advice (where each digest's 16-bit chunks sit in the guest's lookup
//! table), then proves and verifies.

#[global_allocator]
static ALLOCATOR: bench::Jemalloc = bench::Jemalloc;

use std::collections::BTreeMap;

use bench::Plan;
use clap::Parser;
use lean_compiler::{compile, parse_with_replacements};
use leanvm_core::cpu::{Program, prove, verify};
use primitives::{
    field::{F192, g_pow},
    pretty_f64, pretty_integer,
};
use sha3::{Digest, Keccak256};

const GUEST: &str = include_str!("../guest/pow.py");
/// Digests per fast block (`B` in the guest).
const BLOCK: u64 = 16;
/// The guest's lookup table starts at cell 2, after the two public-input cells.
const TABLE_BASE: usize = 2;

#[derive(Parser)]
struct Cli {
    /// Leading zero bits required of the digest (16 through 32).
    #[arg(long, default_value_t = 18, value_parser = clap::value_parser!(u32).range(16..=32))]
    difficulty: u32,
    /// WHIR inverse-rate logarithm: 1 is rate 1/2, 2 is rate 1/4.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..=4))]
    log_inv_rate: u64,
    /// Measured proving passes after one warmup.
    #[arg(long, default_value_t = 1)]
    repeat: usize,
    /// Idle seconds before each measured pass.
    #[arg(long, default_value_t = 2)]
    cooldown: u64,
    /// Print the guest's bytecode and exit.
    #[arg(long)]
    disasm: bool,
}

/// `keccak256(abi.encode(uint256(j)))`.
fn digest(j: u64) -> [u8; 32] {
    let mut msg = [0u8; 32];
    msg[24..].copy_from_slice(&j.to_be_bytes());
    Keccak256::digest(msg).into()
}

fn lane(d: &[u8; 32], k: usize) -> u64 {
    u64::from_le_bytes(d[8 * k..8 * k + 8].try_into().unwrap())
}

/// The bits of lane 0 that the `difficulty` leading bits of the digest are: byte
/// `k / 8`, most significant bit first.
fn mask(difficulty: u32) -> u64 {
    (0..difficulty).fold(0, |m, k| m | 1 << (8 * (k / 8) + 7 - k % 8))
}

fn find_smallest(difficulty: u32) -> u64 {
    let m = mask(difficulty);
    (0..1u64 << 24).find(|&j| lane(&digest(j), 0) & m == 0).expect("no hit below 2^24")
}

/// The guest compiled for `difficulty`.
fn guest(difficulty: u32) -> Program {
    let mask1 = (mask(difficulty) >> 16) & 0xffff;
    let mask1: Vec<String> = (0..16).map(|k| ((mask1 >> k) & 1).to_string()).collect();
    let step: Vec<String> = (0..BLOCK)
        .map(|t| format!("f192(0, {}, 0)", if t == 0 { 0 } else { ((t - 1) ^ t) << 56 }))
        .collect();
    let repl = BTreeMap::from([
        ("D_PLACEHOLDER".to_string(), difficulty.to_string()),
        ("MASK1_PLACEHOLDER".to_string(), format!("[{}]", mask1.join(", "))),
        ("STEP_PLACEHOLDER".to_string(), format!("[{}]", step.join(", "))),
    ]);
    compile(&parse_with_replacements(GUEST, &repl).expect("the guest parses"))
}

/// The public input: `m[0] = i mod 2^16`, `m[1] = i >> 16`, each a polynomial of degree < 16.
fn public_input(i: u64) -> [F192; 2] {
    [F192::new(i & 0xffff, 0, 0), F192::new(i >> 16, 0, 0)]
}

/// The prover's advice: per digest (j = 0..=i, in order) its four chunk addresses
/// and its lane 1; per full block whether it takes the slow path.
fn advice(i: u64) -> (Vec<Vec<F192>>, Vec<Vec<F192>>) {
    let gpow: Vec<F192> = (0..TABLE_BASE + (1 << 16)).map(|k| F192::from(g_pow(k))).collect();
    let mut w = Vec::with_capacity(i as usize + 1);
    let mut slow = Vec::new();
    let full_blocks = i / BLOCK;
    for j in 0..=i {
        let d = digest(j);
        let l0 = lane(&d, 0);
        let mut entry: Vec<F192> = (0..4).map(|c| gpow[TABLE_BASE + ((l0 >> (16 * c)) & 0xffff) as usize]).collect();
        entry.push(F192::new(lane(&d, 1), 0, 0));
        w.push(entry);
        if j % BLOCK == 0 && j / BLOCK < full_blocks {
            let any_zero = (j..j + BLOCK).any(|k| lane(&digest(k), 0) & 0xffff == 0);
            slow.push(vec![if any_zero { F192::ONE } else { F192::ZERO }]);
        }
    }
    (w, slow)
}

fn main() {
    let cli = Cli::parse();
    let log_inv_rate = cli.log_inv_rate as usize;
    let mut program = guest(cli.difficulty);
    if cli.disasm {
        println!("{}", lean_compiler::disassemble(&program.prog));
        return;
    }
    let i = find_smallest(cli.difficulty);
    let d = digest(i);
    println!(
        "smallest i with keccak256(abi.encode(uint256(i))) starting with {} zero bits",
        cli.difficulty
    );
    println!("  i                           : {}", pretty_integer(i as usize));
    println!("  keccak256                   : 0x{}", d.iter().map(|b| format!("{b:02x}")).collect::<String>());
    let (w, slow) = advice(i);
    program.set_witness("w", w);
    program.set_witness("slow", slow);
    let pi = public_input(i);

    let plan = Plan::new(cli.repeat, cli.cooldown);
    let ((proof, stats), prove_time) = plan.warm_then_measure(|last| {
        let _quiet = (!last).then(bench::suppress_tracing);
        prove(&program, pi, log_inv_rate).expect("the statement proves")
    });
    let (_, verify_time) = Plan::new(cli.repeat, 0).measure_quiet(|_| verify(&program, &pi, &proof).unwrap());

    println!("  hashes proven               : {}", pretty_integer(i as usize + 1));
    println!("  bytecode                    : {} instructions", pretty_integer(program.prog.len()));
    println!("  cycles (VM steps)           : {}", pretty_integer(stats.cycles));
    println!("    details                   : {}", stats.details());
    let bytes = bincode::serialized_size(&proof).expect("proof is serializable");
    println!("  rate                        : 1/{}", 1 << log_inv_rate);
    println!("  proof size                  : {:.1} KiB", bytes as f64 / 1024.0);
    println!(
        "  proving time                : {} s{}      peak memory {} GiB",
        pretty_f64(prove_time.mean()),
        prove_time.spread(),
        pretty_f64(bench::peak_rss_bytes() as f64 / (1u64 << 30) as f64)
    );
    println!("  verifying                   : {} ms", pretty_f64(verify_time.mean() * 1000.0));
}

#[cfg(test)]
mod tests {
    //! Execution-level checks, mostly at difficulty 16 (i = 43,786): the honest run goes
    //! through, and every false claim or forged piece of advice we tried is rejected
    //! by the program's own constraints.
    use super::*;

    const D: u32 = 16;

    fn run(claim: u64, tamper: impl FnOnce(&mut Vec<Vec<F192>>, &mut Vec<Vec<F192>>)) -> bool {
        run_at(D, claim, tamper)
    }

    fn run_at(d: u32, claim: u64, tamper: impl FnOnce(&mut Vec<Vec<F192>>, &mut Vec<Vec<F192>>)) -> bool {
        let mut program = guest(d);
        let (mut w, mut slow) = advice(claim);
        tamper(&mut w, &mut slow);
        program.set_witness("w", w);
        program.set_witness("slow", slow);
        match program.execute(public_input(claim)) {
            Ok(exec) => exec.unconstrained_reads.is_empty(),
            Err(_) => false,
        }
    }

    #[test]
    fn honest_claim_executes() {
        assert!(run(find_smallest(D), |_, _| {}));
    }

    #[test]
    fn a_non_hit_is_rejected() {
        assert!(!run(find_smallest(D) - 1, |_, _| {}));
        assert!(!run(find_smallest(D) + 1, |_, _| {}));
    }

    #[test]
    fn a_hit_that_is_not_the_smallest_is_rejected() {
        let i = find_smallest(D);
        let next = (i + 1..).find(|&j| lane(&digest(j), 0) & mask(D) == 0).unwrap();
        assert!(!run(next, |_, _| {}));
    }

    #[test]
    fn forged_lookups_are_rejected() {
        let i = find_smallest(D);
        // Swapped chunks: the reconstruction no longer matches the digest.
        assert!(!run(i, |w, _| w[100].swap(0, 1)));
        // An address just past the table: the range check fails.
        assert!(!run(i, |w, _| w[100][0] = F192::from(g_pow(TABLE_BASE + (1 << 16)))));
        // A forged lane 1 outside K.
        assert!(!run(i, |w, _| w[100][4] = w[100][4] + F192::new(0, 1, 0)));
    }

    #[test]
    fn the_fast_path_rejects_a_block_with_a_zero_chunk() {
        // At difficulty 16 a zero low chunk is a hit, so take 18, where such blocks
        // lie below i (and go through the slow path, which the honest run shows).
        let d = 18;
        let i = find_smallest(d);
        let blocks: Vec<usize> = (0..(i / BLOCK) as usize)
            .filter(|&b| (0..BLOCK).any(|t| lane(&digest(b as u64 * BLOCK + t), 0) & 0xffff == 0))
            .collect();
        assert!(!blocks.is_empty(), "difficulty 18 has such blocks below i");
        assert!(run_at(d, i, |_, _| {}));
        assert!(!run_at(d, i, |_, slow| slow[blocks[0]] = vec![F192::ZERO]));
    }
}
