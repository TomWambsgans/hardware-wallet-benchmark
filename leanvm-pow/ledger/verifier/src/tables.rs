//! The six instruction tables: their widths, their bus flushes evaluated at given column values, their
//! constraints. leanVM's `layout.rs` builds each flush as a symbolic degree-2 form; here each one is evaluated
//! directly, flush by flush and coordinate by coordinate, in the same order.

use crate::field::{E, GEN, ONE, ZERO};

pub const BUS_BITS: usize = 4;
pub const TUPLE: usize = 1 << BUS_BITS;

pub const OP_XOR: usize = 0;
pub const OP_MUL: usize = 1;
pub const OP_SET: usize = 2;
pub const OP_DEREF: usize = 3;
pub const OP_JUMP: usize = 4;
pub const OP_KECCAK: usize = 5;
pub const N_TABLES: usize = 6;

pub const NUM_GLOBAL_COLUMNS: usize = 6;
pub const MEMORY_0: usize = 0;
pub const MEMORY_1: usize = 1;
pub const MEMORY_2: usize = 2;
pub const MEMORY_FINAL_COUNTERS: usize = 3;
pub const BYTECODE_FINAL_COUNTERS: usize = 4;
pub const QKECCAK: usize = 5;

pub const SEP_STATE: E = ONE;
pub const SEP_MEM: E = GEN;
pub const SEP_BYTECODE: E = E::new(4, 0, 0);

// KECCAK's columns: a head, the input lanes, the output lanes, a read count per cell read then written, cnt_bc.
const KECCAK_HEAD: usize = 13;
pub const KECCAK_IN: usize = KECCAK_HEAD;
pub const KECCAK_OUT: usize = KECCAK_IN + 25;
const KECCAK_CELLS: usize = 13;
const KECCAK_CNT: usize = KECCAK_OUT + 25;
const KECCAK_CNT_BC: usize = KECCAK_CNT + 2 * KECCAK_CELLS;

pub const TABLE_WIDTHS: [usize; N_TABLES] = [15, 15, 8, 15, 14, KECCAK_CNT_BC + 1];
pub const GLOBAL_COLUMN_BASES: [usize; N_TABLES] = {
    let mut bases = [NUM_GLOBAL_COLUMNS; N_TABLES];
    let mut table = 1;
    while table < N_TABLES {
        bases[table] = bases[table - 1] + TABLE_WIDTHS[table - 1];
        table += 1;
    }
    bases
};
pub const N_COLUMNS: usize = GLOBAL_COLUMN_BASES[N_TABLES - 1] + TABLE_WIDTHS[N_TABLES - 1];

/// Each table's flush count (push and pull alike).
pub const N_FLUSHES: [usize; N_TABLES] = [5, 5, 3, 5, 5, 2 + 2 * KECCAK_CELLS];
pub const N_BUS_BLOCKS: usize = {
    let mut sum = 0;
    let mut t = 0;
    while t < N_TABLES {
        sum += N_FLUSHES[t];
        t += 1;
    }
    sum
};

/// The read-count columns of each table, in column order: one count-side block each.
pub fn count_columns(table: usize) -> &'static [u8] {
    const ARITH: [u8; 4] = [11, 12, 13, 14];
    const SET: [u8; 2] = [6, 7];
    const DEREF: [u8; 4] = [11, 12, 13, 14];
    const JUMP: [u8; 4] = [8, 9, 10, 11];
    const KECCAK: [u8; 27] = {
        let mut out = [0u8; 27];
        let mut i = 0;
        while i < 27 {
            out[i] = (KECCAK_CNT + i) as u8;
            i += 1;
        }
        out
    };
    match table {
        OP_XOR | OP_MUL => &ARITH,
        OP_SET => &SET,
        OP_DEREF => &DEREF,
        OP_JUMP => &JUMP,
        _ => &KECCAK,
    }
}
pub const N_COUNT_BLOCKS: usize = 4 + 4 + 2 + 4 + 4 + 27;

/// The jump table's constraints, `b + cond·w` and `cond·(b + 1)`; the others have none.
pub const N_CONSTRAINTS: usize = 2;
pub fn jump_constraints(v: &[E]) -> [E; 2] {
    let (condition, inverse, flag) = (v[5], v[12], v[13]);
    [flag + condition * inverse, condition * (flag + ONE)]
}

fn g(exponent: usize) -> E {
    E::monomial(exponent)
}

/// A tuple being written, coordinate by coordinate.
struct Tuple<'a> {
    out: &'a mut [E; TUPLE],
    len: usize,
}

impl Tuple<'_> {
    fn push(&mut self, value: E) {
        self.out[self.len] = value;
        self.len += 1;
    }
}

/// Flush `flush` of `table`, the push side (`push`) or the pull one, at column values `v`: its tuple into `out`.
/// Returns how many coordinates it has; the rest of `out` is zero.
pub fn flush(table: usize, flush: usize, push: bool, v: &[E], out: &mut [E; TUPLE]) -> usize {
    *out = [ZERO; TUPLE];
    let mut t = Tuple { out, len: 0 };
    let col = |i: usize| v[i];
    let prod = |a: usize, b: usize| v[a] * v[b];
    // `[SEP, address, count (×g on push), suffix...]`.
    let counted = |t: &mut Tuple, sep: E, address: E, count: usize| {
        t.push(sep);
        t.push(address);
        t.push(if push { GEN * v[count] } else { v[count] });
    };
    let (pc, fp) = (0, 1);
    if flush == 0 {
        // The state: push the successor, pull the current one.
        t.push(SEP_STATE);
        if table == OP_JUMP {
            let (dest, frame, b) = (6, 7, 13);
            if push {
                t.push(prod(b, dest) + GEN * prod(b, pc) + GEN * col(pc));
                t.push(prod(b, frame) + prod(b, fp) + col(fp));
            } else {
                t.push(col(pc));
                t.push(col(fp));
            }
        } else if push {
            t.push(GEN * col(pc));
            t.push(col(fp));
        } else {
            t.push(col(pc));
            t.push(col(fp));
        }
        return t.len;
    }
    if flush == 1 {
        // The bytecode: [SEP_BYTECODE, pc, count, g^opcode, operands...].
        let (count, operands): (usize, &[usize]) = match table {
            OP_XOR | OP_MUL => (14, &[2, 3, 4]),
            OP_SET => (7, &[2, 3, 4, 5]),
            OP_DEREF => (14, &[2, 3, 4, 5, 6]),
            OP_JUMP => (11, &[2, 3, 4]),
            _ => (KECCAK_CNT_BC, &[2, 3, 4, 5, 6, 7, 8, 9, 10, 11]),
        };
        counted(&mut t, SEP_BYTECODE, col(pc), count);
        t.push(g(table));
        for &operand in operands {
            t.push(col(operand));
        }
        // Operands past the named ones are zero, up to five (ten for KECCAK).
        t.len = if table == OP_KECCAK { 14 } else { 9 };
        return t.len;
    }
    // Memory: [SEP_MEM, address, count, limb 0, limb 1, limb 2].
    let memory = |t: &mut Tuple, address: E, count: usize, limbs: [E; 3]| {
        counted(t, SEP_MEM, address, count);
        for limb in limbs {
            t.push(limb);
        }
    };
    match table {
        OP_XOR | OP_MUL => {
            let (va, vb) = ([5, 6, 7], [8, 9, 10]);
            match flush {
                2 => memory(&mut t, prod(fp, 2), 11, va.map(col)),
                3 => memory(&mut t, prod(fp, 3), 12, vb.map(col)),
                _ => {
                    let result = if table == OP_MUL {
                        let p = |j: usize, k: usize| prod(va[j], vb[k]);
                        [
                            p(0, 0) + p(1, 2) + p(2, 1),
                            p(0, 1) + p(1, 0) + p(1, 2) + p(2, 1) + p(2, 2),
                            p(0, 2) + p(1, 1) + p(2, 0) + p(2, 2),
                        ]
                    } else {
                        [0, 1, 2].map(|i| col(va[i]) + col(vb[i]))
                    };
                    memory(&mut t, prod(fp, 4), 13, result);
                }
            }
        }
        OP_SET => memory(&mut t, prod(fp, 2), 6, [3, 4, 5].map(col)),
        OP_DEREF => {
            let (f_pc, f_fp, ptr) = (5, 6, 7);
            let v3 = [8, 9, 10];
            match flush {
                2 => memory(&mut t, prod(fp, 2), 11, [col(ptr), ZERO, ZERO]),
                3 => {
                    // v2 = (1 + f_pc + f_fp)·v3 + f_pc·(g^2·pc) + f_fp·fp, the K-valued sources in the low limb only.
                    let gated = |lane: usize| col(lane) + prod(f_pc, lane) + prod(f_fp, lane);
                    let store = [
                        gated(v3[0]) + g(2) * prod(f_pc, pc) + prod(f_fp, fp),
                        gated(v3[1]),
                        gated(v3[2]),
                    ];
                    memory(&mut t, prod(ptr, 3), 12, store);
                }
                _ => memory(&mut t, prod(fp, 4), 13, v3.map(col)),
            }
        }
        OP_JUMP => {
            let (operand, count, value) = [(2, 8, 5), (3, 9, 6), (4, 10, 7)][flush - 2];
            memory(&mut t, prod(fp, operand), count, [col(value), ZERO, ZERO]);
        }
        _ => {
            // Thirteen cells read, then thirteen written, each in the layout its flag names.
            let side = (flush - 2) / KECCAK_CELLS;
            let cell = (flush - 2) % KECCAK_CELLS;
            let (lanes, flag, missing) = if side == 0 {
                (KECCAK_IN, 10, Some(12))
            } else {
                (KECCAK_OUT, 11, None)
            };
            let (even, odd) = (cell_lanes(false, cell), cell_lanes(true, cell));
            let lane = |l: Option<usize>| l.map(|l| lanes + l);
            let limb = |e: Option<usize>, o: Option<usize>| {
                let (a, b) = (lane(e).or(missing), lane(o).or(missing));
                if a == b {
                    return a.map_or(ZERO, col);
                }
                let mut sum = ZERO;
                if let Some(a) = a {
                    sum += col(a) + prod(flag, a);
                }
                if let Some(b) = b {
                    sum += prod(flag, b);
                }
                sum
            };
            let address = if side == 0 {
                match cell {
                    0..4 => prod(fp, 2 + cell),
                    4..8 => g(cell - 4) * prod(fp, 6),
                    8 => prod(fp, 7),
                    _ => g(cell - 9) * prod(fp, 8),
                }
            } else {
                g(cell) * prod(fp, 9)
            };
            let limbs = [limb(even.0, odd.0), limb(even.1, odd.1), ZERO];
            memory(&mut t, address, KECCAK_CNT + KECCAK_CELLS * side + cell, limbs);
        }
    }
    t.len
}

/// The lanes cell `cell` of a sponge state holds, `(lo, hi)`, in the even or the odd layout.
fn cell_lanes(odd: bool, cell: usize) -> (Option<usize>, Option<usize>) {
    match (odd, cell) {
        (_, 9..) | (true, 1..) => (Some(2 * cell - 1), Some(2 * cell)),
        (true, _) => (None, Some(0)),
        (false, 8) => (Some(16), None),
        (false, _) => (Some(2 * cell), Some(2 * cell + 1)),
    }
}

/// A table's padding row: zero, but for KECCAK's output lanes, the permutation of zeros.
pub fn padding_row(table: usize) -> &'static [E] {
    const ZEROS: [E; 90] = [ZERO; 90];
    const KECCAK: [E; 90] = {
        let lanes = crate::hash::keccak_f_const([0; 25]);
        let mut row = [ZERO; 90];
        let mut lane = 0;
        while lane < 25 {
            row[KECCAK_OUT + lane] = E::new(lanes[lane], 0, 0);
            lane += 1;
        }
        row
    };
    if table == OP_KECCAK {
        &KECCAK
    } else {
        &ZEROS[..TABLE_WIDTHS[table]]
    }
}

// ---------------------------------------------------------------- the q_keccak slots

const QKECCAK_SLOTS: usize = 25 * 2; // the two committed states per step at depth 12
const QKECCAK_SPARE: usize = 64 - QKECCAK_SLOTS;

const fn spare_local(k: usize) -> usize {
    if k < KECCAK_IN { k } else { KECCAK_CNT + (k - KECCAK_IN) }
}

/// The slot of `q_keccak` the global column `column` is, if it is one: an input lane, or a KECCAK column riding
/// a spare slot.
pub fn qkeccak_slot(column: usize) -> Option<usize> {
    let local = column.checked_sub(GLOBAL_COLUMN_BASES[OP_KECCAK])?;
    for k in 0..QKECCAK_SPARE {
        if spare_local(k) == local {
            return Some(QKECCAK_SLOTS + k);
        }
    }
    (KECCAK_IN..KECCAK_OUT).contains(&local).then(|| local - KECCAK_IN)
}

/// Whether `column` is a KECCAK output lane, which nothing commits.
pub fn is_keccak_output(column: usize) -> bool {
    let base = GLOBAL_COLUMN_BASES[OP_KECCAK];
    (base + KECCAK_OUT..base + KECCAK_OUT + 25).contains(&column)
}
