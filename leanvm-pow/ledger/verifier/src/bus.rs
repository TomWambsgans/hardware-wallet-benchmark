//! The layout of the committed columns, the bus balance (a batched GKR over its three grand products), and the
//! table sumcheck. leanVM's `layout.rs` and `bus.rs`, with every symbolic form replaced by evaluating
//! [`tables::flush`] where the form was evaluated.

use crate::field::{E, ONE, ZERO};
use crate::keccak::KeccakShape;
use crate::tables::{
    self, BUS_BITS, GLOBAL_COLUMN_BASES, N_BUS_BLOCKS, N_COLUMNS, N_CONSTRAINTS, N_COUNT_BLOCKS, N_FLUSHES, N_TABLES,
    OP_JUMP, OP_KECCAK, QKECCAK, SEP_BYTECODE, SEP_MEM, SEP_STATE, TABLE_WIDTHS, TUPLE,
};
use crate::transcript::{
    Source, Transcript, dot, eq_kernel, fold_eval, index_mle, log2_ceil, log2_strict, padding_weight, poly_eval,
    stack_offsets,
};
use crate::{Error, MAX_POINT, require};

pub const MIN_STACKED_LOG: usize = 15;
pub const MAX_STACKED_LOG: usize = 28;
const MAX_TABLE_LOG: usize = 32;
const KECCAK_DEPTH: usize = 12;
const KECCAK_MIN_STEPS_LOG: usize = 9;
const TABLE_LOG_FLOORS: [usize; N_TABLES] = [0, 0, 0, 0, 0, KECCAK_MIN_STEPS_LOG];

/// Where a column sits in the stack: its point fills the low `variables` coordinates, the bits of `index` (a
/// multiple of `2^variables`) fix the rest. `NONE` for a KECCAK output lane, which nothing commits.
#[derive(Clone, Copy, Debug)]
pub struct Slot {
    pub variables: u8,
    pub index: u32,
}

impl Slot {
    pub const NONE: Slot = Slot {
        variables: u8::MAX,
        index: 0,
    };

    pub fn is_some(&self) -> bool {
        self.variables != u8::MAX
    }

    pub fn variables(&self) -> usize {
        self.variables as usize
    }

    /// eq weight of the coordinates above the window.
    pub fn eq_above(&self, point: &[E]) -> E {
        crate::transcript::eq_bits((self.index >> self.variables) as u64, &point[self.variables()..])
    }
}

pub struct Layout {
    pub log_memory: usize,
    pub log_bytecode: usize,
    pub table_rows: [u64; N_TABLES],
    pub heights: [usize; N_TABLES],
    pub stack_log: usize,
    pub placed: u64,
    pub keccak: KeccakShape,
}

#[inline(never)]
pub fn build_layout(
    log_memory: u64,
    table_rows: &[u64; N_TABLES],
    slots: &mut [Slot; N_COLUMNS],
) -> Result<Layout, Error> {
    let log_bytecode = log2_strict(crate::bytecode::len())?;
    require(
        (16..=32).contains(&log_memory)
            && table_rows.iter().all(|&rows| rows <= 1 << MAX_TABLE_LOG)
            && (BUS_BITS..=32 + BUS_BITS).contains(&log_bytecode),
        Error::AnnouncedTableSizes,
    )?;
    let log_bytecode = log_bytecode - BUS_BITS;
    let log_memory = log_memory as usize;
    let mut heights = [0; N_TABLES];
    for t in 0..N_TABLES {
        heights[t] = log2_ceil(table_rows[t]).max(TABLE_LOG_FLOORS[t]);
    }
    let keccak = KeccakShape {
        log_steps: heights[OP_KECCAK],
        depth: KECCAK_DEPTH,
    };
    let mut kappas = [0usize; N_COLUMNS];
    kappas[..6].copy_from_slice(&[
        log_memory,
        log_memory,
        log_memory,
        log_memory,
        log_bytecode,
        keccak.log_steps + keccak.slot_bits(),
    ]);
    for t in 0..N_TABLES {
        let base = GLOBAL_COLUMN_BASES[t];
        kappas[base..base + TABLE_WIDTHS[t]].fill(heights[t]);
    }
    // The columns with a block of their own, stacked largest first.
    let mut blocks = [0u16; N_COLUMNS];
    let mut block_kappas = [0usize; N_COLUMNS];
    let mut n_blocks = 0;
    for column in 0..N_COLUMNS {
        if tables::qkeccak_slot(column).is_none() && !tables::is_keccak_output(column) {
            blocks[n_blocks] = column as u16;
            block_kappas[n_blocks] = kappas[column];
            n_blocks += 1;
        }
    }
    let mut block_offsets = [0u64; N_COLUMNS];
    let total_log = stack_offsets(&block_kappas[..n_blocks], &mut block_offsets);
    let mut offsets = [u64::MAX; N_COLUMNS];
    let mut placed = 0u64;
    for b in 0..n_blocks {
        offsets[blocks[b] as usize] = block_offsets[b];
        placed += 1 << block_kappas[b];
    }
    let stack_log = MIN_STACKED_LOG.max(total_log);
    require(stack_log <= MAX_STACKED_LOG, Error::CommittedSize)?;
    *slots = [Slot::NONE; N_COLUMNS];
    for column in 0..N_COLUMNS {
        let index = match tables::qkeccak_slot(column) {
            Some(slot) => offsets[QKECCAK] + ((slot as u64) << kappas[column]),
            None if offsets[column] != u64::MAX => offsets[column],
            None => continue,
        };
        // Below 2^stack_log <= 2^28.
        slots[column] = Slot {
            variables: kappas[column] as u8,
            index: index as u32,
        };
    }
    Ok(Layout {
        log_memory,
        log_bytecode,
        table_rows: *table_rows,
        heights,
        stack_log,
        placed,
        keccak,
    })
}

/// A point of at most `MAX_POINT` coordinates.
#[derive(Clone, Copy)]
pub struct Point {
    pub coords: [E; MAX_POINT],
    pub len: usize,
}

impl Point {
    pub const EMPTY: Point = Point {
        coords: [ZERO; MAX_POINT],
        len: 0,
    };

    pub fn as_slice(&self) -> &[E] {
        &self.coords[..self.len]
    }
}

/// The three grand-product GKRs, batched: the count root, the point, and the three claims there.
fn verify_gkr<S: Source>(depth: usize, transcript: &mut Transcript<S>) -> Result<(E, Point, [E; 3]), Error> {
    let shared = transcript.next_scalar()?;
    let count = transcript.next_scalar()?;
    let mut point = Point::EMPTY;
    let mut values = [shared, shared, count];
    let mut layer = depth;
    while layer > 0 {
        let step = if layer % 2 == 1 { 1 } else { 2 };
        let combiner = transcript.sample();
        let mut claim = poly_eval(&values, combiner);
        let n_coeffs = (1 << step) + 1;
        let mut x = [ZERO; MAX_POINT];
        let mut message = [ZERO; 5];
        for i in 0..point.len {
            transcript.round_poly(n_coeffs, claim, Some(point.coords[i]), &mut message)?;
            x[i] = transcript.sample();
            claim = poly_eval(&message[..n_coeffs], x[i]);
        }
        let mut children = [[ZERO; 4]; 3];
        for child in children.iter_mut() {
            transcript.next_scalars(&mut child[..1 << step])?;
        }
        let mut products = [ONE; 3];
        for (product, child) in products.iter_mut().zip(&children) {
            for &value in &child[..1 << step] {
                *product *= value;
            }
        }
        require(claim == poly_eval(&products, combiner), Error::GkrLayer)?;
        let mut y = [ZERO; 2];
        transcript.samples(&mut y[..step]);
        for (value, child) in values.iter_mut().zip(children.iter_mut()) {
            *value = fold_eval(&mut child[..1 << step], &y[..step])?;
        }
        require(point.len + step <= MAX_POINT, Error::AnnouncedTableSizes)?;
        let mut next = Point::EMPTY;
        next.coords[..step].copy_from_slice(&y[..step]);
        next.coords[step..step + point.len].copy_from_slice(&x[..point.len]);
        next.len = point.len + step;
        point = next;
        layer -= step;
    }
    Ok((count, point, values))
}

/// One side of the bus's blocks: the stacked slot of each (the framework's first) and the cube's depth. Push and
/// pull share theirs; the count side has no framework.
struct SideLayout {
    depth: usize,
    slots: [Slot; 3 + N_BUS_BLOCKS],
    n_framework: usize,
}

impl SideLayout {
    fn new(layout: &Layout, count: bool) -> Result<Self, Error> {
        let mut sizes = [0usize; 3 + N_BUS_BLOCKS];
        let mut n = 0;
        if !count {
            sizes[..3].copy_from_slice(&[0, layout.log_memory, layout.log_bytecode]);
            n = 3;
            for &(owner, _) in &push_pull_blocks() {
                sizes[n] = layout.heights[owner as usize];
                n += 1;
            }
        } else {
            for &(owner, _) in &count_blocks() {
                sizes[n] = layout.heights[owner as usize];
                n += 1;
            }
        }
        let mut offsets = [0u64; 3 + N_BUS_BLOCKS];
        let depth = stack_offsets(&sizes[..n], &mut offsets);
        require(depth <= 32, Error::AnnouncedTableSizes)?;
        let mut slots = [Slot::NONE; 3 + N_BUS_BLOCKS];
        for i in 0..n {
            slots[i] = Slot {
                variables: sizes[i] as u8,
                index: offsets[i] as u32,
            };
        }
        Ok(Self {
            depth,
            slots,
            n_framework: if count { 0 } else { 3 },
        })
    }

    /// Block `b`'s selector at the bus point.
    fn selector(&self, b: usize, point: &[E]) -> E {
        self.slots[self.n_framework + b].eq_above(point)
    }
}

/// The owner and flush (or count column) of each block of a side, in the side's order.
fn push_pull_blocks() -> [(u8, u8); N_BUS_BLOCKS] {
    let mut out = [(0, 0); N_BUS_BLOCKS];
    let mut i = 0;
    for t in 0..N_TABLES {
        for f in 0..N_FLUSHES[t] {
            out[i] = (t as u8, f as u8);
            i += 1;
        }
    }
    out
}

fn count_blocks() -> [(u8, u8); N_COUNT_BLOCKS] {
    let mut out = [(0, 0); N_COUNT_BLOCKS];
    let mut i = 0;
    for t in 0..N_TABLES {
        for &column in tables::count_columns(t) {
            out[i] = (t as u8, column);
            i += 1;
        }
    }
    out
}

struct Bus {
    /// zeta: the GKR point, which the table sumcheck reuses; its low coordinates are the memory and bytecode points.
    point: Point,
    memory: [E; 3],
    memory_final: E,
    bytecode_final: E,
    /// What the tables owe each side.
    totals: [E; 3],
    beta: E,
    weights: [E; TUPLE],
}

/// A block's fingerprint form at the columns `v` of its owner: `beta + sum_slot weight[slot] * coordinate`.
fn block_form(side: usize, owner: usize, which: usize, v: &[E], beta: E, weights: &[E; TUPLE]) -> E {
    if side == 2 {
        return v[which]; // a count block's one coordinate, at alpha = beta = 0
    }
    let mut tuple = [ZERO; TUPLE];
    let n = tables::flush(owner, which, side == 0, v, &mut tuple);
    beta + dot(&weights[..n], &tuple[..n])
}

fn verify_bus_balance<S: Source>(layout: &Layout, transcript: &mut Transcript<S>, bus: &mut Bus) -> Result<(), Error> {
    let flush_layout = SideLayout::new(layout, false)?;
    let mut alphas = [ZERO; BUS_BITS];
    transcript.samples(&mut alphas);
    eq_kernel(&alphas, &mut bus.weights);
    bus.beta = transcript.sample();
    let (count_root, point, tree_values) = verify_gkr(flush_layout.depth, transcript)?;
    require(count_root != ZERO, Error::BusCountZero)?;
    require(
        point.len >= layout.log_memory.max(layout.log_bytecode) && layout.log_bytecode + BUS_BITS <= MAX_POINT,
        Error::AnnouncedTableSizes,
    )?;
    bus.point = point;
    let point = bus.point.as_slice();

    transcript.next_scalars(&mut bus.memory)?;
    bus.memory_final = transcript.next_scalar()?;
    bus.bytecode_final = transcript.next_scalar()?;
    let memory_index = index_mle(&point[..layout.log_memory]);
    let bytecode_index = index_mle(&point[..layout.log_bytecode]);
    let mut bytecode_point = [ZERO; MAX_POINT];
    bytecode_point[..layout.log_bytecode].copy_from_slice(&point[..layout.log_bytecode]);
    bytecode_point[layout.log_bytecode..layout.log_bytecode + BUS_BITS].copy_from_slice(&alphas);
    let bytecode_value = crate::bytecode::evaluate(&bytecode_point[..layout.log_bytecode + BUS_BITS])?;

    let (weights, memory) = (&bus.weights, &bus.memory);
    let fingerprints = |pc: E, memory_count: E, bytecode_count: E| {
        [
            dot(&weights[..3], &[SEP_STATE, pc, ONE]),
            dot(
                &weights[..6],
                &[SEP_MEM, memory_index, memory_count, memory[0], memory[1], memory[2]],
            ),
            dot(&weights[..3], &[SEP_BYTECODE, bytecode_index, bytecode_count]) + bytecode_value,
        ]
    };
    let final_pc = crate::field::GEN.pow((1u64 << layout.log_bytecode) - 1);
    let framework = [
        fingerprints(ONE, ONE, ONE),
        fingerprints(final_pc, bus.memory_final, bus.bytecode_final),
    ];
    let one_weight = {
        let mut w = [ZERO; TUPLE];
        w[0] = ONE;
        w
    };
    // A table's padding weight, and its padding row's form per block below.
    let mut padding_weights = [ZERO; N_TABLES];
    for t in 0..N_TABLES {
        padding_weights[t] = padding_weight(&point[..layout.heights[t]], layout.table_rows[t]);
    }
    let count_layout = SideLayout::new(layout, true)?;
    let blocks = push_pull_blocks();
    let counts = count_blocks();
    for side in 0..3 {
        let (side_layout, n_blocks) = if side < 2 {
            (&flush_layout, N_BUS_BLOCKS)
        } else {
            (&count_layout, N_COUNT_BLOCKS)
        };
        let (side_beta, side_weights) = if side < 2 {
            (bus.beta, &bus.weights)
        } else {
            (ZERO, &one_weight)
        };
        let mut known = ZERO;
        let mut selector_sum = ZERO;
        for f in 0..side_layout.n_framework {
            let selector = side_layout.slots[f].eq_above(point);
            known += selector * (side_beta + framework[side][f]);
            selector_sum += selector;
        }
        // A table's block is summed over its padding rows too, whose leaves hold 1 instead: the difference is public.
        let mut padding_rows = ZERO;
        for b in 0..n_blocks {
            let (owner, which) = if side < 2 { blocks[b] } else { counts[b] };
            let (owner, which) = (owner as usize, which as usize);
            let selector = side_layout.selector(b, point);
            selector_sum += selector;
            let form = block_form(side, owner, which, tables::padding_row(owner), side_beta, side_weights);
            padding_rows += selector * padding_weights[owner] * (form + ONE);
        }
        // The leaves outside every block hold 1.
        bus.totals[side] = tree_values[side] + known + selector_sum + ONE + padding_rows;
    }
    Ok(())
}

/// What the bus and the table sumcheck leave: the bus point (whose low coordinates the memory and bytecode
/// claims are at) and those claims, the table sumcheck's point (its challenges reversed) and each column's
/// evaluation there.
pub struct BusTables {
    pub bus_point: Point,
    pub memory: [E; 3],
    pub memory_final: E,
    pub bytecode_final: E,
    pub table_point: Point,
    pub values: [E; N_COLUMNS],
}

impl BusTables {
    pub const ZERO: BusTables = BusTables {
        bus_point: Point::EMPTY,
        memory: [ZERO; 3],
        memory_final: ZERO,
        bytecode_final: ZERO,
        table_point: Point::EMPTY,
        values: [ZERO; N_COLUMNS],
    };
}

/// The bus balance, then the table sumcheck over all six tables at the bus point.
#[inline(never)]
pub fn bus_and_tables<S: Source>(
    layout: &Layout,
    transcript: &mut Transcript<S>,
    out: &mut BusTables,
) -> Result<(), Error> {
    let mut bus = Bus {
        point: Point::EMPTY,
        memory: [ZERO; 3],
        memory_final: ZERO,
        bytecode_final: ZERO,
        totals: [ZERO; 3],
        beta: ZERO,
        weights: [ZERO; TUPLE],
    };
    verify_bus_balance(layout, transcript, &mut bus)?;
    let xi = transcript.sample();
    let mut xi_powers = [ONE; N_CONSTRAINTS + 3];
    for i in 1..xi_powers.len() {
        xi_powers[i] = xi_powers[i - 1] * xi;
    }
    let target = dot(&xi_powers[N_CONSTRAINTS..], &bus.totals);
    table_sumcheck(layout, &bus, &xi_powers, target, transcript, out)?;
    out.bus_point = bus.point;
    out.memory = bus.memory;
    out.memory_final = bus.memory_final;
    out.bytecode_final = bus.bytecode_final;
    Ok(())
}

/// One batched sumcheck over all six tables at the bus point: the bus forms and the constraints. Each block's
/// selector is recomputed here rather than kept from the bus.
fn table_sumcheck<S: Source>(
    layout: &Layout,
    bus: &Bus,
    xi_powers: &[E; N_CONSTRAINTS + 3],
    target: E,
    transcript: &mut Transcript<S>,
    out: &mut BusTables,
) -> Result<(), Error> {
    let n_rounds = *layout.heights.iter().max().unwrap_or(&0);
    require(
        n_rounds <= MAX_POINT && n_rounds <= bus.point.len,
        Error::AnnouncedTableSizes,
    )?;
    let mut challenges = [ZERO; MAX_POINT];
    let claim = transcript.sumcheck(target, 4, &mut challenges[..n_rounds])?;
    let point = &mut out.table_point;
    for i in 0..n_rounds {
        point.coords[i] = challenges[n_rounds - 1 - i];
    }
    point.len = n_rounds;
    let mut table_weights = [ONE; N_TABLES];
    for variable in 0..n_rounds {
        let challenge = point.coords[variable];
        let equality = ONE + bus.point.coords[variable] + challenge;
        for (weight, &height) in table_weights.iter_mut().zip(&layout.heights) {
            *weight *= if height > variable { equality } else { challenge };
        }
    }
    let values = &mut out.values;
    for t in 0..N_TABLES {
        let base = GLOBAL_COLUMN_BASES[t];
        transcript.next_scalars(&mut values[base..base + TABLE_WIDTHS[t]])?;
    }

    let flush_layout = SideLayout::new(layout, false)?;
    let count_layout = SideLayout::new(layout, true)?;
    let zeta = bus.point.as_slice();
    let (constraint_powers, form_powers) = xi_powers.split_at(N_CONSTRAINTS);
    let blocks = push_pull_blocks();
    let counts = count_blocks();
    let mut terminal = ZERO;
    for t in 0..N_TABLES {
        let v = &values[GLOBAL_COLUMN_BASES[t]..GLOBAL_COLUMN_BASES[t] + TABLE_WIDTHS[t]];
        let mut summand = ZERO;
        if t == OP_JUMP {
            summand = dot(constraint_powers, &tables::jump_constraints(v));
        }
        let mut forms = [ZERO; 3];
        for (b, &(owner, flush)) in blocks.iter().enumerate() {
            if owner as usize == t {
                let selector = flush_layout.selector(b, zeta);
                forms[0] += selector * block_form(0, t, flush as usize, v, bus.beta, &bus.weights);
                forms[1] += selector * block_form(1, t, flush as usize, v, bus.beta, &bus.weights);
            }
        }
        for (b, &(owner, column)) in counts.iter().enumerate() {
            if owner as usize == t {
                forms[2] += count_layout.selector(b, zeta) * v[column as usize];
            }
        }
        terminal += table_weights[t] * (summand + dot(form_powers, &forms));
    }
    require(terminal == claim, Error::TableSumcheckTerminal)
}
