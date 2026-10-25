//! Keccak, by GKR over its rounds (leanVM's `keccak.rs`), in small memory.
//!
//! A claim weighs the 1600 bits of a state, `weights[64 lane + z]`. leanVM keeps that vector; here it stays
//! factored. The first claim's is `lanes[lane] * x^z`. Every later one is `L^T(w)`, `L` being theta, rho and pi
//! and `w[lane][z] = zw[z] * lam[lane]` (an eq kernel over z times one over the lane, the latter shifted along
//! the row by chi's two neighbours), so `weights[lane][z] = g[lane][z] + C[x+1][z] + C[x+4][z+1]` with
//! `g[lane][z] = zw[z + rho(lane)] * lam[pi(lane)]` and `C[x][z] = sum_y g[x + 5y][z]`. Every sum the protocol
//! takes against it then reduces to correlations of `zw` with another 64-entry vector at the 25 shifts rho.

use crate::bus::Point;
use crate::field::{E, ONE, ZERO};
use crate::hash::{KECCAK_PI, KECCAK_RC, KECCAK_RHO, ROUNDS, STATE_LANES};
use crate::transcript::{Source, Transcript, dot, eq_kernel, fold_eval, log2_ceil, poly_eval};
use crate::{Error, MAX_POINT, require};

const PACK_BITS: usize = 4;
const PACK: usize = 1 << PACK_BITS;
const EMBED_BITS: usize = 24;
const PRODUCT_BITS: usize = 2 * EMBED_BITS - 1;
const LOCAL_BITS: usize = 11; // a bit position is z + 64 * lane
const Z_BITS: usize = 6;
const LANE_BITS: usize = 5;

/// Sixteen bits embed in a binary polynomial of degree at most 23, and a product of two embeddings projects to the
/// AND of what they embed (leanVM's `RMFE_EMBED` / `RMFE_PROJECT`).
const RMFE_EMBED: [u32; PACK] = [
    0x40c50b, 0x7f79f2, 0x4b4e0a, 0x72740c, 0x5357da, 0x1d1c9e, 0x04be6e, 0x785246, 0x097cdc, 0x109e7e, 0x1f1454,
    0x213cfc, 0x4cfcc8, 0x775770, 0x187386, 0x818a16,
];
const RMFE_PROJECT: [u64; PACK] = [
    0x1,
    0x7fffffffffff,
    0x274e9d3a74e9,
    0x1d3a74e9d3a7,
    0x65cb972e5cb9,
    0x5cb972e5cb97,
    0x6690aec7cd21,
    0x5d8f9a42bb1f,
    0x73485763e690,
    0x3750967c6ea1,
    0x12cf8dd4259f,
    0x1ba84b3e3750,
    0x0ad0c9f715a1,
    0x064fb8ad0c9f,
    0x456864fb8ad0,
    0x400000000000,
];

#[derive(Clone, Copy, Debug)]
pub struct KeccakShape {
    pub log_steps: usize,
    pub depth: usize,
}

impl KeccakShape {
    pub fn segments(&self) -> usize {
        ROUNDS / self.depth
    }

    fn pack_bits(&self) -> usize {
        self.log_steps - PACK_BITS
    }

    pub fn slot_bits(&self) -> usize {
        log2_ceil((STATE_LANES * self.segments()) as u64)
    }
}

#[derive(Clone, Copy)]
enum Weights {
    /// `lanes[lane] * x^z`.
    Initial([E; 32]),
    /// `L^T` of `zw[z] * lam[lane]`, `zw` the eq kernel of `zq` (rebuilt where it is needed).
    Layer { zq: [E; Z_BITS], lam: [E; STATE_LANES] },
}

/// `out[r] = sum_z eq(p, z) eq(q, z + r mod 64)` for every shift `r`, without either table: walking the shift's
/// bits from the lowest, the sum over z splits by the carry `z + r` leaves at each bit, so a depth-first walk over
/// the shift's bits carries one pair (no carry, carry) per prefix, four products a bit.
fn correlations(p: &[E], q: &[E; Z_BITS], out: &mut [E; 64]) {
    // pair[k][a][b] = eq_k(p, a) eq_k(q, b).
    let mut pair = [[[ZERO; 2]; 2]; Z_BITS];
    for k in 0..Z_BITS {
        let (p0, p1, q0, q1) = (ONE + p[k], p[k], ONE + q[k], q[k]);
        pair[k] = [[p0 * q0, p0 * q1], [p1 * q0, p1 * q1]];
    }
    fn walk(pair: &[[[E; 2]; 2]; Z_BITS], k: usize, shift: usize, carry: [E; 2], out: &mut [E; 64]) {
        if k == Z_BITS {
            out[shift] = carry[0] + carry[1]; // the carry out of bit 5 wraps: mod 64
            return;
        }
        for r in 0..2 {
            let mut next = [ZERO; 2];
            for (c, &weight) in carry.iter().enumerate() {
                if weight == ZERO {
                    continue;
                }
                for z in 0..2 {
                    let w = z ^ r ^ c;
                    next[(z + r + c) >> 1] += weight * pair[k][z][w];
                }
            }
            walk(pair, k + 1, shift | r << k, next, out);
        }
    }
    walk(&pair, 0, 0, [ONE, ZERO], out);
}

/// Lane `lane` moved `k` columns along its row.
fn along(lane: usize, k: usize) -> usize {
    (lane % 5 + k) % 5 + 5 * (lane / 5)
}

impl Weights {
    /// `C[x][z]`.
    fn column(zw: &[E; 64], lam: &[E; STATE_LANES], x: usize, z: usize) -> E {
        let mut sum = ZERO;
        for y in 0..5 {
            let lane = x + 5 * y;
            sum += zw[(z + KECCAK_RHO[lane] as usize) % 64] * lam[KECCAK_PI[lane]];
        }
        sum
    }

    /// `sum_{z in bits of rc} weights[0][z]`, the positions iota flips.
    fn lane0_sum(&self, rc: u64) -> E {
        match self {
            Weights::Initial(lanes) => lanes[0] * E::new(rc, 0, 0),
            Weights::Layer { zq, lam } => {
                let mut zw = [ZERO; 64];
                eq_kernel(zq, &mut zw);
                let zw = &zw;
                let mut sum = ZERO;
                let mut bits = rc;
                while bits != 0 {
                    let z = bits.trailing_zeros() as usize;
                    bits &= bits - 1;
                    sum += zw[z] * lam[KECCAK_PI[0]]
                        + Self::column(zw, lam, 1, z)
                        + Self::column(zw, lam, 4, (z + 1) % 64);
                }
                sum
            }
        }
    }

    /// `sum_j eq(local, j) weights[j]`, `j < 1600`.
    fn dot_eq(&self, local: &[E]) -> E {
        match self {
            Weights::Initial(lanes) => dot_eq_initial(lanes, local),
            Weights::Layer { zq, lam } => dot_eq_layer(zq, lam, local),
        }
    }

    /// `sum_lane wt[lane] weights[lane][z]` for every z.
    fn lane_combination(&self, wt: &[E; STATE_LANES], out: &mut [E; 64]) {
        match self {
            Weights::Initial(lanes) => {
                let sum = dot(wt, &lanes[..STATE_LANES]);
                for (z, value) in out.iter_mut().enumerate() {
                    *value = sum.times_monomial(z);
                }
            }
            Weights::Layer { zq, lam } => {
                let mut zw = [ZERO; 64];
                eq_kernel(zq, &mut zw);
                let mut columns = [ZERO; 5];
                for lane in 0..STATE_LANES {
                    columns[lane % 5] += wt[lane];
                }
                *out = [ZERO; 64];
                for lane in 0..STATE_LANES {
                    let x = lane % 5;
                    let g = lam[KECCAK_PI[lane]];
                    let a = g * (wt[lane] + columns[(x + 4) % 5]);
                    let b = g * columns[(x + 1) % 5];
                    let rho = KECCAK_RHO[lane] as usize;
                    for (z, value) in out.iter_mut().enumerate() {
                        *value += a * zw[(z + rho) % 64] + b * zw[(z + 1 + rho) % 64];
                    }
                }
            }
        }
    }
}

/// `sum_{lane, z} eq(local, 64 lane + z) lanes[lane] x^z`.
#[inline(never)]
fn dot_eq_initial(lanes: &[E; 32], local: &[E]) -> E {
    let mut lc = [ZERO; 32];
    eq_kernel(&local[Z_BITS..], &mut lc);
    let mut zc = [ZERO; 64];
    eq_kernel(&local[..Z_BITS], &mut zc);
    let mut monomials = ZERO;
    for (z, &weight) in zc.iter().enumerate() {
        monomials += weight.times_monomial(z);
    }
    dot(&lc[..STATE_LANES], &lanes[..STATE_LANES]) * monomials
}

/// `sum_{lane, z} eq(local, 64 lane + z) L^T(zw lam)[lane][z]`: correlations of the two z kernels at the shifts rho.
#[inline(never)]
fn dot_eq_layer(zq: &[E; Z_BITS], lam: &[E; STATE_LANES], local: &[E]) -> E {
    let mut lc = [ZERO; 32];
    eq_kernel(&local[Z_BITS..], &mut lc);
    let mut correlation = [ZERO; 64];
    correlations(&local[..Z_BITS], zq, &mut correlation);
    let mut total = ZERO;
    let (mut cr0, mut cr1, mut lc_columns) = ([ZERO; 5], [ZERO; 5], [ZERO; 5]);
    for lane in 0..STATE_LANES {
        let rho = KECCAK_RHO[lane] as usize;
        let g = lam[KECCAK_PI[lane]];
        let r0 = g * correlation[rho];
        total += lc[lane] * r0;
        cr0[lane % 5] += r0;
        cr1[lane % 5] += g * correlation[(rho + 1) % 64];
        lc_columns[lane % 5] += lc[lane];
    }
    for x in 0..5 {
        total += lc_columns[x] * (cr0[(x + 1) % 5] + cr1[(x + 4) % 5]);
    }
    total
}

#[derive(Clone, Copy)]
struct Claim {
    value: E,
    mu: [E; PACK],
    point: Point, // a pack index, then a segment index
    weights: Weights,
}

fn instance_weights(s: E) -> [E; PACK] {
    let mut powers = [ONE; EMBED_BITS];
    for b in 1..EMBED_BITS {
        powers[b] = powers[b - 1] * s;
    }
    let mut out = [ZERO; PACK];
    for (value, &e) in out.iter_mut().zip(&RMFE_EMBED) {
        for (b, &power) in powers.iter().enumerate() {
            if e >> b & 1 == 1 {
                *value += power;
            }
        }
    }
    out
}

#[inline(never)]
fn verify_layer<S: Source>(
    transcript: &mut Transcript<S>,
    shape: KeccakShape,
    step: usize,
    claim: &mut Claim,
) -> Result<(), Error> {
    // 1] The product polynomial: the claim's weighted sum of the packs' unprojected chi.
    let mut product = [ZERO; PRODUCT_BITS];
    transcript.next_scalars(&mut product)?;
    let mut projected = ZERO;
    for (c, &coefficient) in product.iter().enumerate() {
        let mut functional = ZERO;
        for i in 0..PACK {
            if RMFE_PROJECT[i] >> c & 1 == 1 {
                functional += claim.mu[i];
            }
        }
        projected += functional * coefficient;
    }
    let mut segments = [ZERO; 2];
    let segment_point = &claim.point.as_slice()[shape.pack_bits()..];
    eq_kernel(segment_point, &mut segments[..1 << segment_point.len()]);
    let mut iota = ZERO;
    for (segment, &weight) in segments.iter().enumerate().take(shape.segments()) {
        let constant = KECCAK_RC[shape.depth * (segment + 1) - step - 1];
        iota += weight * claim.weights.lane0_sum(constant);
    }
    let mut mu_sum = ZERO;
    for &m in &claim.mu {
        mu_sum += m;
    }
    require(projected + iota * mu_sum == claim.value, Error::KeccakProduct)?;

    // 2] At a random point a pack is one field element, and the polynomial's value a sumcheck claim.
    let s = transcript.sample();
    let mu = instance_weights(s);
    let mut kappa = ZERO;
    for &m in &mu {
        kappa += m;
    }
    let mut value = poly_eval(&product, s);

    // 3] The pack and the segment.
    let mut scale = ONE;
    // Each coordinate of the claim's point gives way to its challenge.
    let mut message = [ZERO; 5];
    for i in 0..claim.point.len {
        let r = claim.point.coords[i];
        transcript.round_poly(3, value, Some(r), &mut message)?;
        let challenge = transcript.sample();
        value = (ONE + r + challenge) * poly_eval(&message[..3], challenge);
        scale *= ONE + r + challenge;
        claim.point.coords[i] = challenge;
    }

    // 4] The bit position.
    let mut local = [ZERO; LOCAL_BITS];
    let value = transcript.sumcheck(value, 4, &mut local)?;
    let mut t = [ZERO; 3];
    transcript.next_scalars(&mut t)?;
    require(
        scale * claim.weights.dot_eq(&local) * (kappa * t[0] + (kappa + t[1]) * t[2]) == value,
        Error::KeccakLayer,
    )?;

    // 5] One claim on the state before chi, then on the round's input through the linear map.
    let beta = transcript.sample();
    let mut lw = [ZERO; 1 << LANE_BITS];
    eq_kernel(&local[Z_BITS..], &mut lw);
    let mut lam = [ZERO; STATE_LANES];
    for (lane, value) in lam.iter_mut().enumerate() {
        *value = lw[lane] + beta * (lw[along(lane, 4)] + beta * lw[along(lane, 3)]);
    }
    claim.value = t[0] + beta * (t[1] + beta * t[2]);
    claim.mu = mu;
    claim.weights = Weights::Layer {
        zq: local[..Z_BITS].try_into().unwrap(),
        lam,
    };
    Ok(())
}

/// A sumcheck over the slot: the point it ends on, the weight the claim puts on each slice there, and what is
/// left to match. Segment `first + s`'s state (`s < count`) sits at slots `25 (first + s) + lane`.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn open<S: Source>(
    transcript: &mut Transcript<S>,
    shape: KeccakShape,
    claim: &Claim,
    first: usize,
    count: usize,
    value: E,
    slot: &mut Point,
    weights: &mut [E; 64],
) -> Result<E, Error> {
    *slot = Point::EMPTY;
    slot.len = shape.slot_bits();
    let value = transcript.sumcheck(value, 3, &mut slot.coords[..slot.len])?;
    let mut slot_eq = [ZERO; 64];
    eq_kernel(slot.as_slice(), &mut slot_eq);
    let mut segments = [ZERO; 2];
    let segment_point = &claim.point.as_slice()[shape.pack_bits()..];
    eq_kernel(segment_point, &mut segments[..1 << segment_point.len()]);
    let mut wt = [ZERO; STATE_LANES];
    for segment in 0..count {
        for (lane, w) in wt.iter_mut().enumerate() {
            *w += slot_eq[STATE_LANES * (first + segment) + lane] * segments[segment];
        }
    }
    claim.weights.lane_combination(&wt, weights);
    Ok(value)
}

/// The reduction: a random claim on every segment's output at `instance`, `depth` layers down to the committed
/// inputs. The last segment's output is the permutation's, claimed by `output`; the other's is committed, and its
/// claim is returned with its point in `output_point`. The inputs' 64 slices and their point go to `slices` and
/// `input_point`.
#[inline(never)]
pub fn verify_keccak<S: Source>(
    transcript: &mut Transcript<S>,
    shape: KeccakShape,
    instance: &[E],
    output: &[E],
    output_point: &mut Point,
    input_point: &mut Point,
    slices: &mut [E; 64],
) -> Result<E, Error> {
    require(
        instance.len() == shape.log_steps
            && output.len() == STATE_LANES
            && shape.log_steps >= PACK_BITS
            && shape.segments() == 2
            && shape.log_steps + shape.slot_bits() <= MAX_POINT,
        Error::AnnouncedTableSizes,
    )?;
    let mut segment = [ZERO; 1];
    transcript.samples(&mut segment);
    let mut point = Point::EMPTY;
    point.coords[..shape.pack_bits()].copy_from_slice(&instance[PACK_BITS..]);
    point.coords[shape.pack_bits()] = segment[0];
    point.len = shape.pack_bits() + 1;
    let mut lane_point = [ZERO; LANE_BITS];
    transcript.samples(&mut lane_point);
    let mut lanes = [ZERO; 32];
    eq_kernel(&lane_point, &mut lanes);
    let mut segment_eq = [ZERO; 2];
    eq_kernel(&segment, &mut segment_eq);
    let last = segment_eq[shape.segments() - 1] * dot(&lanes[..STATE_LANES], output);
    let committed = transcript.next_scalar()?;
    let mut mu = [ZERO; PACK];
    eq_kernel(&instance[..PACK_BITS], &mut mu);
    let mut claim = Claim {
        value: committed + last,
        mu,
        point,
        weights: Weights::Initial(lanes),
    };
    for step in 0..shape.depth {
        verify_layer(transcript, shape, step, &mut claim)?;
    }
    let word = open_outputs(transcript, shape, &lanes, segment[0], committed, instance, output_point)?;
    open_inputs(transcript, shape, &claim, input_point, slices)?;
    Ok(word)
}

/// The committed outputs: the first claim's (rebuilt from its lanes and segment, all that enters the opening),
/// whose instance weights are an eq already.
#[inline(never)]
fn open_outputs<S: Source>(
    transcript: &mut Transcript<S>,
    shape: KeccakShape,
    lanes: &[E; 32],
    segment: E,
    committed: E,
    instance: &[E],
    output_point: &mut Point,
) -> Result<E, Error> {
    let mut first = Claim {
        value: ZERO,
        mu: [ZERO; PACK],
        point: Point::EMPTY,
        weights: Weights::Initial(*lanes),
    };
    first.point.coords[shape.pack_bits()] = segment;
    first.point.len = shape.pack_bits() + 1;
    let mut slot = Point::EMPTY;
    let mut weights = [ZERO; 64];
    let value = open(
        transcript,
        shape,
        &first,
        1,
        shape.segments() - 1,
        committed,
        &mut slot,
        &mut weights,
    )?;
    let word = transcript.next_scalar()?;
    require(weights[0] * word == value, Error::KeccakOutputOpening)?;
    *output_point = Point::EMPTY;
    output_point.coords[..instance.len()].copy_from_slice(instance);
    output_point.coords[instance.len()..instance.len() + slot.len].copy_from_slice(slot.as_slice());
    output_point.len = instance.len() + slot.len;
    Ok(word)
}

/// The inputs: the instances of a pack first, then the slot.
#[inline(never)]
fn open_inputs<S: Source>(
    transcript: &mut Transcript<S>,
    shape: KeccakShape,
    claim: &Claim,
    input_point: &mut Point,
    slices: &mut [E; 64],
) -> Result<(), Error> {
    let mut low = [ZERO; PACK_BITS];
    let value = transcript.sumcheck(claim.value, 3, &mut low)?;
    let mut slot = Point::EMPTY;
    let mut weights = [ZERO; 64];
    let value = open(
        transcript,
        shape,
        claim,
        0,
        shape.segments(),
        value,
        &mut slot,
        &mut weights,
    )?;
    transcript.next_scalars(slices)?;
    let mut mu = claim.mu;
    require(
        fold_eval(&mut mu, &low)? * dot(&weights, slices) == value,
        Error::KeccakInputOpening,
    )?;
    let pack = shape.pack_bits();
    *input_point = Point::EMPTY;
    input_point.coords[..PACK_BITS].copy_from_slice(&low);
    input_point.coords[PACK_BITS..PACK_BITS + pack].copy_from_slice(&claim.point.as_slice()[..pack]);
    input_point.coords[PACK_BITS + pack..PACK_BITS + pack + slot.len].copy_from_slice(slot.as_slice());
    input_point.len = PACK_BITS + pack + slot.len;
    Ok(())
}
