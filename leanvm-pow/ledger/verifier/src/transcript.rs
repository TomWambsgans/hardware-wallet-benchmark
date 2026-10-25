//! The proof as a stream, and Fiat-Shamir: leanVM's duplex sponge over Keccak-f[1600].
//!
//! The device reads the proof in the order the verifier consumes it: scalars (24 bytes each), and for each
//! Merkle opening phase its rows (ascending positions) then its sibling digests (bottom level first). A
//! [`Source`] hands out those pieces; on the device it pulls them over USB.

use crate::field::{E, ONE, ZERO};
use crate::hash::{Digest, State};
use crate::{Error, require};

/// What the verifier asks the proof for next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Piece {
    Scalar,
    /// The start of a Merkle opening phase: no bytes.
    Batch,
    Row,
    Sibling,
}

pub trait Source {
    /// Fill `out` with the next bytes of the proof, of the kind `piece`.
    fn read(&mut self, piece: Piece, out: &mut [u8]) -> Result<(), Error>;

    /// The proof ends here: fails if any of it is left unread.
    fn finish(&mut self) -> Result<(), Error>;
}

const DS_OBSERVE: u64 = 1;
const DS_POW_NONCE: u64 = 4;
const RATE_SCALARS: usize = 4;

pub struct Sponge {
    state: State,
    pending: [(E, u64); RATE_SCALARS],
    n_pending: usize,
}

impl Sponge {
    pub fn new(fiat_shamir_iv: Digest, public_input: Digest) -> Self {
        let mut state = State::ZERO;
        for (i, word) in fiat_shamir_iv
            .words()
            .into_iter()
            .chain(public_input.words())
            .enumerate()
        {
            state.set_lane(i, word);
        }
        state.permute();
        Self {
            state,
            pending: [(ZERO, 0); RATE_SCALARS],
            n_pending: 0,
        }
    }

    /// The waiting scalars over the rate (overwrite mode: the rest of it zero), the capacity kept, then a permutation.
    fn duplex(&mut self) {
        for i in 0..RATE_SCALARS {
            let (value, tag) = if i < self.n_pending { self.pending[i] } else { (ZERO, 0) };
            for (k, limb) in [value.c0, value.c1, value.c2, tag].into_iter().enumerate() {
                self.state.set_lane(4 * i + k, limb);
            }
        }
        self.state.permute();
        self.n_pending = 0;
    }

    fn absorb(&mut self, value: E, tag: u64) {
        if self.n_pending == RATE_SCALARS {
            self.duplex();
        }
        self.pending[self.n_pending] = (value, tag);
        self.n_pending += 1;
    }

    pub fn sample(&mut self) -> E {
        self.duplex();
        E::new(self.state.lane(0), self.state.lane(1), self.state.lane(2))
    }
}

pub struct Transcript<'a, S: Source> {
    source: &'a mut S,
    sponge: Sponge,
}

impl<'a, S: Source> Transcript<'a, S> {
    pub fn new(source: &'a mut S, fiat_shamir_iv: Digest, public_input: Digest) -> Self {
        Self {
            source,
            sponge: Sponge::new(fiat_shamir_iv, public_input),
        }
    }

    pub fn sample(&mut self) -> E {
        self.sponge.sample()
    }

    pub fn samples(&mut self, out: &mut [E]) {
        for value in out {
            *value = self.sample();
        }
    }

    fn next(&mut self) -> Result<E, Error> {
        let mut bytes = [0u8; 24];
        self.source.read(Piece::Scalar, &mut bytes)?;
        Ok(E::from_bytes(&bytes))
    }

    pub fn next_scalar(&mut self) -> Result<E, Error> {
        let value = self.next()?;
        self.sponge.absorb(value, DS_OBSERVE);
        Ok(value)
    }

    pub fn next_scalars(&mut self, out: &mut [E]) -> Result<(), Error> {
        for value in out {
            *value = self.next_scalar()?;
        }
        Ok(())
    }

    /// The proof-of-work nonce: absorbed with its own tag; the challenge drawn next must have its low `bits` zero.
    pub fn grind_check(&mut self, bits: u32) -> Result<(), Error> {
        let nonce = self.next()?;
        self.sponge.absorb(nonce, DS_POW_NONCE);
        let challenge = self.sample();
        let mask = 1u64.checked_shl(bits).map_or(u64::MAX, |bit| bit - 1);
        let valid = if bits == 0 {
            nonce == ZERO
        } else {
            challenge.c0 & mask == 0
        };
        require(valid, Error::GrindingNonce)
    }

    pub fn read(&mut self, piece: Piece, out: &mut [u8]) -> Result<(), Error> {
        self.source.read(piece, out)
    }

    pub fn finish(self) -> Result<(), Error> {
        self.source.finish()
    }

    /// A sumcheck round's polynomial, its coefficients into `out` (`count` of them, `count <= 5`).
    ///
    /// Without an equality factor `q(0) + q(1) == claim`, and the transcript holds c0, c2, c3, ...; with one
    /// (`r`), `(1 + r) q(0) + r q(1) == claim`, and it holds c1, c2, ...
    pub fn round_poly(&mut self, count: usize, claim: E, eq_factor: Option<E>, out: &mut [E; 5]) -> Result<(), Error> {
        match eq_factor {
            None => {
                out[0] = self.next_scalar()?;
                let mut tail = ZERO;
                for slot in out[2..count].iter_mut() {
                    *slot = self.next_scalar()?;
                    tail += *slot;
                }
                out[1] = claim + tail;
            }
            Some(r) => {
                let mut tail = ZERO;
                for slot in out[1..count].iter_mut() {
                    *slot = self.next_scalar()?;
                    tail += *slot;
                }
                out[0] = claim + r * tail;
            }
        }
        Ok(())
    }

    /// A sumcheck of `point.len()` rounds without equality factors: the challenges into `point`, the final claim out.
    pub fn sumcheck(&mut self, mut claim: E, count: usize, point: &mut [E]) -> Result<E, Error> {
        let mut message = [ZERO; 5];
        for challenge in point.iter_mut() {
            self.round_poly(count, claim, None, &mut message)?;
            *challenge = self.sample();
            claim = poly_eval(&message[..count], *challenge);
        }
        Ok(claim)
    }
}

// ---------------------------------------------------------------- multilinear helpers

/// `eq(i, point)` for every index `i < 2^len(point)`, LSB-first, into `out[..2^len]`.
pub fn eq_kernel(point: &[E], out: &mut [E]) {
    out[0] = ONE;
    for (k, &r) in point.iter().enumerate() {
        let half = 1 << k;
        for i in 0..half {
            let high = out[i] * r;
            out[i + half] = high;
            out[i] += high;
        }
    }
}

/// The multilinear extension of `values` at `point`, folding `values` in place.
pub fn fold_eval(values: &mut [E], point: &[E]) -> Result<E, Error> {
    require(
        point.len() < 32 && values.len() == 1 << point.len(),
        Error::MultilinearSize,
    )?;
    let mut len = values.len();
    for &r in point {
        for i in 0..len / 2 {
            values[i] = values[2 * i] + r * (values[2 * i] + values[2 * i + 1]);
        }
        len /= 2;
    }
    Ok(values[0])
}

pub fn eq_eval(left: &[E], right: &[E]) -> E {
    let mut result = ONE;
    for (&x, &y) in left.iter().zip(right) {
        result *= ONE + x + y;
    }
    result
}

/// `eq(bits of selector, point)`.
pub fn eq_bits(selector: u64, point: &[E]) -> E {
    let mut result = ONE;
    for (bit, &x) in point.iter().enumerate() {
        result *= if selector >> bit & 1 == 1 { x } else { ONE + x };
    }
    result
}

pub fn dot(left: &[E], right: &[E]) -> E {
    let mut result = ZERO;
    for (&x, &y) in left.iter().zip(right) {
        result += x * y;
    }
    result
}

/// `pad_n(point)`, the multilinear extension of `[z >= n]`, `n <= 2^len(point)`.
pub fn padding_weight(point: &[E], n: u64) -> E {
    let bit = |k: usize| E::new(n >> k & 1, 0, 0);
    let mut low = ONE;
    for (k, &r) in point.iter().enumerate() {
        low = (ONE + bit(k)) * r + (ONE + bit(k) + r) * low;
    }
    (ONE + bit(point.len())) * low
}

/// MLE of `[1, g, g^2, ...]` at an LSB-first point.
pub fn index_mle(point: &[E]) -> E {
    let mut result = ONE;
    let mut generator_power = crate::field::GEN;
    for &challenge in point {
        result *= ONE + challenge * (ONE + generator_power);
        generator_power = generator_power.square();
    }
    result
}

pub fn poly_eval(coefficients: &[E], point: E) -> E {
    coefficients.iter().rev().fold(ZERO, |acc, &c| acc * point + c)
}

pub const fn log2_ceil(value: u64) -> usize {
    (64 - value.saturating_sub(1).leading_zeros()) as usize
}

pub fn log2_strict(value: u64) -> Result<usize, Error> {
    require(value.is_power_of_two(), Error::NotPowerOfTwo)?;
    Ok(value.trailing_zeros() as usize)
}

/// Where a run sits in a stacked cube: its point fills the low `variables` coordinates, the bits of `index` fix the rest.
#[derive(Clone, Copy, Debug, Default)]
pub struct Placement {
    pub variables: usize,
    pub index: u64,
}

impl Placement {
    /// eq weight of the coordinates above the window.
    pub fn eq_above(&self, point: &[E]) -> E {
        eq_bits(self.index >> self.variables, &point[self.variables..])
    }
}

/// Stack runs of `2^sizes[i]` words, largest first (ties by index): each run's offset, and the log of the total.
pub fn stack_offsets(sizes: &[usize], offsets: &mut [u64]) -> usize {
    let n = sizes.len();
    let mut order = [0u16; 256];
    for (i, slot) in order[..n].iter_mut().enumerate() {
        *slot = i as u16;
    }
    // Insertion sort by (size descending, index ascending): stable on index.
    for i in 1..n {
        let mut j = i;
        while j > 0 && sizes[order[j - 1] as usize] < sizes[order[j] as usize] {
            order.swap(j - 1, j);
            j -= 1;
        }
    }
    let mut total = 0u64;
    for &index in &order[..n] {
        offsets[index as usize] = total;
        total += 1 << sizes[index as usize];
    }
    log2_ceil(total)
}
