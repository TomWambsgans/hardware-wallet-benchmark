//! Ring switching (leanVM's `ring_switch.rs`): the 64 slice claims the Keccak reduction leaves become one claim
//! on the committed column `q_keccak`.

use crate::bus::Point;
use crate::field::{E, GEN, ONE, ZERO};
use crate::transcript::{Source, Transcript};

const RING_MAP_SHIFTS: [usize; 6] = [32, 16, 8, 4, 2, 1];

/// The drawn map, stage by stage: `a_p+1 = a_p + f_p a_p^(2^shift)`.
fn ring_map(mut value: E, challenges: &[E; 6]) -> E {
    for (&challenge, shift) in challenges.iter().zip(RING_MAP_SHIFTS) {
        let mut frobenius = value;
        for _ in 0..shift {
            frobenius = frobenius.square();
        }
        value += challenge * frobenius;
    }
    value
}

/// The weight `W(u) = Phi(eq(point, u))`: `Phi(a) = sum_k c_k a^(2^k)`, the `c_k` products of powers of the six
/// challenges (rebuilt when the weight is evaluated).
pub struct RingWeight {
    /// The point of the 64 slice claims (`verify_keccak` writes it in place).
    pub point: Point,
    challenges: [E; 6],
}

/// `c_k`: the product over the stages whose shift `k` has a bit of, of the stage's challenge to `2^(k mod shift)`.
fn coefficients(challenges: &[E; 6], out: &mut [E; 64]) {
    for (k, coefficient) in out.iter_mut().enumerate() {
        let mut product = ONE;
        for (&f, shift) in challenges.iter().zip(RING_MAP_SHIFTS) {
            if k & shift != 0 {
                let mut power = f;
                for _ in 0..k % shift {
                    power = power.square();
                }
                product *= power;
            }
        }
        *coefficient = product;
    }
}

impl RingWeight {
    pub const ZERO: RingWeight = RingWeight {
        point: Point::EMPTY,
        challenges: [ZERO; 6],
    };

    /// `W` at `r_prime`: `sum_k c_k prod_n (1 + r_n^(2^k) + r'_n)`.
    pub fn at(&self, r_prime: &[E]) -> E {
        let mut table = [ZERO; 64];
        coefficients(&self.challenges, &mut table);
        let mut total = ZERO;
        let mut frobenius = self.point;
        for &c in &table {
            let mut product = c;
            for (value, &challenge) in frobenius.coords[..frobenius.len].iter_mut().zip(r_prime) {
                product *= ONE + *value + challenge;
                *value = value.square();
            }
            total += product;
        }
        total
    }
}

/// The 64 claims `s[i] = z(i, point)` become the one claim `sum_u W(u) q_keccak(u) = target`.
#[inline(never)]
pub fn ring_switch<S: Source>(s: &[E; 64], transcript: &mut Transcript<S>, weight: &mut RingWeight) -> E {
    let mut challenges = [ZERO; 6];
    transcript.samples(&mut challenges);
    weight.challenges = challenges;
    // The target `sum_i x^i Phi(s_i)`, by Horner from the top.
    let mut target = ZERO;
    for &value in s.iter().rev() {
        target = target * GEN + ring_map(value, &challenges);
    }
    target
}
