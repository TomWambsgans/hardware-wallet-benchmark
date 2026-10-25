//! `K = GF(2)[x]/(x^64 + x^4 + x^3 + x + 1)` and `E = K[y]/(y^3 + y + 1)`, on plain integers.
//! From leanVM's `verifier` crate (`crates/verifier/src/field.rs`), minus the table multiplier.

use core::ops::{Add, AddAssign, Mul, MulAssign};

/// 32x32 carry-less product, by integer multiplication: both operands split into the four classes of their bit
/// positions mod 4 (eight bits each), a coefficient of a class product sums at most eight bits, so its carries stay
/// below the next bit of its class, and masking each class's sum to its own bits leaves the parities. Sixteen
/// 32x32->64 multiplies, one output class at a time.
#[cfg(not(target_arch = "arm"))]
#[inline(always)]
fn clmul32(a: u32, b: u32) -> u64 {
    const M: u32 = 0x1111_1111;
    const N: u64 = 0x1111_1111_1111_1111;
    let b = [
        (b & M) as u64,
        (b & M << 1) as u64,
        (b & M << 2) as u64,
        (b & M << 3) as u64,
    ];
    let mut out = 0u64;
    for k in 0..4 {
        let mut z = 0u64;
        for i in 0..4 {
            z ^= ((a & M << i) as u64) * b[(k + 4 - i) % 4];
        }
        out |= z & N << k;
    }
    out
}

// The same on the device, by hand: compiled, every product of a field multiplication is hoisted and spilled.
// r0 = a, r1 = b -> r0:r1. a's classes in r2-r5 and b's in r6-r9, both masked once; each output class sums four
// UMULLs (r12:lr) into r10:r11 (class 0 straight into r0:r1), masked to its class and joined to the result. r9,
// the static base, is saved and restored around it: nothing here reads a global.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    ".syntax unified",
    ".thumb",
    ".section .text.leanvm_clmul32,\"ax\",%progbits",
    ".global leanvm_clmul32",
    ".type leanvm_clmul32, %function",
    ".thumb_func",
    "leanvm_clmul32:",
    "    push {{r4-r11, lr}}",
    "    and r2, r0, #0x11111111",
    "    and r3, r0, #0x22222222",
    "    and r4, r0, #0x44444444",
    "    and r5, r0, #0x88888888",
    "    and r6, r1, #0x11111111",
    "    and r7, r1, #0x22222222",
    "    and r8, r1, #0x44444444",
    "    and r9, r1, #0x88888888",
    // class 0: a0 b0 + a1 b3 + a2 b2 + a3 b1
    "    umull r0, r1, r2, r6",
    "    umull r12, lr, r3, r9",
    "    eor r0, r0, r12",
    "    eor r1, r1, lr",
    "    umull r12, lr, r4, r8",
    "    eor r0, r0, r12",
    "    eor r1, r1, lr",
    "    umull r12, lr, r5, r7",
    "    eor r0, r0, r12",
    "    eor r1, r1, lr",
    "    and r0, r0, #0x11111111",
    "    and r1, r1, #0x11111111",
    // class 1: a0 b1 + a1 b0 + a2 b3 + a3 b2
    "    umull r10, r11, r2, r7",
    "    umull r12, lr, r3, r6",
    "    eor r10, r10, r12",
    "    eor r11, r11, lr",
    "    umull r12, lr, r4, r9",
    "    eor r10, r10, r12",
    "    eor r11, r11, lr",
    "    umull r12, lr, r5, r8",
    "    eor r10, r10, r12",
    "    eor r11, r11, lr",
    "    and r10, r10, #0x22222222",
    "    and r11, r11, #0x22222222",
    "    orr r0, r0, r10",
    "    orr r1, r1, r11",
    // class 2: a0 b2 + a1 b1 + a2 b0 + a3 b3
    "    umull r10, r11, r2, r8",
    "    umull r12, lr, r3, r7",
    "    eor r10, r10, r12",
    "    eor r11, r11, lr",
    "    umull r12, lr, r4, r6",
    "    eor r10, r10, r12",
    "    eor r11, r11, lr",
    "    umull r12, lr, r5, r9",
    "    eor r10, r10, r12",
    "    eor r11, r11, lr",
    "    and r10, r10, #0x44444444",
    "    and r11, r11, #0x44444444",
    "    orr r0, r0, r10",
    "    orr r1, r1, r11",
    // class 3: a0 b3 + a1 b2 + a2 b1 + a3 b0
    "    umull r10, r11, r2, r9",
    "    umull r12, lr, r3, r8",
    "    eor r10, r10, r12",
    "    eor r11, r11, lr",
    "    umull r12, lr, r4, r7",
    "    eor r10, r10, r12",
    "    eor r11, r11, lr",
    "    umull r12, lr, r5, r6",
    "    eor r10, r10, r12",
    "    eor r11, r11, lr",
    "    and r10, r10, #0x88888888",
    "    and r11, r11, #0x88888888",
    "    orr r0, r0, r10",
    "    orr r1, r1, r11",
    "    pop {{r4-r11, pc}}",
    ".size leanvm_clmul32, . - leanvm_clmul32",
);

#[cfg(target_arch = "arm")]
unsafe extern "C" {
    fn leanvm_clmul32(a: u32, b: u32) -> u64;
}

#[cfg(target_arch = "arm")]
#[inline(always)]
fn clmul32(a: u32, b: u32) -> u64 {
    unsafe { leanvm_clmul32(a, b) }
}

/// 64x64 carry-less product, by Karatsuba over 32-bit halves: `(low, high)`.
#[inline(always)]
fn clmul64(a: u64, b: u64) -> (u64, u64) {
    let (a0, a1, b0, b1) = (a as u32, (a >> 32) as u32, b as u32, (b >> 32) as u32);
    let low = clmul32(a0, b0);
    let high = clmul32(a1, b1);
    let middle = clmul32(a0 ^ a1, b0 ^ b1) ^ low ^ high;
    (low ^ middle << 32, high ^ middle >> 32)
}

#[inline(always)]
pub(crate) fn clmul(a: u64, b: u64) -> u128 {
    let (low, high) = clmul64(a, b);
    (high as u128) << 64 | low as u128
}

/// The carry-less square: the bits of `a` spread to the even positions.
const fn spread(a: u64) -> u128 {
    let mut x = a as u128;
    x = (x | x << 32) & 0x0000_0000_FFFF_FFFF_0000_0000_FFFF_FFFF;
    x = (x | x << 16) & 0x0000_FFFF_0000_FFFF_0000_FFFF_0000_FFFF;
    x = (x | x << 8) & 0x00FF_00FF_00FF_00FF_00FF_00FF_00FF_00FF;
    x = (x | x << 4) & 0x0F0F_0F0F_0F0F_0F0F_0F0F_0F0F_0F0F_0F0F;
    x = (x | x << 2) & 0x3333_3333_3333_3333_3333_3333_3333_3333;
    (x | x << 1) & 0x5555_5555_5555_5555_5555_5555_5555_5555
}

/// Reduce a 128-bit carry-less product modulo `x^64 + x^4 + x^3 + x + 1`.
pub(crate) const fn reduce(p: u128) -> u64 {
    let (lo, hi) = (p as u64, (p >> 64) as u64);
    let spill = (hi >> 63) ^ (hi >> 61) ^ (hi >> 60);
    let v = hi ^ spill;
    lo ^ v ^ (v << 1) ^ (v << 3) ^ (v << 4)
}

fn base_mul(left: u64, right: u64) -> u64 {
    reduce(clmul(left, right))
}

/// GF(2^64).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct K(pub u64);

impl K {
    pub fn square(self) -> Self {
        Self(reduce(spread(self.0)))
    }

    /// `self^(2^64 - 2)` by Itoh-Tsujii; zero maps to zero.
    pub fn inv(self) -> Self {
        let sq = |mut v: Self, n: u32| {
            for _ in 0..n {
                v = v.square();
            }
            v
        };
        let t1 = self;
        let t2 = sq(t1, 1) * t1;
        let t3 = sq(t2, 1) * t1;
        let t6 = sq(t3, 3) * t3;
        let t12 = sq(t6, 6) * t6;
        let t24 = sq(t12, 12) * t12;
        let t48 = sq(t24, 24) * t24;
        let t60 = sq(t48, 12) * t12;
        let t63 = sq(t60, 3) * t3;
        sq(t63, 1)
    }
}

impl Add for K {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl Mul for K {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self(base_mul(self.0, rhs.0))
    }
}

/// `K[y]/(y^3 + y + 1)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct E {
    pub c0: u64,
    pub c1: u64,
    pub c2: u64,
}

pub const ZERO: E = E::new(0, 0, 0);
pub const ONE: E = E::new(1, 0, 0);
pub const GEN: E = E::new(2, 0, 0);

impl E {
    pub const fn new(c0: u64, c1: u64, c2: u64) -> Self {
        Self { c0, c1, c2 }
    }

    pub fn from_bytes(data: &[u8; 24]) -> Self {
        let limb = |at: usize| {
            let mut word = [0u8; 8];
            word.copy_from_slice(&data[at..at + 8]);
            u64::from_le_bytes(word)
        };
        Self::new(limb(0), limb(8), limb(16))
    }

    /// `x^k`, `k < 64`: a monomial of `K`.
    pub const fn monomial(k: usize) -> Self {
        Self::new(1 << k, 0, 0)
    }

    pub fn is_zero(self) -> bool {
        self == ZERO
    }

    pub fn square(self) -> Self {
        let (s0, s1, s2) = (spread(self.c0), spread(self.c1), spread(self.c2));
        // y^4 = y^2 + y.
        Self::new(reduce(s0), reduce(s2), reduce(s1 ^ s2))
    }

    /// `self^(2^64)`: K is fixed, and y maps to y^2.
    fn frobenius(self) -> Self {
        Self::new(self.c0, self.c2, self.c1 ^ self.c2)
    }

    pub fn pow(self, exponent: u64) -> Self {
        let (mut base, mut out, mut n) = (self, ONE, exponent);
        while n != 0 {
            if n & 1 == 1 {
                out *= base;
            }
            base = base.square();
            n >>= 1;
        }
        out
    }

    /// `self^(2^192 - 2)` through the norm to K. Zero maps to zero.
    pub fn inv(self) -> Self {
        let m = self.frobenius() * self.frobenius().frobenius();
        let norm = self * m;
        m * E::from(K(norm.c0).inv())
    }

    /// `self * x^k`, `k < 64`, by shifts.
    pub fn times_monomial(self, k: usize) -> Self {
        let shift = |limb: u64| reduce((limb as u128) << k);
        Self::new(shift(self.c0), shift(self.c1), shift(self.c2))
    }
}

impl From<K> for E {
    fn from(value: K) -> Self {
        Self::new(value.0, 0, 0)
    }
}

impl Add for E {
    type Output = Self;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self {
        Self::new(self.c0 ^ rhs.c0, self.c1 ^ rhs.c1, self.c2 ^ rhs.c2)
    }
}

impl AddAssign for E {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Mul for E {
    type Output = Self;
    /// Karatsuba: six base products into the coefficients of y^0..y^4, then y^3 = y + 1 folds them back into three limbs.
    fn mul(self, rhs: Self) -> Self {
        let (a, b) = (self, rhs);
        let (p0, p1, p2) = (clmul(a.c0, b.c0), clmul(a.c1, b.c1), clmul(a.c2, b.c2));
        let e1 = clmul(a.c0 ^ a.c1, b.c0 ^ b.c1) ^ p0 ^ p1;
        let e2 = clmul(a.c0 ^ a.c2, b.c0 ^ b.c2) ^ p0 ^ p2 ^ p1;
        let e3 = clmul(a.c1 ^ a.c2, b.c1 ^ b.c2) ^ p1 ^ p2;
        Self::new(reduce(p0 ^ e3), reduce(e1 ^ e3 ^ p2), reduce(e2 ^ p2))
    }
}

impl Mul<K> for E {
    type Output = Self;
    fn mul(self, rhs: K) -> Self {
        Self::new(
            base_mul(self.c0, rhs.0),
            base_mul(self.c1, rhs.0),
            base_mul(self.c2, rhs.0),
        )
    }
}

impl MulAssign for E {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_reference_vectors() {
        // From leanVM's verifier tests (independent Python reference).
        assert_eq!(K(0x01090913877ed8ed) * K(0x66ab35ac2768468f), K(0x50c4519dc383744a));
        let a = E::new(0x950e87d7f5606615, 0x2c61275c9e6b6cf8, 0x1f00bca0042db923);
        let b = E::new(0x6dbca290a9eab706, 0x4c10a4fe30cffdda, 0xf26fff4cc4fd394d);
        assert_eq!(
            a * b,
            E::new(0x888a0fc35abaf5f6, 0x68a84cbc132b0649, 0x9fdeaf613003cabe)
        );
        assert_eq!(
            a.square(),
            E::new(0x8fba131ad5d46b8c, 0x1c170457f537a805, 0x3632cc098ca15135)
        );
        assert_eq!(a * a.inv(), ONE);
        for k in 0..64 {
            assert_eq!(a.times_monomial(k), a * E::monomial(k));
        }
    }
}
