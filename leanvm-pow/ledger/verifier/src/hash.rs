//! Keccak-f[1600] and Keccak-256 (Ethereum's padding), and digests.
//!
//! On the device the permutation is the PQ Bench app's assembly (`ledger-app/src/crypto`),
//! which works on the bit-interleaved state; elsewhere a portable one.

use crate::field::E;
use crate::{Error, require};

pub const STATE_LANES: usize = 25;
pub const RATE: usize = 136;
pub const ROUNDS: usize = 24;

pub const KECCAK_RC: [u64; ROUNDS] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];
pub const KECCAK_RHO: [u32; STATE_LANES] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];
/// Where lane `x + 5y` lands.
pub const KECCAK_PI: [usize; STATE_LANES] = {
    let mut pi = [0; STATE_LANES];
    let mut i = 0;
    while i < STATE_LANES {
        pi[i] = i / 5 + 5 * ((2 * (i % 5) + 3 * (i / 5)) % 5);
        i += 1;
    }
    pi
};

/// Keccak-f[1600], portable and `const`: the native permutation, and compile-time tables on the device.
pub const fn keccak_f_const(mut a: [u64; STATE_LANES]) -> [u64; STATE_LANES] {
    let mut round = 0;
    while round < ROUNDS {
        let mut c = [0u64; 5];
        let mut x = 0;
        while x < 5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            x += 1;
        }
        x = 0;
        while x < 5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            let mut y = 0;
            while y < 5 {
                a[x + 5 * y] ^= d;
                y += 1;
            }
            x += 1;
        }
        let mut b = [0u64; STATE_LANES];
        let mut i = 0;
        while i < STATE_LANES {
            b[KECCAK_PI[i]] = a[i].rotate_left(KECCAK_RHO[i]);
            i += 1;
        }
        let mut y = 0;
        while y < 5 {
            x = 0;
            while x < 5 {
                a[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
                x += 1;
            }
            y += 1;
        }
        a[0] ^= KECCAK_RC[round];
        round += 1;
    }
    a
}

/// A Keccak-f[1600] state in the platform's representation: its lanes natively; on the device bit-interleaved
/// (each lane as a word of its even bits, then a word of its odd bits), the form the app's assembly permutes, so
/// that only the lanes read or written are converted.
#[derive(Clone, Copy)]
pub struct State {
    #[cfg(not(feature = "device"))]
    lanes: [u64; STATE_LANES],
    #[cfg(feature = "device")]
    words: [u32; 2 * STATE_LANES],
}

#[cfg(feature = "device")]
unsafe extern "C" {
    /// `ledger-app/src/crypto/keccak.c`: Keccak-f[1600] on the bit-interleaved state.
    fn keccak_permute(s: *mut u32);
}

/// Even bits of x to the low half, odd bits to the high half.
#[cfg(feature = "device")]
fn unzip(mut x: u32) -> u32 {
    let mut t;
    t = (x ^ (x >> 1)) & 0x22222222;
    x ^= t ^ (t << 1);
    t = (x ^ (x >> 2)) & 0x0C0C0C0C;
    x ^= t ^ (t << 2);
    t = (x ^ (x >> 4)) & 0x00F000F0;
    x ^= t ^ (t << 4);
    t = (x ^ (x >> 8)) & 0x0000FF00;
    x ^= t ^ (t << 8);
    x
}

#[cfg(feature = "device")]
fn zip(mut x: u32) -> u32 {
    let mut t;
    t = (x ^ (x >> 8)) & 0x0000FF00;
    x ^= t ^ (t << 8);
    t = (x ^ (x >> 4)) & 0x00F000F0;
    x ^= t ^ (t << 4);
    t = (x ^ (x >> 2)) & 0x0C0C0C0C;
    x ^= t ^ (t << 2);
    t = (x ^ (x >> 1)) & 0x22222222;
    x ^= t ^ (t << 1);
    x
}

impl State {
    #[cfg(not(feature = "device"))]
    pub const ZERO: State = State {
        lanes: [0; STATE_LANES],
    };
    #[cfg(feature = "device")]
    pub const ZERO: State = State {
        words: [0; 2 * STATE_LANES],
    };

    #[cfg(not(feature = "device"))]
    pub fn permute(&mut self) {
        self.lanes = keccak_f_const(self.lanes);
    }

    #[cfg(feature = "device")]
    pub fn permute(&mut self) {
        unsafe { keccak_permute(self.words.as_mut_ptr()) };
    }

    #[cfg(not(feature = "device"))]
    pub fn lane(&self, i: usize) -> u64 {
        self.lanes[i]
    }

    #[cfg(feature = "device")]
    pub fn lane(&self, i: usize) -> u64 {
        let (even, odd) = (self.words[2 * i], self.words[2 * i + 1]);
        let lo = zip((even & 0xFFFF) | (odd << 16));
        let hi = zip((even >> 16) | (odd & 0xFFFF_0000));
        lo as u64 | (hi as u64) << 32
    }

    /// Lane `i` XORed with `value`.
    #[cfg(not(feature = "device"))]
    pub fn xor_lane(&mut self, i: usize, value: u64) {
        self.lanes[i] ^= value;
    }

    #[cfg(feature = "device")]
    pub fn xor_lane(&mut self, i: usize, value: u64) {
        let (lo, hi) = (unzip(value as u32), unzip((value >> 32) as u32));
        self.words[2 * i] ^= (lo & 0xFFFF) | (hi << 16);
        self.words[2 * i + 1] ^= (lo >> 16) | (hi & 0xFFFF_0000);
    }

    #[cfg(not(feature = "device"))]
    pub fn set_lane(&mut self, i: usize, value: u64) {
        self.lanes[i] = value;
    }

    #[cfg(feature = "device")]
    pub fn set_lane(&mut self, i: usize, value: u64) {
        let (lo, hi) = (unzip(value as u32), unzip((value >> 32) as u32));
        self.words[2 * i] = (lo & 0xFFFF) | (hi << 16);
        self.words[2 * i + 1] = (lo >> 16) | (hi & 0xFFFF_0000);
    }
}

/// Keccak-256, fed in pieces: whole 64-bit words where the input allows.
pub struct Hasher {
    state: State,
    filled: usize, // bytes of the current block absorbed
    word: u64,     // the bytes of a lane not yet XORed into it
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    pub fn new() -> Self {
        Self {
            state: State::ZERO,
            filled: 0,
            word: 0,
        }
    }

    /// The bytes since the last whole lane, as one; then the permutation when the block is full.
    fn end_lane(&mut self) {
        if self.word != 0 {
            self.state.xor_lane(self.filled / 8 - 1, self.word);
            self.word = 0;
        }
        if self.filled == RATE {
            self.state.permute();
            self.filled = 0;
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.filled.is_multiple_of(8) && data.len() >= 8 {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&data[..8]);
                self.word = u64::from_le_bytes(bytes);
                self.filled += 8;
                data = &data[8..];
            } else {
                self.word |= (data[0] as u64) << (8 * (self.filled % 8));
                self.filled += 1;
                data = &data[1..];
                if !self.filled.is_multiple_of(8) {
                    continue;
                }
            }
            self.end_lane();
        }
    }

    /// `n` zero bytes.
    pub fn zeros(&mut self, mut n: usize) {
        while n > 0 {
            let step = n.min(8 - self.filled % 8);
            self.filled += step;
            n -= step;
            if self.filled.is_multiple_of(8) {
                self.end_lane();
            }
        }
    }

    pub fn finish(mut self) -> Digest {
        self.word |= 0x01 << (8 * (self.filled % 8));
        self.state.xor_lane(self.filled / 8, self.word);
        self.state.xor_lane(RATE / 8 - 1, 0x80 << 56);
        self.state.permute();
        let mut value = [0u8; 32];
        for i in 0..4 {
            value[8 * i..8 * i + 8].copy_from_slice(&self.state.lane(i).to_le_bytes());
        }
        Digest(value)
    }
}

pub fn keccak_hash(data: &[u8]) -> Digest {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finish()
}

pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> Digest {
    let mut hasher = Hasher::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finish()
}

/// 256 bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn words(&self) -> [u64; 4] {
        let mut out = [0u64; 4];
        for (i, word) in out.iter_mut().enumerate() {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&self.0[8 * i..8 * i + 8]);
            *word = u64::from_le_bytes(bytes);
        }
        out
    }

    pub fn halves(&self) -> (E, E) {
        let [w0, w1, w2, w3] = self.words();
        (E::new(w0, w1, 0), E::new(w2, w3, 0))
    }

    pub fn from_halves(low: E, high: E) -> Result<Self, Error> {
        require(low.c2 == 0 && high.c2 == 0, Error::DigestHalf)?;
        let mut value = [0u8; 32];
        for (i, word) in [low.c0, low.c1, high.c0, high.c1].into_iter().enumerate() {
            value[8 * i..8 * i + 8].copy_from_slice(&word.to_le_bytes());
        }
        Ok(Self(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak256_vectors() {
        // From leanVM's verifier tests (the `sha3` crate's Keccak256 of 00 01 .. (mod 256)).
        for (n, want) in [
            (0, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
            (135, "cbdfd9dee5faad3818d6b06f95a219fd290b0e1706f6a82e5a595b9ce9faca62"),
            (136, "7ce759f1ab7f9ce437719970c26b0a66ff11fe3e38e17df89cf5d29c7d7f807e"),
            (272, "fdf2ec49e749960d3c8521a0219af8d03e30e2b3bf19bd16150ee0eaf133d66e"),
        ] {
            let input: std::vec::Vec<u8> = (0..n).map(|i| i as u8).collect();
            let got: std::string::String = keccak_hash(&input).0.iter().map(|b| std::format!("{b:02x}")).collect();
            assert_eq!(got, want, "{n} bytes");
            let mut split = Hasher::new();
            split.update(&input[..n / 3]);
            split.update(&input[n / 3..]);
            assert_eq!(split.finish(), keccak_hash(&input));
        }
    }
}
