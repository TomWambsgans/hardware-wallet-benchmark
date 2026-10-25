//! The stacked bytecode multilinear, from a sparse table compiled into the app ([`crate::program`]).
//!
//! The table is `TUPLE` columns of `2^ROWS_LOG` words, column-major, its index LSB-first the row's bits then
//! the column's. Only its nonzero words are stored: per column, each one's row and its index in a dictionary of
//! the distinct words.

use crate::field::{E, ZERO, reduce};
use crate::program::{COLUMN_START, DICT, ENTRIES, LOG_LEN};
use crate::tables::BUS_BITS;
use crate::transcript::{eq_bits, eq_kernel};
use crate::{Error, require};

const LO: usize = 5; // row bits weighed by a table; the rest are one eq product per group of 32 rows

pub fn len() -> u64 {
    1 << LOG_LEN
}

/// `sum_k x^k * sums[k]`: each limb shifted into place, then one reduction.
fn monomial_sum(sums: &[E; 64]) -> E {
    let (mut c0, mut c1, mut c2) = (0u128, 0u128, 0u128);
    for (k, sum) in sums.iter().enumerate() {
        c0 ^= (sum.c0 as u128) << k;
        c1 ^= (sum.c1 as u128) << k;
        c2 ^= (sum.c2 as u128) << k;
    }
    E::new(reduce(c0), reduce(c1), reduce(c2))
}

/// The table's multilinear extension at `point` (`LOG_LEN` coordinates, LSB-first).
pub fn evaluate(point: &[E]) -> Result<E, Error> {
    require(
        point.len() == LOG_LEN && LOG_LEN >= BUS_BITS + LO,
        Error::MultilinearSize,
    )?;
    let rows_log = LOG_LEN - BUS_BITS;
    let (row_point, column_point) = point.split_at(rows_log);
    require(rows_log <= 2 * LO + 1, Error::MultilinearSize)?;
    let mut eq_lo = [ZERO; 1 << LO];
    eq_kernel(&row_point[..LO], &mut eq_lo);
    let mut eq_hi = [ZERO; 1 << (LO + 1)];
    eq_kernel(&row_point[LO..], &mut eq_hi[..1 << (rows_log - LO)]);
    let mut total = ZERO;
    for column in 0..1 << BUS_BITS {
        let (start, end) = (COLUMN_START[column] as usize, COLUMN_START[column + 1] as usize);
        if start == end {
            continue;
        }
        let column_weight = eq_bits(column as u64, column_point);
        let mut column_sum = ZERO;
        let mut at = start;
        while at < end {
            // One group: the entries whose rows share their bits above LO.
            let group = (ENTRIES[at] >> 16) >> LO;
            let mut bit_sums = [ZERO; 64];
            while at < end && (ENTRIES[at] >> 16) >> LO == group {
                let entry = ENTRIES[at];
                let weight = eq_lo[(entry >> 16) as usize & ((1 << LO) - 1)];
                let mut word = DICT[(entry & 0xFFFF) as usize];
                while word != 0 {
                    let k = word.trailing_zeros() as usize;
                    bit_sums[k] += weight;
                    word &= word - 1;
                }
                at += 1;
            }
            column_sum += monomial_sum(&bit_sums) * eq_hi[group as usize];
        }
        total += column_weight * column_sum;
    }
    Ok(total)
}
