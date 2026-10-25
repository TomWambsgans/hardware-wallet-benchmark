//! The WHIR opening (leanVM's `whir.rs`), streaming its Merkle openings: each queried row is hashed and folded as
//! it arrives, so a level keeps only (position, digest, value) per distinct query.

use crate::field::{E, K, ONE, ZERO};
use crate::hash::{Digest, Hasher, hash_pair};
use crate::transcript::{Piece, Source, Transcript, eq_eval, eq_kernel, fold_eval, log2_strict, poly_eval};
use crate::{Error, MAX_POINT, require};

const INITIAL_FOLDING_FACTOR: usize = 6;
const SUBSEQUENT_FOLDING_FACTOR: usize = 4;
const RS_DOMAIN_INITIAL_REDUCTION_FACTOR: usize = 3;
const RS_DOMAIN_SUBSEQUENT_REDUCTION_FACTOR: usize = 1;
const RESIDUAL_MAX_LOG: usize = 5;
const QUERY_GRINDING_BITS: u32 = 17;
const MIN_STACKED_LOG: usize = crate::bus::MIN_STACKED_LOG;
const MAX_STACKED_LOG: usize = crate::bus::MAX_STACKED_LOG;
const MAX_LEVELS: usize = 6;

/// Queries one level may draw, and all levels together: on the device what rate 1/4 draws (at most 112 at
/// level 0, 235 in all), not rate 1/2's 225 and 368.
#[cfg(feature = "device")]
pub const MAX_QUERIES: usize = 112;
#[cfg(feature = "device")]
const MAX_ALL_QUERIES: usize = 240;
#[cfg(not(feature = "device"))]
pub const MAX_QUERIES: usize = 256;
#[cfg(not(feature = "device"))]
const MAX_ALL_QUERIES: usize = 400;
/// The out-of-domain points of every level but the last: their sizes sum to at most 22 + 18 + 14 + 10 + 6.
const MAX_OOD: usize = 72;

/// leanVM's `WHIR_QUERIES`: per log inverse rate (1..=4) and stacked log size (15..=28), each level's query count.
#[rustfmt::skip]
const WHIR_QUERIES: [[[u16; MAX_LEVELS]; 14]; 4] = [
    [[222, 55, 0, 0, 0, 0], [223, 56, 30, 0, 0, 0], [223, 56, 31, 0, 0, 0], [223, 56, 32, 0, 0, 0], [223, 56, 32, 0, 0, 0], [223, 56, 32, 22, 0, 0], [223, 56, 32, 22, 0, 0], [224, 56, 32, 23, 0, 0], [224, 56, 32, 23, 0, 0], [224, 56, 32, 23, 17, 0], [224, 56, 32, 23, 17, 0], [224, 56, 32, 23, 18, 0], [225, 56, 32, 23, 18, 0], [225, 56, 32, 23, 18, 14]],
    [[111, 45, 0, 0, 0, 0], [112, 45, 27, 0, 0, 0], [112, 45, 28, 0, 0, 0], [112, 45, 28, 0, 0, 0], [112, 45, 28, 0, 0, 0], [112, 45, 28, 20, 0, 0], [112, 45, 28, 20, 0, 0], [112, 45, 28, 21, 0, 0], [112, 45, 28, 21, 0, 0], [112, 45, 28, 21, 16, 0], [112, 45, 28, 21, 16, 0], [112, 45, 28, 21, 16, 0], [112, 45, 28, 21, 16, 0], [112, 45, 28, 21, 16, 13]],
    [[75, 37, 0, 0, 0, 0], [75, 37, 24, 0, 0, 0], [75, 37, 25, 0, 0, 0], [75, 38, 25, 0, 0, 0], [75, 38, 25, 0, 0, 0], [75, 38, 25, 18, 0, 0], [75, 38, 25, 19, 0, 0], [75, 38, 25, 19, 0, 0], [75, 38, 25, 19, 0, 0], [75, 38, 25, 19, 15, 0], [75, 38, 25, 19, 15, 0], [75, 38, 25, 19, 15, 0], [75, 38, 25, 19, 15, 0], [75, 38, 25, 19, 15, 13]],
    [[56, 32, 0, 0, 0, 0], [56, 32, 22, 0, 0, 0], [56, 32, 22, 0, 0, 0], [56, 32, 23, 0, 0, 0], [56, 32, 23, 0, 0, 0], [56, 32, 23, 17, 0, 0], [56, 32, 23, 17, 0, 0], [56, 32, 23, 18, 0, 0], [56, 32, 23, 18, 0, 0], [56, 32, 23, 18, 14, 0], [56, 32, 23, 18, 14, 0], [56, 32, 23, 18, 14, 0], [56, 32, 23, 18, 15, 0], [56, 32, 23, 18, 15, 12]],
];

struct Config {
    levels: usize,
    log_inv_rates: [usize; MAX_LEVELS],
    folds: [usize; MAX_LEVELS],
    queries: [usize; MAX_LEVELS],
}

fn derive_config(log_n: usize, log_inv_rate: usize) -> Result<Config, Error> {
    require(
        (MIN_STACKED_LOG..=MAX_STACKED_LOG).contains(&log_n) && (1..=4).contains(&log_inv_rate),
        Error::WhirShape,
    )?;
    let mut config = Config {
        levels: 1,
        log_inv_rates: [0; MAX_LEVELS],
        folds: [0; MAX_LEVELS],
        queries: [0; MAX_LEVELS],
    };
    config.folds[0] = INITIAL_FOLDING_FACTOR;
    config.log_inv_rates[0] = log_inv_rate;
    let mut remaining = log_n - INITIAL_FOLDING_FACTOR;
    while remaining > RESIDUAL_MAX_LOG {
        require(config.levels < MAX_LEVELS, Error::QueryCountLadder)?;
        let reduction = if config.levels == 1 {
            RS_DOMAIN_INITIAL_REDUCTION_FACTOR
        } else {
            RS_DOMAIN_SUBSEQUENT_REDUCTION_FACTOR
        };
        let last = config.levels - 1;
        config.log_inv_rates[config.levels] = config.log_inv_rates[last] + config.folds[last] - reduction;
        let fold = SUBSEQUENT_FOLDING_FACTOR.min(remaining);
        remaining -= fold;
        config.folds[config.levels] = fold;
        config.levels += 1;
    }
    let table = &WHIR_QUERIES[log_inv_rate - 1][log_n - MIN_STACKED_LOG];
    let n_table = table.iter().take_while(|&&q| q != 0).count();
    require(n_table == config.levels, Error::QueryCountLadder)?;
    for level in 0..config.levels {
        config.queries[level] = table[level] as usize;
        require(config.queries[level] <= MAX_QUERIES, Error::WhirShape)?;
    }
    Ok(config)
}

fn sample_queries<S: Source>(transcript: &mut Transcript<S>, block_length: u64, out: &mut [u32]) -> Result<(), Error> {
    let depth = log2_strict(block_length)?;
    require(depth <= 32, Error::WhirShape)?;
    let per_word = 192 / depth;
    let mut filled = 0;
    while filled < out.len() {
        let sample = transcript.sample();
        let bits = [sample.c0, sample.c1, sample.c2, 0];
        for chunk in 0..per_word.min(out.len() - filled) {
            let (limb, shift) = (chunk * depth / 64, chunk * depth % 64);
            let window = (bits[limb] as u128 | (bits[limb + 1] as u128) << 64) >> shift;
            out[filled] = (window as u64 & (block_length - 1)) as u32;
            filled += 1;
        }
    }
    Ok(())
}

/// The level's batched query claims as one weight at `point` (annex B, lemma lem:colweight).
fn induced_weight(queries: &[u32], lam: E, point: &[E]) -> E {
    let message_log = point.len();
    // The subspace polynomials' normalizers: the subspaces are spanned by powers of x, so all lie in K.
    let mut roots = [K(0); MAX_POINT + 1];
    let mut layer = [K(0); MAX_POINT];
    roots[0] = K(1);
    for (i, value) in layer[..message_log].iter_mut().enumerate() {
        *value = K(1 << (i + 1));
    }
    for i in 0..message_log {
        let root = roots[i];
        for value in layer[i..message_log].iter_mut() {
            *value = value.square() + root * *value;
        }
        roots[i + 1] = layer[i];
    }
    let mut inverses = [K(0); MAX_POINT];
    for (inverse, root) in inverses[..message_log].iter_mut().zip(&roots) {
        *inverse = root.inv();
    }
    let mut total = ZERO;
    let mut weight = ONE;
    for &query in queries {
        let mut basis = K(query as u64);
        let mut product = weight;
        for (coordinate, &challenge) in point.iter().enumerate() {
            product *= ONE + challenge * (K(1) + basis * inverses[coordinate]);
            basis = basis.square() + roots[coordinate] * basis;
        }
        total += product;
        weight *= lam;
    }
    total
}

/// A level's Merkle opening: rows at the distinct queried positions, ascending, then the siblings that authenticate
/// them together. Each row is hashed and reduced to `value` (its lanes against `lane_weights`) as it arrives.
struct Opened {
    positions: [u32; MAX_QUERIES],
    values: [E; MAX_QUERIES],
    count: usize,
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn open_rows<S: Source>(
    opened: &mut Opened,
    transcript: &mut Transcript<S>,
    root: Digest,
    block_length: u64,
    queries: &[u32],
    row_words: usize,
    leaf_words: usize,
    level0: bool,
    lane_weights: &[E],
) -> Result<(), Error> {
    let height = log2_strict(block_length)?;
    opened.count = 0;
    // The distinct positions, ascending.
    for &query in queries {
        let at = opened.positions[..opened.count].partition_point(|&p| p < query);
        if at < opened.count && opened.positions[at] == query {
            continue;
        }
        opened.positions.copy_within(at..opened.count, at + 1);
        opened.positions[at] = query;
        opened.count += 1;
    }
    require(row_words <= leaf_words && leaf_words <= 64, Error::MerkleOpeningShape)?;
    let mut digests = [[0u8; 32]; MAX_QUERIES];
    let mut indices = [0u32; MAX_QUERIES];
    transcript.read(Piece::Batch, &mut [])?;
    let prefix = leaf_words - row_words;
    let mut row = [0u8; 8 * 64];
    for i in 0..opened.count {
        transcript.read(Piece::Row, &mut row[..8 * row_words])?;
        let mut hasher = Hasher::new();
        hasher.zeros(8 * prefix);
        hasher.update(&row[..8 * row_words]);
        digests[i] = hasher.finish().0;
        indices[i] = opened.positions[i];
        let word = |k: usize| {
            // Word k of the leaf image, its zero prefix included.
            if k < prefix {
                return 0u64;
            }
            let at = 8 * (k - prefix);
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&row[at..at + 8]);
            u64::from_le_bytes(bytes)
        };
        let mut value = ZERO;
        if level0 {
            for (i, &weight) in lane_weights.iter().enumerate() {
                let w = word(leaf_words - 1 - i);
                if w != 0 {
                    value += weight * K(w);
                }
            }
        } else {
            for (lane, &weight) in lane_weights.iter().enumerate() {
                value += weight * E::new(word(3 * lane), word(3 * lane + 1), word(3 * lane + 2));
            }
        }
        opened.values[i] = value;
    }
    // Every node on a queried path, bottom-up, a sibling read only where it is not itself on one.
    let mut n = opened.count;
    for _ in 0..height {
        let (mut read, mut write) = (0, 0);
        while read < n {
            let index = indices[read];
            let paired = index & 1 == 0 && read + 1 < n && indices[read + 1] == index | 1;
            let parent = if paired {
                let parent = hash_pair(&digests[read], &digests[read + 1]);
                read += 2;
                parent
            } else {
                let mut sibling = [0u8; 32];
                transcript.read(Piece::Sibling, &mut sibling)?;
                let parent = if index & 1 == 0 {
                    hash_pair(&digests[read], &sibling)
                } else {
                    hash_pair(&sibling, &digests[read])
                };
                read += 1;
                parent
            };
            digests[write] = parent.0;
            indices[write] = index >> 1;
            write += 1;
        }
        n = write;
    }
    require(n == 1 && digests[0] == root.0, Error::MerkleRootMismatch)
}

#[derive(Clone, Copy)]
enum Glued {
    Ood { at: usize, len: usize },
    Queries { at: usize, len: usize, lam: E },
}

/// Verify the multilevel opening of the stacked witness: the claims `target` batches, whose weights
/// `evaluate_basis` evaluates at the terminal point.
#[inline(never)]
pub fn verify_whir<S: Source, F: FnOnce(&[E]) -> E>(
    transcript: &mut Transcript<S>,
    log_n: usize,
    placed: u64,
    log_inv_rate: usize,
    target: E,
    root: Digest,
    evaluate_basis: F,
) -> Result<(), Error> {
    let config = derive_config(log_n, log_inv_rate)?;
    let mut running_quad = [ZERO; 5];
    transcript.round_poly(3, target, None, &mut running_quad)?;
    let mut folds = [ZERO; MAX_POINT];
    let mut n_folds = 0;
    let mut glued = [(ZERO, 0usize, Glued::Ood { at: 0, len: 0 }); 2 * MAX_LEVELS];
    let mut n_glued = 0;
    let mut ood_points = [ZERO; MAX_OOD];
    let mut opened = Opened {
        positions: [0; MAX_QUERIES],
        values: [ZERO; MAX_QUERIES],
        count: 0,
    };
    let mut n_ood = 0;
    let mut all_queries = [0u32; MAX_ALL_QUERIES];
    let mut n_queries = 0;
    let mut current_root = root;

    for level in 0..config.levels {
        let (fold_count, level_rate) = (config.folds[level], config.log_inv_rates[level]);
        let level_start = n_folds;
        for _ in 0..fold_count {
            let challenge = transcript.sample();
            folds[n_folds] = challenge;
            n_folds += 1;
            let claim = poly_eval(&running_quad[..3], challenge);
            transcript.round_poly(3, claim, None, &mut running_quad)?;
        }
        let message_log = log_n - n_folds;
        let final_level = level == config.levels - 1;
        let mut pending = [([ZERO; 5], Glued::Ood { at: 0, len: 0 }); 2];
        let mut n_pending = 0;
        let mut residual = [ZERO; 1 << RESIDUAL_MAX_LOG];
        let mut next_root = current_root;
        if final_level {
            require(message_log <= RESIDUAL_MAX_LOG, Error::WhirShape)?;
            transcript.next_scalars(&mut residual[..1 << message_log])?;
        } else {
            let mut halves = [ZERO; 2];
            transcript.next_scalars(&mut halves)?;
            next_root = Digest::from_halves(halves[0], halves[1])?;
            require(n_ood + message_log <= ood_points.len(), Error::WhirShape)?;
            transcript.samples(&mut ood_points[n_ood..n_ood + message_log]);
            let ood_value = transcript.next_scalar()?;
            let mut intro = [ZERO; 5];
            transcript.round_poly(3, ood_value, None, &mut intro)?;
            pending[n_pending] = (
                intro,
                Glued::Ood {
                    at: n_ood,
                    len: message_log,
                },
            );
            n_pending += 1;
            n_ood += message_log;
        }

        transcript.grind_check(QUERY_GRINDING_BITS)?;
        let block_length = 1u64 << (message_log + level_rate);
        let count = config.queries[level];
        require(n_queries + count <= MAX_ALL_QUERIES, Error::WhirShape)?;
        let queries = &mut all_queries[n_queries..n_queries + count];
        sample_queries(transcript, block_length, queries)?;
        let lam = transcript.sample();
        let lanes = 1usize << fold_count;
        let leaf_words = if level == 0 { lanes } else { 3 * lanes };
        let row_words = if level == 0 {
            placed.div_ceil(1 << message_log) as usize
        } else {
            leaf_words
        };
        let mut lane_weights = [ZERO; 64];
        eq_kernel(&folds[level_start..n_folds], &mut lane_weights[..lanes]);
        open_rows(
            &mut opened,
            transcript,
            current_root,
            block_length,
            queries,
            row_words,
            leaf_words,
            level == 0,
            &lane_weights[..lanes],
        )?;
        let mut enforced = ZERO;
        let mut weight = ONE;
        for &query in queries.iter() {
            let at = opened.positions[..opened.count].partition_point(|&p| p < query);
            enforced += opened.values[at] * weight;
            weight *= lam;
        }
        let mut intro = [ZERO; 5];
        transcript.round_poly(3, enforced, None, &mut intro)?;
        pending[n_pending] = (
            intro,
            Glued::Queries {
                at: n_queries,
                len: count,
                lam,
            },
        );
        n_pending += 1;
        n_queries += count;
        let mut scalar = ONE;
        for &(intro, claim) in &pending[..n_pending] {
            scalar *= lam;
            for (q, i) in running_quad[..3].iter_mut().zip(intro) {
                *q += scalar * i;
            }
            glued[n_glued] = (scalar, n_folds, claim);
            n_glued += 1;
        }

        if final_level {
            let mut tail = [ZERO; RESIDUAL_MAX_LOG];
            let mut running_target = ZERO;
            for round in 0..message_log {
                let challenge = transcript.sample();
                running_target = poly_eval(&running_quad[..3], challenge);
                tail[round] = challenge;
                if round + 1 < message_log {
                    transcript.round_poly(3, running_target, None, &mut running_quad)?;
                }
            }
            // Each glued claim is rebound at the terminal point: the folds its level fixed after it, then the tail.
            let mut point = [ZERO; MAX_POINT];
            point[..n_folds].copy_from_slice(&folds[..n_folds]);
            point[n_folds..n_folds + message_log].copy_from_slice(&tail[..message_log]);
            let point = &point[..n_folds + message_log];
            let lane_folds = config.folds[0];
            let mut rotated = [ZERO; MAX_POINT];
            let n = point.len();
            rotated[..n - lane_folds].copy_from_slice(&point[lane_folds..]);
            rotated[n - lane_folds..n].copy_from_slice(&point[..lane_folds]);
            let mut weight = evaluate_basis(&rotated[..n]);
            for &(scalar, fold_start, claim) in &glued[..n_glued] {
                let at_point = &point[fold_start..];
                weight += scalar
                    * match claim {
                        Glued::Ood { at, len } => eq_eval(&ood_points[at..at + len], at_point),
                        Glued::Queries { at, len, lam } => induced_weight(&all_queries[at..at + len], lam, at_point),
                    };
            }
            let terminal = weight * fold_eval(&mut residual[..1 << message_log], &tail[..message_log])?;
            return require(terminal == running_target, Error::WhirTerminal);
        }
        current_root = next_root;
    }
    Err(Error::WhirShape)
}
