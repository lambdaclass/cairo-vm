// Code ported from the the implementation from pathfinder here:
//   https://github.com/eqlabs/pathfinder/blob/00a1a74a90a7b8a7f1d07ac3e616be1cb39cf8f1/crates/stark_poseidon/src/lib.rs

use super::poseidon_constants::{FULL_ROUNDS, PARTIAL_ROUNDS, POSEIDON_COMP_CONSTS};
use starknet_crypto::FieldElement;

/// Linear layer for MDS matrix M = ((3,1,1), (1,-1,1), (1,1,2))
/// Given state vector x, it returns Mx, optimized by precomputing t.
#[inline(always)]
fn mix(state: &mut [FieldElement; 3]) {
    let t = state[0] + state[1] + state[2];
    state[0] = t + FieldElement::TWO * state[0];
    state[1] = t - FieldElement::TWO * state[1];
    state[2] = t - FieldElement::THREE * state[2];
}

#[inline]
fn round_comp(state: &mut [FieldElement; 3], idx: usize, full: bool) {
    if full {
        state[0] = state[0] + POSEIDON_COMP_CONSTS[idx];
        state[1] = state[1] + POSEIDON_COMP_CONSTS[idx + 1];
        state[2] = state[2] + POSEIDON_COMP_CONSTS[idx + 2];
        state[0] = state[0] * state[0] * state[0];
        state[1] = state[1] * state[1] * state[1];
        state[2] = state[2] * state[2] * state[2];
    } else {
        state[2] = state[2] + POSEIDON_COMP_CONSTS[idx];
        state[2] = state[2] * state[2] * state[2];
    }
    mix(state);
}

/// Poseidon permutation function
pub fn permute_comp(state: &mut [FieldElement; 3]) {
    let mut idx = 0;

    // Full rounds
    for _ in 0..(FULL_ROUNDS / 2) {
        round_comp(state, idx, true);
        idx += 3;
    }

    // Partial rounds
    for _ in 0..PARTIAL_ROUNDS {
        round_comp(state, idx, false);
        idx += 1;
    }

    // Full rounds
    for _ in 0..(FULL_ROUNDS / 2) {
        round_comp(state, idx, true);
        idx += 3;
    }
}
