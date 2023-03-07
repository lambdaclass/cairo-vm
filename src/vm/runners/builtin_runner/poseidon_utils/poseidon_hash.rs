// Code ported from the implementation from pathfinder here:
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_permute_a() {
        let mut poseidon_state = [FieldElement::THREE, FieldElement::ZERO, FieldElement::TWO];
        permute_comp(&mut poseidon_state);
        assert_eq!(
            poseidon_state,
            [
                FieldElement::from_hex_be(
                    "0x268c44203f1c763bca21beb5aec78b9063cdcdd0fdf6b598bb8e1e8f2b6253f"
                )
                .unwrap(),
                FieldElement::from_hex_be(
                    "0x2b85c9f686f5d3036db55b2ca58a763a3065bc1bc8efbe0e70f3a7171f6cad3"
                )
                .unwrap(),
                FieldElement::from_hex_be(
                    "0x61df3789eef0e1ee0dbe010582a00dd099191e6395dfb976e7be3be2fa9d54b"
                )
                .unwrap()
            ]
        )
    }

    #[test]
    fn test_permute_b() {
        let mut poseidon_state = [
            FieldElement::from_hex_be(
                "0x268c44203f1c763bca21beb5aec78b9063cdcdd0fdf6b598bb8e1e8f2b6253f",
            )
            .unwrap(),
            FieldElement::from_hex_be(
                "0x2b85c9f686f5d3036db55b2ca58a763a3065bc1bc8efbe0e70f3a7171f6cad3",
            )
            .unwrap(),
            FieldElement::from_hex_be(
                "0x61df3789eef0e1ee0dbe010582a00dd099191e6395dfb976e7be3be2fa9d54b",
            )
            .unwrap(),
        ];
        permute_comp(&mut poseidon_state);
        assert_eq!(
            poseidon_state,
            [
                FieldElement::from_hex_be(
                    "0x4ec565b1b01606b5222602b20f8ddc4a8a7c75b559b852ab183a0daf5930b5c"
                )
                .unwrap(),
                FieldElement::from_hex_be(
                    "0x4d3c32c3c7cd39b6444db42e2437eeda12e459d28ce49a0f761a23d64c29e4c"
                )
                .unwrap(),
                FieldElement::from_hex_be(
                    "0x749d4d0ddf41548e039f183b745a08b80fad54e9ac389021148350bdda70a92"
                )
                .unwrap()
            ]
        )
    }
}
