use num_bigint::{BigInt, Sign};

const CELLS_PER_HASH: i32 = 3;
const INPUT_CELLS_PER_HASH: i32 = 2;
pub(crate) struct PedersenInstanceDef {
    ratio: i32,
    repetitions: i32,
    element_height: i32,
    element_bits: i32,
    n_inputs: i32,
    hash_limit: Option<BigInt>,
}

impl PedersenInstanceDef {
    pub(crate) fn default() -> Self {
        PedersenInstanceDef {
            ratio: 8,
            repetitions: 4,
            element_height: 256,
            element_bits: 252,
            n_inputs: 2,
            hash_limit: Some(BigInt::new(
                Sign::Plus,
                vec![1, 0, 0, 0, 0, 0, 17, 134217728],
            )),
        }
    }

    pub(crate) fn new(ratio: i32, repetitions: i32) -> Self {
        PedersenInstanceDef {
            ratio,
            repetitions,
            element_height: 256,
            element_bits: 252,
            n_inputs: 2,
            hash_limit: Some(BigInt::new(
                Sign::Plus,
                vec![1, 0, 0, 0, 0, 0, 17, 134217728],
            )),
        }
    }

    pub(crate) fn cells_per_builtin(&self) -> i32 {
        CELLS_PER_HASH
    }

    pub(crate) fn range_check_units_per_builtin(&self) -> i32 {
        0
    }
}
