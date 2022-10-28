use num_bigint::{BigInt, Sign};

pub(crate) const CELLS_PER_HASH: u32 = 3;
pub(crate) const INPUT_CELLS_PER_HASH: u32 = 2;
pub(crate) struct PedersenInstanceDef {
    pub(crate) ratio: u32,
    pub(crate) repetitions: u32,
    pub(crate) element_height: u32,
    pub(crate) element_bits: u32,
    pub(crate) n_inputs: u32,
    pub(crate) hash_limit: BigInt,
}

impl PedersenInstanceDef {
    pub(crate) fn default() -> Self {
        PedersenInstanceDef {
            ratio: 8,
            repetitions: 4,
            element_height: 256,
            element_bits: 252,
            n_inputs: 2,
            hash_limit: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
        }
    }

    pub(crate) fn new(ratio: u32, repetitions: u32) -> Self {
        PedersenInstanceDef {
            ratio,
            repetitions,
            element_height: 256,
            element_bits: 252,
            n_inputs: 2,
            hash_limit: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
        }
    }

    pub(crate) fn cells_per_builtin(&self) -> u32 {
        CELLS_PER_HASH
    }

    pub(crate) fn range_check_units_per_builtin(&self) -> u32 {
        0
    }
}
