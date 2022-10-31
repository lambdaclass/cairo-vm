use num_bigint::{BigInt, Sign};

pub(crate) const CELLS_PER_HASH: u32 = 3;
pub(crate) const INPUT_CELLS_PER_HASH: u32 = 2;

#[derive(Debug)]
pub(crate) struct PedersenInstanceDef {
    pub(crate) ratio: u32,
    pub(crate) _repetitions: u32,
    pub(crate) _element_height: u32,
    pub(crate) _element_bits: u32,
    pub(crate) _n_inputs: u32,
    pub(crate) _hash_limit: BigInt,
}

impl PedersenInstanceDef {
    pub(crate) fn default() -> Self {
        PedersenInstanceDef {
            ratio: 8,
            _repetitions: 4,
            _element_height: 256,
            _element_bits: 252,
            _n_inputs: 2,
            _hash_limit: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
        }
    }

    pub(crate) fn new(ratio: u32, _repetitions: u32) -> Self {
        PedersenInstanceDef {
            ratio,
            _repetitions,
            _element_height: 256,
            _element_bits: 252,
            _n_inputs: 2,
            _hash_limit: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
        }
    }

    pub(crate) fn _cells_per_builtin(&self) -> u32 {
        CELLS_PER_HASH
    }

    pub(crate) fn _range_check_units_per_builtin(&self) -> u32 {
        0
    }
}
