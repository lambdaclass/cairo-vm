use num_bigint::{BigInt, Sign};

pub(crate) const CELLS_PER_EC_OP: u32 = 7;
pub(crate) const INPUT_CELLS_PER_EC_OP: u32 = 5;

#[derive(Clone, Debug)]
pub(crate) struct EcOpInstanceDef {
    pub(crate) ratio: u32,
    pub(crate) scalar_height: u32,
    pub(crate) _scalar_bits: u32,
    pub(crate) scalar_limit: BigInt,
}

impl EcOpInstanceDef {
    pub(crate) fn default() -> Self {
        EcOpInstanceDef {
            ratio: 256,
            scalar_height: 256,
            _scalar_bits: 252,
            scalar_limit: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
        }
    }

    pub(crate) fn new(ratio: u32) -> Self {
        EcOpInstanceDef {
            ratio,
            scalar_height: 256,
            _scalar_bits: 252,
            scalar_limit: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
        }
    }

    pub(crate) fn _cells_per_builtin(&self) -> u32 {
        CELLS_PER_EC_OP
    }

    pub(crate) fn _range_check_units_per_builtin(&self) -> u32 {
        0
    }
}
