use num_bigint::{BigInt, Sign};

const CELLS_PER_EC_OP: i32 = 7;
const INPUT_CELLS_PER_EC_OP: i32 = 5;

pub(crate) struct EcOpInstanceDef {
    ratio: i32,
    scalar_height: i32,
    scalar_bits: i32,
    scalar_limit: BigInt,
}

impl EcOpInstanceDef {
    pub(crate) fn default() -> Self {
        EcOpInstanceDef {
            ratio: 256,
            scalar_height: 256,
            scalar_bits: 252,
            scalar_limit: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
        }
    }

    pub(crate) fn new(ratio: i32) -> Self {
        EcOpInstanceDef {
            ratio,
            scalar_height: 256,
            scalar_bits: 252,
            scalar_limit: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
        }
    }

    pub(crate) fn cells_per_builtin(&self) -> i32 {
        CELLS_PER_EC_OP
    }

    pub(crate) fn range_check_units_per_builtin(&self) -> i32 {
        0
    }
}
