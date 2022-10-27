const CELLS_PER_RANGE_SIGNATURE: i32 = 2;

pub(crate) struct EcdsaInstanceDef {
    ratio: i32,
    repetitions: i32,
    height: i32,
    n_hash_bits: i32,
}

impl EcdsaInstanceDef {
    pub(crate) fn default() -> Self {
        EcdsaInstanceDef {
            ratio: 512,
            repetitions: 1,
            height: 256,
            n_hash_bits: 251,
        }
    }

    pub(crate) fn new(ratio: i32) -> Self {
        EcdsaInstanceDef {
            ratio,
            repetitions: 1,
            height: 256,
            n_hash_bits: 251,
        }
    }

    pub(crate) fn cells_per_builtin(&self) -> i32 {
        CELLS_PER_RANGE_SIGNATURE
    }

    pub(crate) fn range_check_units_per_builtin(&self) -> i32 {
        0
    }
}
