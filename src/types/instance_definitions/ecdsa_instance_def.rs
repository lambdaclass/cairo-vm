pub(crate) const CELLS_PER_SIGNATURE: u32 = 2;
pub(crate) const INPUT_CELLS_PER_SIGNATURE: u32 = 2;

pub(crate) struct EcdsaInstanceDef {
    pub(crate) ratio: u32,
    pub(crate) repetitions: u32,
    pub(crate) height: u32,
    pub(crate) n_hash_bits: u32,
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

    pub(crate) fn new(ratio: u32) -> Self {
        EcdsaInstanceDef {
            ratio,
            repetitions: 1,
            height: 256,
            n_hash_bits: 251,
        }
    }

    pub(crate) fn cells_per_builtin(&self) -> u32 {
        CELLS_PER_SIGNATURE
    }

    pub(crate) fn range_check_units_per_builtin(&self) -> u32 {
        0
    }
}
