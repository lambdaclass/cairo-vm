pub(crate) const _CELLS_PER_SIGNATURE: u32 = 2;
pub(crate) const _INPUT_CELLS_PER_SIGNATURE: u32 = 2;

#[derive(Debug)]
pub(crate) struct EcdsaInstanceDef {
    pub(crate) _ratio: u32,
    pub(crate) _repetitions: u32,
    pub(crate) _height: u32,
    pub(crate) _n_hash_bits: u32,
}

impl EcdsaInstanceDef {
    pub(crate) fn default() -> Self {
        EcdsaInstanceDef {
            _ratio: 512,
            _repetitions: 1,
            _height: 256,
            _n_hash_bits: 251,
        }
    }

    pub(crate) fn new(ratio: u32) -> Self {
        EcdsaInstanceDef {
            _ratio: ratio,
            _repetitions: 1,
            _height: 256,
            _n_hash_bits: 251,
        }
    }

    pub(crate) fn _cells_per_builtin(&self) -> u32 {
        _CELLS_PER_SIGNATURE
    }

    pub(crate) fn _range_check_units_per_builtin(&self) -> u32 {
        0
    }
}
