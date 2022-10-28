pub(crate) struct DilutedPoolInstanceDef {
    pub(crate) _units_per_step: u32,
    pub(crate) _spacing: u32,
    pub(crate) _n_bits: u32,
}

impl DilutedPoolInstanceDef {
    pub(crate) fn default() -> Self {
        DilutedPoolInstanceDef {
            _units_per_step: 16,
            _spacing: 4,
            _n_bits: 16,
        }
    }

    pub(crate) fn new(_units_per_step: u32, _spacing: u32, _n_bits: u32) -> Self {
        DilutedPoolInstanceDef {
            _units_per_step,
            _spacing,
            _n_bits,
        }
    }
}
