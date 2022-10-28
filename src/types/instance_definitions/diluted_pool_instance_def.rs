pub(crate) struct DilutedPoolInstanceDef {
    pub(crate) units_per_step: u32,
    pub(crate) spacing: u32,
    pub(crate) n_bits: u32,
}

impl DilutedPoolInstanceDef {
    pub(crate) fn default() -> Self {
        DilutedPoolInstanceDef {
            units_per_step: 16,
            spacing: 4,
            n_bits: 16,
        }
    }

    pub(crate) fn new(units_per_step: u32, spacing: u32, n_bits: u32) -> Self {
        DilutedPoolInstanceDef {
            units_per_step,
            spacing,
            n_bits,
        }
    }
}
