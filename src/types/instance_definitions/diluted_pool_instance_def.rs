pub(crate) struct DilutedPoolInstanceDef {
    units_per_step: i32,
    spacing: i32,
    n_bits: i32,
}

impl DilutedPoolInstanceDef {
    pub(crate) fn default() -> Self {
        DilutedPoolInstanceDef {
            units_per_step: 16,
            spacing: 4,
            n_bits: 16,
        }
    }

    pub(crate) fn new(units_per_step: i32, spacing: i32, n_bits: i32) -> Self {
        DilutedPoolInstanceDef {
            units_per_step,
            spacing,
            n_bits,
        }
    }
}
