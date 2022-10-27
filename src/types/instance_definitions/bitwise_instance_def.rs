pub(crate) const CELLS_PER_BITWISE: i32 = 2;
pub(crate) const INPUT_CELLS_PER_BITWISE: i32 = 5;

pub(crate) struct BitwiseInstanceDef {
    pub(crate) ratio: i32,
    pub(crate) total_n_bits: i32,
}

impl BitwiseInstanceDef {
    pub(crate) fn default() -> Self {
        BitwiseInstanceDef {
            ratio: 256,
            total_n_bits: 251,
        }
    }

    pub(crate) fn new(ratio: i32) -> Self {
        BitwiseInstanceDef {
            ratio,
            total_n_bits: 251,
        }
    }

    pub(crate) fn cells_per_builtin(&self) -> i32 {
        CELLS_PER_BITWISE
    }

    pub(crate) fn range_check_units_per_builtin(&self) -> i32 {
        0
    }
}
