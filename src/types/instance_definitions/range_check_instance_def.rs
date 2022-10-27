pub(crate) const CELLS_PER_RANGE_CHECK: i32 = 1;

pub(crate) struct RangeCheckInstanceDef {
    pub(crate) ratio: i32,
    pub(crate) n_parts: i32,
}

impl RangeCheckInstanceDef {
    pub(crate) fn default() -> Self {
        RangeCheckInstanceDef {
            ratio: 8,
            n_parts: 8,
        }
    }

    pub(crate) fn new(ratio: i32, n_parts: i32) -> Self {
        RangeCheckInstanceDef { ratio, n_parts }
    }

    pub(crate) fn cells_per_builtin(&self) -> i32 {
        CELLS_PER_RANGE_CHECK
    }

    pub(crate) fn range_check_units_per_builtin(&self) -> i32 {
        self.n_parts
    }
}
