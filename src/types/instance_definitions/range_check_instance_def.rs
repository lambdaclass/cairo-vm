pub(crate) const CELLS_PER_RANGE_CHECK: u32 = 1;

#[derive(Debug)]
pub(crate) struct RangeCheckInstanceDef {
    pub(crate) ratio: u32,
    pub(crate) n_parts: u32,
}

impl RangeCheckInstanceDef {
    pub(crate) fn default() -> Self {
        RangeCheckInstanceDef {
            ratio: 8,
            n_parts: 8,
        }
    }

    pub(crate) fn new(ratio: u32, n_parts: u32) -> Self {
        RangeCheckInstanceDef { ratio, n_parts }
    }

    pub(crate) fn _cells_per_builtin(&self) -> u32 {
        CELLS_PER_RANGE_CHECK
    }

    pub(crate) fn _range_check_units_per_builtin(&self) -> u32 {
        self.n_parts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_range_check_units_per_builtin() {
        let builtin_instance = RangeCheckInstanceDef::default();
        assert_eq!(builtin_instance._range_check_units_per_builtin(), 8);
    }

    #[test]
    fn get_cells_per_builtin() {
        let builtin_instance = RangeCheckInstanceDef::default();
        assert_eq!(builtin_instance._cells_per_builtin(), 1);
    }
}
