#[derive(Debug, PartialEq)]
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

#[cfg(test)]
mod tests {
    use super::DilutedPoolInstanceDef;

    #[test]
    fn test_default() {
        let diluted_pool = DilutedPoolInstanceDef::default();
        assert_eq!(diluted_pool._units_per_step, 16);
        assert_eq!(diluted_pool._spacing, 4);
        assert_eq!(diluted_pool._n_bits, 16);
    }

    #[test]
    fn test_new() {
        let diluted_pool = DilutedPoolInstanceDef::new(1, 1, 1);
        assert_eq!(diluted_pool._units_per_step, 1);
        assert_eq!(diluted_pool._spacing, 1);
        assert_eq!(diluted_pool._n_bits, 1);
    }
}
