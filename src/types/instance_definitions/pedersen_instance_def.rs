use crate::utils::CAIRO_PRIME;
use big_num::BigNum;

pub(crate) const CELLS_PER_HASH: u32 = 3;
pub(crate) const INPUT_CELLS_PER_HASH: u32 = 2;

#[derive(Debug, PartialEq)]
pub(crate) struct PedersenInstanceDef {
    pub(crate) ratio: u32,
    pub(crate) _repetitions: u32,
    pub(crate) _element_height: u32,
    pub(crate) _element_bits: u32,
    pub(crate) _n_inputs: u32,
    pub(crate) _hash_limit: BigNum,
}

impl PedersenInstanceDef {
    pub(crate) fn default() -> Self {
        PedersenInstanceDef {
            ratio: 8,
            _repetitions: 4,
            _element_height: 256,
            _element_bits: 252,
            _n_inputs: 2,
            _hash_limit: CAIRO_PRIME.clone(),
        }
    }

    pub(crate) fn new(ratio: u32, _repetitions: u32) -> Self {
        PedersenInstanceDef {
            ratio,
            _repetitions,
            _element_height: 256,
            _element_bits: 252,
            _n_inputs: 2,
            _hash_limit: CAIRO_PRIME.clone(),
        }
    }

    pub(crate) fn _cells_per_builtin(&self) -> u32 {
        CELLS_PER_HASH
    }

    pub(crate) fn _range_check_units_per_builtin(&self) -> u32 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_range_check_units_per_builtin() {
        let builtin_instance = PedersenInstanceDef::default();
        assert_eq!(builtin_instance._range_check_units_per_builtin(), 0);
    }

    #[test]
    fn get_cells_per_builtin() {
        let builtin_instance = PedersenInstanceDef::default();
        assert_eq!(builtin_instance._cells_per_builtin(), 3);
    }

    #[test]
    fn test_new() {
        let builtin_instance = PedersenInstanceDef {
            ratio: 10,
            _repetitions: 2,
            _element_height: 256,
            _element_bits: 252,
            _n_inputs: 2,
            _hash_limit: CAIRO_PRIME.clone(),
        };
        assert_eq!(PedersenInstanceDef::new(10, 2), builtin_instance);
    }

    #[test]
    fn test_default() {
        let builtin_instance = PedersenInstanceDef {
            ratio: 8,
            _repetitions: 4,
            _element_height: 256,
            _element_bits: 252,
            _n_inputs: 2,
            _hash_limit: CAIRO_PRIME.clone(),
        };
        assert_eq!(PedersenInstanceDef::default(), builtin_instance);
    }
}
