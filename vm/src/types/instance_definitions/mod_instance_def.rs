use serde::Serialize;

use crate::math_utils::safe_div_u32;

pub(crate) const N_WORDS: usize = 4;

#[derive(Serialize, Debug, PartialEq, Clone)]
pub(crate) struct ModInstanceDef {
    pub(crate) ratio: Option<u32>,
    pub(crate) word_bit_len: u32,
    pub(crate) batch_size: usize,
    // Only used by mod, ignored by add
    pub(crate) bits_per_part: u32,
}

impl ModInstanceDef {
    pub(crate) fn default() -> Self {
        ModInstanceDef {
            ratio: Some(1),
            word_bit_len: 3,
            batch_size: 1,
            bits_per_part: 1,
        }
    }

    pub(crate) fn cells_per_instance(&self) -> u32 {
        (N_WORDS + 3 + self.batch_size * 3 * (N_WORDS + 1)) as u32
    }

    pub(crate) fn range_check_units_per_builtin(&self) -> u32 {
        0
    }

    pub(crate) fn invocation_height(self) -> usize {
        self.batch_size
    }

    // Only used by mod, ignored by add
    pub(crate) fn p_multipliers_n_part(self) -> u32 {
        safe_div_u32(self.word_bit_len, self.bits_per_part).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn get_range_check_units_per_builtin() {
        let builtin_instance = ModInstanceDef::default();
        assert_eq!(builtin_instance.range_check_units_per_builtin(), 0);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn get_cells_per_instance() {
        let builtin_instance = ModInstanceDef::default();
        assert_eq!(builtin_instance.cells_per_instance(), 3);
    }
}
