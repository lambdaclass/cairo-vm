use serde::Serialize;

use super::LowRatio;

pub(crate) const N_WORDS: usize = 4;

pub(crate) const CELLS_PER_MOD: u32 = 7;

#[derive(Serialize, Debug, PartialEq, Clone)]
pub(crate) struct ModInstanceDef {
    pub(crate) ratio: Option<LowRatio>,
    pub(crate) word_bit_len: u32,
    pub(crate) batch_size: usize,
}

impl ModInstanceDef {
    pub(crate) fn new(ratio: Option<u32>, batch_size: usize, word_bit_len: u32) -> Self {
        ModInstanceDef {
            ratio: ratio.map(LowRatio::new_int),
            word_bit_len,
            batch_size,
        }
    }
}
