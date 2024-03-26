use serde::Serialize;

pub(crate) const N_WORDS: usize = 4;

#[derive(Serialize, Debug, PartialEq, Clone)]
pub(crate) struct ModInstanceDef {
    pub(crate) ratio: Option<u32>,
    pub(crate) word_bit_len: u32,
    pub(crate) batch_size: usize,
}

impl ModInstanceDef {
    pub(crate) fn default() -> Self {
        ModInstanceDef {
            ratio: Some(32), //TODO: Ask what this should be
            word_bit_len: 3,
            batch_size: 1,
        }
    }

    pub(crate) fn new(ratio: Option<u32>, batch_size: usize) -> Self {
        ModInstanceDef {
            ratio,
            word_bit_len: 3,
            batch_size,
        }
    }
}
