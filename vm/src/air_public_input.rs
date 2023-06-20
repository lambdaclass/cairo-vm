use std::collections::HashMap;

use felt::Felt252;

use crate::types::layout::CairoLayout;

pub struct PublicMemoryEntry {
    address: usize,
    value: Felt252,
    page: usize,
}

pub struct PublicInput<'a> {
    layout: &'a str,
    layout_params: Option<CairoLayout>,
    rc_min: Felt252,
    rc_max: Felt252,
    n_steps: Felt252,
    memory_segments: HashMap<&'a str>,
}
