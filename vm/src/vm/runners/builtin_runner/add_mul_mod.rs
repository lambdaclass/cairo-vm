use core::array;

use crate::Felt252;

use crate::types::instance_definitions::mod_instance_def::ModInstanceDef;

//The maximum n value that the function fill_memory accepts.
const FILL_MEMORY_MAX: usize = 100000;

const INPUT_NAMES: [&str; 7] = ["p0", "p1", "p2", "p3", "values_ptr", "offsets_ptr", "n"];

const MEMORY_VAR_NAMES: [&str; 15] = [
    "a_offset", "b_offset", "c_offset", "a0", "a1", "a2", "a3", "b0", "b1", "b2", "b3", "c0", "c1",
    "c2", "c3",
];

const INPUT_CELLS: usize = INPUT_NAMES.len();
const ADDITIONAL_MEMORY_UNITS: usize = MEMORY_VAR_NAMES.len();

#[derive(Debug, Clone)]
pub struct ModBuiltinRunner {
    builtin_type: ModBuiltinType,
    base: usize,
    instance_def: ModInstanceDef,
    included: bool,
    zero_segment_index: usize,
    zero_segment_size: usize,
    // Precomputed powers used for reading and writing values that are represented as n_words words of word_bit_len bits each.
    shift: Felt252,
    shift_powers: Vec<Felt252>,
}

#[derive(Debug, Clone)]
pub enum ModBuiltinType {
    Mul,
    Add,
}

impl ModBuiltinRunner {
    pub fn new_add_mod(instance_def: ModInstanceDef, included: bool) -> Self {
        Self::new(instance_def, included, ModBuiltinType::Add)
    }

    pub fn new_mul_mod(instance_def: ModInstanceDef, included: bool) -> Self {
        Self::new(instance_def, included, ModBuiltinType::Mul)
    }
    fn new(instance_def: ModInstanceDef, included: bool, builtin_type: ModBuiltinType) -> Self {
        let shift = Felt252::TWO.pow(instance_def.word_bit_len);
        let shift_powers = (0..instance_def.n_words).map(|i| shift.pow(i)).collect();
        let zero_segment_size =
            core::cmp::max(instance_def.n_words, instance_def.batch_size * 3) as usize;
        Self {
            builtin_type,
            base: 0,
            instance_def,
            included,
            zero_segment_index: 0,
            zero_segment_size,
            shift,
            shift_powers,
        }
    }
}
