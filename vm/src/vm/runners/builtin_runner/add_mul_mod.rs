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
}

#[derive(Debug, Clone)]
pub enum ModBuiltinType {
    Mul,
    Add,
}

impl ModBuiltinRunner {
    fn new_add_mod(instance_def: ModInstanceDef, included: bool) -> Self {
        Self {
            builtin_type: ModBuiltinType::Add,
            base: 0,
            instance_def,
            included,
        }
    }

    fn new_mul_mod(instance_def: ModInstanceDef, included: bool) -> Self {
        Self {
            builtin_type: ModBuiltinType::Mul,
            base: 0,
            instance_def,
            included,
        }
    }
}
