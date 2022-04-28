mod relocatable;

use num_bigint::BigUint;
use std::collections::HashMap

pub struct MemoryDict {
    data: HashMap,
    frozen: bool,
    relocation_rules: HashMap<BigUint, RelocatableValue>
};

impl MemoryDict {
    pub fn index(&self, addr: relocatable::MaybeRelocatable) -> relocatable::MaybeRelocatable {
        // Error checking
        // Return
    }
}
