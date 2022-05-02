use std::collections::HashMap;
use crate::vm::relocatable::MaybeRelocatable;

pub struct Memory {
    data:HashMap<MaybeRelocatable, MaybeRelocatable>,
}

impl Memory {
    pub fn get(&self, &addr: &MaybeRelocatable) -> Option<MaybeRelocatable> {
        Some(self.data[addr])
    }
}
