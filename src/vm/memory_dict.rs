use crate::vm::relocatable::MaybeRelocatable;
use std::collections::HashMap;

pub struct Memory {
    data: HashMap<MaybeRelocatable, MaybeRelocatable>,
}

impl Memory {
    pub fn get(&self, addr: &MaybeRelocatable) -> Option<&MaybeRelocatable> {
        return self.data.get(addr);
    }
}
