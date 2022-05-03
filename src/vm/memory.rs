use std::collections::HashMap;
use crate::vm::relocatable::MaybeRelocatable;

struct Memory {
    data:HashMap<MaybeRelocatable, MaybeRelocatable>
}

impl Memory {
    fn get(&self, addr:&MaybeRelocatable) -> Option<&MaybeRelocatable> {
        return self.data.get(&addr)
    }
}
