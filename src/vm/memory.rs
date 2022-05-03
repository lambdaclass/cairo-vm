use std::collections::HashMap;
use relocatable::MaybeRelocatable

struct Memory {
    data:HashMap<MaybeRelocatable, MaybeRelocatable>
}

impl Memory {
    fn get(&self, addr:&MaybeRelocatable) -> Option<MaybeRelocatable> {
        Some(self.data.get(addr))
    }
}
