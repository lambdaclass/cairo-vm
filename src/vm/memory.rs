mod relocatable;

std::collections::HashMap;

struct Memory {
    data:HashMap<relocatable::MaybeRelocatable, relocatable::MaybeRelocatable>;
}

impl Memory {
    fn get(&self, &addr:relocatable::MaybeRelocatable) -> Option<relocatable::MaybeRelocatable> {
        Some(self.data[addr])
    }
}
