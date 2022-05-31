use crate::types::relocatable::MaybeRelocatable;
use crate::vm::vm_memory::memory::Memory;

pub struct ValidatedMemoryDict {
    pub memory: Memory,
    pub validated_addresses: Vec<MaybeRelocatable>,
}

impl ValidatedMemoryDict {
    #[allow(dead_code)]
    pub fn new() -> ValidatedMemoryDict {
        ValidatedMemoryDict {
            memory: Memory::new(),
            validated_addresses: Vec::<MaybeRelocatable>::new(),
        }
    }
    #[allow(dead_code)]
    pub fn get(&self, addr: &MaybeRelocatable) -> Option<&MaybeRelocatable> {
        self.memory.get(addr)
    }

    #[allow(dead_code)]
    pub fn insert(&mut self, key: &MaybeRelocatable, val: &MaybeRelocatable) {
        self.memory.insert(&key.clone(), &val.clone());
    }
}

impl<const N: usize> From<[(MaybeRelocatable, MaybeRelocatable); N]> for ValidatedMemoryDict {
    fn from(key_val_list: [(MaybeRelocatable, MaybeRelocatable); N]) -> Self {
        ValidatedMemoryDict {
            memory: Memory::from(key_val_list),
            validated_addresses: Vec::<MaybeRelocatable>::new(),
        }
    }
}
