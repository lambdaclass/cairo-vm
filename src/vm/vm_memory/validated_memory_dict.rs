use crate::types::relocatable::{MaybeRelocatable, Relocatable};
use crate::vm::vm_memory::memory::Memory;
use num_bigint::BigInt;
use std::collections::HashMap;

pub struct ValidatedMemoryDict {
    memory: Memory,
    _validation_rules: HashMap<BigInt, Vec<(ValidationRule, ())>>,
    _validated_addresses: Vec<Relocatable>,
}

impl ValidatedMemoryDict {
    #[allow(dead_code)]
    pub fn new() -> ValidatedMemoryDict {
        ValidatedMemoryDict {
            memory: Memory::new(),
            _validation_rules: HashMap::<BigInt, Vec<(ValidationRule, ())>>::new(),
            _validated_addresses: Vec::<Relocatable>::new(),
        }
    }
    pub fn get(&self, addr: &MaybeRelocatable) -> Option<&MaybeRelocatable> {
        self.memory.get(addr)
    }

    pub fn insert(&mut self, key: &MaybeRelocatable, val: &MaybeRelocatable) {
        self.memory.insert(&key.clone(), &val.clone());
    }
}

impl<const N: usize> From<[(MaybeRelocatable, MaybeRelocatable); N]> for ValidatedMemoryDict {
    fn from(key_val_list: [(MaybeRelocatable, MaybeRelocatable); N]) -> Self {
        ValidatedMemoryDict {
            memory: Memory::from(key_val_list),
            _validation_rules: HashMap::<BigInt, Vec<(ValidationRule, ())>>::new(),
            _validated_addresses: Vec::<Relocatable>::new(),
        }
    }
}

pub struct ValidationRule(fn(Memory, MaybeRelocatable, ()) -> Relocatable);
