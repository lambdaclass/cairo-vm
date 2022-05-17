use crate::vm::memory::Memory;
use crate::vm::relocatable::MaybeRelocatable;
use crate::vm::relocatable::Relocatable;
use num_bigint::BigInt;
use std::collections::HashMap;

pub struct ValidatedMemoryDict {
    memory: Memory,
    _validation_rules: HashMap<BigInt, Vec<(ValidationRule, ())>>,
    _validated_addresses: Vec<Relocatable>,
}

impl ValidatedMemoryDict {
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

pub struct ValidationRule(fn(Memory, MaybeRelocatable, ()) -> Relocatable);
