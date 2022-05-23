use crate::vm::memory::Memory;
use crate::vm::relocatable::MaybeRelocatable;
use crate::vm::relocatable::Relocatable;
use num_bigint::BigInt;
use std::collections::HashMap;

pub struct ValidatedMemoryDict {
    memory: Memory,
    validation_rules:
        HashMap<BigInt, Vec<Box<dyn (Fn(Memory, MaybeRelocatable) -> MaybeRelocatable)>>>,
    _validated_addresses: Vec<Relocatable>,
}

impl ValidatedMemoryDict {
    #[allow(dead_code)]
    pub fn new() -> ValidatedMemoryDict {
        ValidatedMemoryDict {
            memory: Memory::new(),
            validation_rules: HashMap::<
                BigInt,
                Vec<Box<dyn (Fn(Memory, MaybeRelocatable) -> MaybeRelocatable)>>,
            >::new(),
            _validated_addresses: Vec::<Relocatable>::new(),
        }
    }
    pub fn get(&self, addr: &MaybeRelocatable) -> Option<&MaybeRelocatable> {
        self.memory.get(addr)
    }

    pub fn insert(&mut self, key: &MaybeRelocatable, val: &MaybeRelocatable) {
        self.memory.insert(&key.clone(), &val.clone());
    }

    pub fn add_validation_rule(
        &mut self,
        segment_index: BigInt,
        rule: Box<dyn (Fn(Memory, MaybeRelocatable) -> MaybeRelocatable)>,
    ) {
        self.validation_rules.insert(segment_index, vec![rule]);
    }
}
