use crate::vm::memory::Memory;
use crate::vm::relocatable::MaybeRelocatable;
use crate::vm::relocatable::Relocatable;
use num_bigint::BigInt;
use std::collections::HashMap;

pub struct ValidatedMemoryDict {
    memory: Memory,
    validation_rules: HashMap<BigInt, Vec<(ValidationRule, ())>>,
    validated_addresses: Vec<Relocatable>,
}

impl ValidatedMemoryDict {
    pub fn new() -> ValidatedMemoryDict {
        ValidatedMemoryDict {
            memory: Memory::new(),
            validation_rules: HashMap::<BigInt, Vec<(ValidationRule, ())>>::new(),
            validated_addresses: Vec::<Relocatable>::new(),
        }
    }
}

pub struct ValidationRule(fn(Memory, MaybeRelocatable, ()) -> Relocatable);
