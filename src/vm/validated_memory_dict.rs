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

pub struct ValidationRule(fn(Memory, MaybeRelocatable, ()) -> Relocatable);
