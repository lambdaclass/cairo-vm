use num_bigint::BigUint;
use crate::vm::memory_dict::Memory;
use crate::vm::relocatable::Relocatable;
use std::collections::HashMap;
use crate::vm::relocatable::MaybeRelocatable;

pub struct ValidatedMemoryDict {
    memory : Memory,
    validation_rules : HashMap<BigUint, Vec<(ValidationRule, ())>>,
    validated_addresses: Vec<Relocatable>
}

pub struct ValidationRule(fn(Memory, MaybeRelocatable, ()) -> Relocatable);
