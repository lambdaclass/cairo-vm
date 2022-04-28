mod memory_dict;
mod relocatable;

use num_bigint::BigUint;
use memory_dict::MemoryDict;
use relocatable::RelocatableValue

pub struct ValidatedMemoryDict {
    memory : MemoryDict,
    validation_rules : HashMap<BigUint, Vec<(ValidationRule, ())>>,
    validated_addresses: Vec<RelocatableValue>
}

pub struct ValidationRule(fn(MemoryDict, MaybeRelocatable, ()) -> RelocatableValue)
