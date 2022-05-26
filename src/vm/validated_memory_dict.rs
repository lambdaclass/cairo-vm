use crate::vm::memory::Memory;
use crate::vm::relocatable::MaybeRelocatable;
use num_bigint::BigInt;
use std::collections::HashMap;

pub struct ValidationRule<'a>(
    pub Box<dyn (Fn(&Memory, MaybeRelocatable) -> MaybeRelocatable) + 'a>,
);
pub struct ValidatedMemoryDict<'a> {
    memory: Memory,
    validation_rules: HashMap<BigInt, Vec<ValidationRule<'a>>>,
    _validated_addresses: Vec<MaybeRelocatable>,
}

impl<'a> ValidatedMemoryDict<'a> {
    #[allow(dead_code)]
    pub fn new() -> ValidatedMemoryDict<'a> {
        ValidatedMemoryDict {
            memory: Memory::new(),
            validation_rules: HashMap::<BigInt, Vec<ValidationRule<'a>>>::new(),
            _validated_addresses: Vec::<MaybeRelocatable>::new(),
        }
    }
    pub fn get(&self, addr: &MaybeRelocatable) -> Option<&MaybeRelocatable> {
        self.memory.get(addr)
    }

    pub fn insert(&mut self, key: &MaybeRelocatable, val: &MaybeRelocatable) {
        self.memory.insert(&key.clone(), &val.clone());
    }

    pub fn add_validation_rule(&mut self, segment_index: BigInt, rule: ValidationRule<'a>) {
        self.validation_rules
            .entry(segment_index)
            .or_insert(Vec::<ValidationRule<'a>>::new())
            .push(rule);
    }

    pub fn validate_existing_memory(&mut self) {
        for (addr, _value) in self.memory.data.iter() {
            if let MaybeRelocatable::RelocatableValue(address) = addr {
                let rules = self.validation_rules.get(&address.segment_index).unwrap();
                for rule in rules {
                    self._validated_addresses
                        .push(rule.0(&self.memory, addr.clone()))
                }
            } else {
                panic!("Cant validate a non-relocatable address");
            }
        }
    }
}

impl<const N: usize> From<[(MaybeRelocatable, MaybeRelocatable); N]> for ValidatedMemoryDict<'_> {
    fn from(key_val_list: [(MaybeRelocatable, MaybeRelocatable); N]) -> Self {
        ValidatedMemoryDict {
            memory: Memory::from(key_val_list),
            validation_rules: HashMap::<BigInt, Vec<ValidationRule<'_>>>::new(),
            _validated_addresses: Vec::<MaybeRelocatable>::new(),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::builtin_runner::{BuiltinRunner, RangeCheckBuiltinRunner};
    use crate::vm::relocatable::Relocatable;
    use crate::{bigint, relocatable};
    use num_traits::FromPrimitive;

    #[test]
    fn add_validation_rule_to_empty_hash() {
        let builtin = RangeCheckBuiltinRunner::new(true, bigint!(8), 8);
        let validation_rule = builtin.validation_rule();
        if let Some(rule) = validation_rule {
            let mut validated_memory = ValidatedMemoryDict::new();
            validated_memory.add_validation_rule(bigint!(1), rule);
            assert_eq!(
                validated_memory
                    .validation_rules
                    .get(&bigint!(1))
                    .unwrap()
                    .len(),
                1
            );
        }
    }

    #[test]
    fn validate_existing_memory_with_range_check_valid_mem() {
        let builtin = RangeCheckBuiltinRunner::new(true, bigint!(8), 8);
        let validation_rule = builtin.validation_rule();
        if let Some(rule) = validation_rule {
            let mut validated_memory = ValidatedMemoryDict::new();
            validated_memory.add_validation_rule(bigint!(1), rule);
            validated_memory.insert(
                &MaybeRelocatable::RelocatableValue(relocatable!(1, 0)),
                &MaybeRelocatable::Int(bigint!(67890)),
            );
            validated_memory.insert(
                &MaybeRelocatable::RelocatableValue(relocatable!(1, 1)),
                &MaybeRelocatable::Int(bigint!(23)),
            );
            validated_memory.insert(
                &MaybeRelocatable::RelocatableValue(relocatable!(1, 2)),
                &MaybeRelocatable::Int(BigInt::from_i64(75847956506).unwrap()),
            );
            validated_memory.validate_existing_memory();
            assert_eq!(validated_memory._validated_addresses.len(), 3);
            assert!(validated_memory
                ._validated_addresses
                .contains(&MaybeRelocatable::RelocatableValue(relocatable!(1, 0))));
            assert!(validated_memory
                ._validated_addresses
                .contains(&MaybeRelocatable::RelocatableValue(relocatable!(1, 1))));
            assert!(validated_memory
                ._validated_addresses
                .contains(&MaybeRelocatable::RelocatableValue(relocatable!(1, 2))));
        } else {
            panic!("Test failed, no validation rule obtained for RangeCheckBuiltin")
        }
    }

    #[test]
    #[should_panic]
    fn validate_existing_memory_with_range_check_invalid_mem() {
        let builtin = RangeCheckBuiltinRunner::new(true, bigint!(8), 8);
        let validation_rule = builtin.validation_rule();
        if let Some(rule) = validation_rule {
            let mut validated_memory = ValidatedMemoryDict::new();
            validated_memory.add_validation_rule(bigint!(1), rule);
            validated_memory.insert(
                &MaybeRelocatable::RelocatableValue(relocatable!(1, 0)),
                &MaybeRelocatable::Int(bigint!(67890)),
            );
            validated_memory.insert(
                &MaybeRelocatable::RelocatableValue(relocatable!(1, 1)),
                &MaybeRelocatable::Int(bigint!(23)),
            );
            validated_memory.insert(
                &MaybeRelocatable::RelocatableValue(relocatable!(1, 2)),
                &MaybeRelocatable::Int(bigint!(-2)),
            );
            validated_memory.validate_existing_memory();
        }
    }
}
