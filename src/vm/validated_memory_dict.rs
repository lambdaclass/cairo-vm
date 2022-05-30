use crate::vm::memory::Memory;
use crate::vm::relocatable::MaybeRelocatable;

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
            validated_addresses: Vec::<MaybeRelocatable>::new(),
        }
    }
}
#[cfg(test)]
mod tests {
    /* use super::*;
    use crate::vm::relocatable::Relocatable;
    use crate::{bigint, relocatable};

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
    }*/
}
