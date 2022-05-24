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

    pub fn _validate_existing_memory(&mut self) {
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
