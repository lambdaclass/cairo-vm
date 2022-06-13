use crate::types::relocatable::MaybeRelocatable;
use std::collections::HashMap;

#[derive(Clone)]
pub struct Memory {
    pub data: HashMap<MaybeRelocatable, MaybeRelocatable>,
}

impl Memory {
    pub fn new() -> Memory {
        Memory {
            data: HashMap::<MaybeRelocatable, MaybeRelocatable>::new(),
        }
    }

    ///Inserts an MaybeRelocatable value into an address given by a MaybeRelocatable key
    pub fn insert(&mut self, key: &MaybeRelocatable, val: &MaybeRelocatable) {
        self.data.insert(key.clone(), val.clone());
    }

    ///Gets the MaybeRelocatable value corresponding to the address given by a MaybeRelocatable key
    pub fn get(&self, addr: &MaybeRelocatable) -> Option<&MaybeRelocatable> {
        self.data.get(addr)
    }
}
impl<const N: usize> From<[(MaybeRelocatable, MaybeRelocatable); N]> for Memory {
    fn from(key_val_list: [(MaybeRelocatable, MaybeRelocatable); N]) -> Self {
        Memory {
            data: HashMap::from(key_val_list),
        }
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod memory_tests {
    use crate::bigint;

    use super::*;
    use num_bigint::BigInt;
    use num_traits::FromPrimitive;

    #[test]
    fn insert_and_get_succesful() {
        let key = MaybeRelocatable::from((0, 0));
        let val = MaybeRelocatable::from(bigint!(5));
        let mut memory = Memory::new();
        memory.insert(&key, &val);
        assert_eq!(memory.get(&key), Some(&MaybeRelocatable::from(bigint!(5))));
    }

    #[test]
    fn get_non_existant_element() {
        let key = MaybeRelocatable::from((0, 0));
        let memory = Memory::new();
        assert_eq!(memory.get(&key), None);
    }

    #[test]
    fn from_array_test() {
        let mem = Memory::from([(
            MaybeRelocatable::from((0, 1)),
            MaybeRelocatable::Int(BigInt::from(bigint!(5))),
        )]);
        assert_eq!(
            mem.get(&MaybeRelocatable::from((0, 1))),
            Some(&MaybeRelocatable::from(bigint!(5)))
        );
    }
}
