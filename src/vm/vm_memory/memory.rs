use crate::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    utils::from_relocatable_to_indexes,
};
use std::convert::From;

#[derive(Clone)]
pub struct Memory {
    pub data: Vec<Vec<MaybeRelocatable>>,
}

impl Memory {
    pub fn new() -> Memory {
        Memory { data: Vec::new() }
    }
    pub fn insert(&mut self, key: &MaybeRelocatable, val: &MaybeRelocatable) {
        if let &MaybeRelocatable::RelocatableValue(relocatable) = key {
            let (i, j) = from_relocatable_to_indexes(relocatable);
            self.data[i][j] = val.clone()
        } else {
            panic!("Memory addresses must be relocatable")
        }
    }
    pub fn get(&self, key: &MaybeRelocatable) -> Option<MaybeRelocatable> {
        if let &MaybeRelocatable::RelocatableValue(relocatable) = key {
            let (i, j) = from_relocatable_to_indexes(relocatable);
            if self.data.len() <= i && self.data[i].len() <= j {
                Some(self.data[i][j])
            } else {
                None
            }
        } else {
            panic!("Memory addresses must be relocatable")
        }
    }
}

impl<const N: usize> From<[(Relocatable, MaybeRelocatable); N]> for Memory {
    fn from(key_val_list: [(Relocatable, MaybeRelocatable); N]) -> Self {
        let memory = Vec::<Vec<MaybeRelocatable>>::new();
        for (key, val) in key_val_list.iter() {
            let (i, j) = from_relocatable_to_indexes(key.clone());
            memory[i][j] = val.clone();
        }
        Memory { data: memory }
    }
}

#[cfg(test)]
mod memory_tests {
    use super::*;
    use num_bigint::BigInt;
    use num_traits::FromPrimitive;

    #[test]
    fn get_test() {
        let key = MaybeRelocatable::Int(BigInt::from_i32(2).unwrap());
        let val = MaybeRelocatable::Int(BigInt::from_i32(5).unwrap());
        let _val_clone = val.clone();
        let mut mem = Memory::new();
        mem.insert(&key, &val);
        assert_eq!(matches!(mem.get(&key), _val_clone), true);
    }

    #[test]
    fn from_array_test() {
        let mem = Memory::from([(
            MaybeRelocatable::Int(BigInt::from_i32(2).unwrap()),
            MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
        )]);
        assert_eq!(
            matches!(
                mem.get(&MaybeRelocatable::Int(BigInt::from_i32(2).unwrap())),
                _val_clone
            ),
            true
        );
    }
}
