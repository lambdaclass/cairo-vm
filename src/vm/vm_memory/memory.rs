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
        Memory {
            data: Vec::<Vec<MaybeRelocatable>>::new(),
        }
    }
    pub fn insert(&mut self, key: &MaybeRelocatable, val: &MaybeRelocatable) {
        if let MaybeRelocatable::RelocatableValue(relocatable) = key {
            let (i, j) = from_relocatable_to_indexes(relocatable.clone());
            //Check that the memory segment exists
            if self.data.len() < i {
                panic!("Cant insert to a non-allocated memory segment")
            }
            //Check that the element is inserted next to the las one on the segment
            //Forgoing this check would allow data to be inserted in a different index
            if self.data[i].len() < j {
                panic!("Memory must be continuous")
            }
            self.data[i].push(val.clone())
        } else {
            panic!("Memory addresses must be relocatable")
        }
    }
    pub fn get(&self, key: &MaybeRelocatable) -> Option<&MaybeRelocatable> {
        if let MaybeRelocatable::RelocatableValue(relocatable) = key {
            let (i, j) = from_relocatable_to_indexes(relocatable.clone());
            if self.data.len() <= i && self.data[i].len() <= j {
                Some(&self.data[i][j])
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
        let mut memory = Vec::<Vec<MaybeRelocatable>>::new();
        for (key, val) in key_val_list.iter() {
            let (i, j) = from_relocatable_to_indexes(key.clone());
            memory[i][j] = val.clone();
        }
        Memory { data: memory }
    }
}

#[cfg(test)]
mod memory_tests {
    use crate::relocatable;

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
            relocatable!(1, 2),
            MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
        )]);
        assert_eq!(
            matches!(
                mem.get(&MaybeRelocatable::RelocatableValue(relocatable!(1, 2))),
                _val_clone
            ),
            true
        );
    }
}
