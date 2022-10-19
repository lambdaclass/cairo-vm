use std::collections::{HashMap, HashSet};

use crate::types::relocatable::Relocatable;
use crate::vm::errors::memory_errors::MemoryError;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::{types::relocatable::MaybeRelocatable, utils::from_relocatable_to_indexes};
use num_bigint::BigInt;

pub struct ValidationRule(
    pub Box<dyn Fn(&Memory, &MaybeRelocatable) -> Result<Vec<MaybeRelocatable>, MemoryError>>,
);
pub struct Memory {
    pub data: Vec<Vec<Option<MaybeRelocatable>>>,
    pub validated_addresses: HashSet<MaybeRelocatable>,
    pub validation_rules: HashMap<usize, ValidationRule>,
}

impl Memory {
    pub fn new() -> Memory {
        Memory {
            data: Vec::<Vec<Option<MaybeRelocatable>>>::new(),
            validated_addresses: HashSet::<MaybeRelocatable>::new(),
            validation_rules: HashMap::new(),
        }
    }
    ///Inserts an MaybeRelocatable value into an address given by a MaybeRelocatable::Relocatable
    /// Will panic if the segment index given by the address corresponds to a non-allocated segment
    /// If the address isnt contiguous with previously inserted data, memory gaps will be represented by inserting None values
    pub fn insert<'a, K: 'a, V: 'a>(&mut self, key: &'a K, val: &'a V) -> Result<(), MemoryError>
    where
        Relocatable: TryFrom<&'a K>,
        MaybeRelocatable: From<&'a K>,
        MaybeRelocatable: From<&'a V>,
    {
        let relocatable: Relocatable = key
            .try_into()
            .map_err(|_| MemoryError::AddressNotRelocatable)?;
        let val = MaybeRelocatable::from(val);
        let (value_index, value_offset) = from_relocatable_to_indexes(relocatable.clone());
        let data_len = self.data.len();
        let segment = self
            .data
            .get_mut(value_index)
            .ok_or(MemoryError::UnallocatedSegment(value_index, data_len))?;
        //Check if the element is inserted next to the last one on the segment
        //Forgoing this check would allow data to be inserted in a different index
        if segment.len() <= value_offset {
            segment.resize(value_offset + 1, None);
        }
        // At this point there's *something* in there
        match segment[value_offset] {
            None => segment[value_offset] = Some(val),
            Some(ref current_value) => {
                if current_value != &val {
                    //Existing memory cannot be changed
                    return Err(MemoryError::InconsistentMemory(
                        relocatable.into(),
                        current_value.to_owned(),
                        val,
                    ));
                }
            }
        };
        self.validate_memory_cell(&MaybeRelocatable::from(key))
    }

    pub fn get<'a, K: 'a>(&self, key: &'a K) -> Result<Option<&MaybeRelocatable>, MemoryError>
    where
        Relocatable: TryFrom<&'a K>,
    {
        let relocatable: Relocatable = key
            .try_into()
            .map_err(|_| MemoryError::AddressNotRelocatable)?;
        let (i, j) = from_relocatable_to_indexes(relocatable);
        if self.data.len() > i && self.data[i].len() > j {
            if let Some(ref element) = self.data[i][j] {
                return Ok(Some(element));
            }
        }
        Ok(None)
    }

    //Gets the value from memory address.
    //If the value is an MaybeRelocatable::Int(Bigint) return &Bigint
    //else raises Err
    pub fn get_integer(&self, key: &Relocatable) -> Result<&BigInt, VirtualMachineError> {
        if let Some(MaybeRelocatable::Int(int)) =
            self.get(key).map_err(VirtualMachineError::MemoryError)?
        {
            Ok(int)
        } else {
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from(key),
            ))
        }
    }

    pub fn get_relocatable(&self, key: &Relocatable) -> Result<&Relocatable, VirtualMachineError> {
        match self.get(key) {
            Ok(Some(MaybeRelocatable::RelocatableValue(rel))) => Ok(rel),
            Ok(_) => Err(VirtualMachineError::ExpectedRelocatable(
                MaybeRelocatable::from(key),
            )),
            Err(memory_error) => Err(VirtualMachineError::MemoryError(memory_error)),
        }
    }

    pub fn insert_value<T: Into<MaybeRelocatable>>(
        &mut self,
        key: &Relocatable,
        val: T,
    ) -> Result<(), VirtualMachineError> {
        self.insert(key, &val.into())
            .map_err(VirtualMachineError::MemoryError)
    }

    pub fn add_validation_rule(&mut self, segment_index: usize, rule: ValidationRule) {
        self.validation_rules.insert(segment_index, rule);
    }

    fn validate_memory_cell(&mut self, address: &MaybeRelocatable) -> Result<(), MemoryError> {
        if let &MaybeRelocatable::RelocatableValue(ref rel_addr) = address {
            if !self.validated_addresses.contains(address) {
                for (index, validation_rule) in self.validation_rules.iter() {
                    if &rel_addr.segment_index == index {
                        self.validated_addresses
                            .extend(validation_rule.0(self, address)?);
                    }
                }
            }
            Ok(())
        } else {
            Err(MemoryError::AddressNotRelocatable)
        }
    }
    ///Applies validation_rules to the current memory
    //Should be called during initialization, as None values will raise a FoundNonInt error
    pub fn validate_existing_memory(&mut self) -> Result<(), MemoryError> {
        for i in 0..self.data.len() {
            for j in 0..self.data[i].len() {
                self.validate_memory_cell(&MaybeRelocatable::from((i, j)))?;
            }
        }
        Ok(())
    }

    pub fn get_range(
        &self,
        addr: &MaybeRelocatable,
        size: usize,
    ) -> Result<Vec<Option<&MaybeRelocatable>>, MemoryError> {
        let mut values = Vec::new();

        for i in 0..size {
            values.push(self.get(&addr.add_usize_mod(i, None))?);
        }

        Ok(values)
    }

    pub fn get_integer_range(
        &self,
        addr: &Relocatable,
        size: usize,
    ) -> Result<Vec<&BigInt>, VirtualMachineError> {
        let mut values = Vec::new();

        for i in 0..size {
            values.push(self.get_integer(&(addr + i))?);
        }

        Ok(values)
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod memory_tests {
    use crate::{
        bigint,
        vm::{
            runners::builtin_runner::{BuiltinRunner, RangeCheckBuiltinRunner},
            vm_memory::memory_segments::MemorySegmentManager,
        },
    };

    use super::*;
    use num_bigint::BigInt;

    pub fn memory_from(
        key_val_list: Vec<(MaybeRelocatable, MaybeRelocatable)>,
        num_segements: usize,
    ) -> Result<Memory, MemoryError> {
        let mut memory = Memory::new();
        for _ in 0..num_segements {
            memory.data.push(Vec::new());
        }
        for (key, val) in key_val_list.iter() {
            memory.insert(key, val)?;
        }
        Ok(memory)
    }

    #[test]
    fn insert_and_get_succesful() {
        let key = MaybeRelocatable::from((0, 0));
        let val = MaybeRelocatable::from(bigint!(5));
        let mut memory = Memory::new();
        memory.data.push(Vec::new());
        memory.insert(&key, &val).unwrap();
        assert_eq!(
            memory.get(&key).unwrap(),
            Some(&MaybeRelocatable::from(bigint!(5)))
        );
    }

    #[test]
    fn get_non_allocated_memory() {
        let key = MaybeRelocatable::from((0, 0));
        let memory = Memory::new();
        assert_eq!(memory.get(&key).unwrap(), None);
    }

    #[test]
    fn get_non_existant_element() {
        let key = MaybeRelocatable::from((0, 0));
        let memory = Memory::new();
        assert_eq!(memory.get(&key).unwrap(), None);
    }

    #[test]
    fn get_non_relocatable_key() {
        let key = MaybeRelocatable::from(bigint!(0));
        let memory = Memory::new();
        let error = memory.get(&key);
        assert_eq!(error, Err(MemoryError::AddressNotRelocatable));
        assert_eq!(
            error.unwrap_err().to_string(),
            "Memory addresses must be relocatable"
        );
    }

    #[test]
    fn insert_non_allocated_memory() {
        let key = MaybeRelocatable::from((0, 0));
        let val = MaybeRelocatable::from(bigint!(5));
        let mut memory = Memory::new();
        let error = memory.insert(&key, &val);
        assert_eq!(error, Err(MemoryError::UnallocatedSegment(0, 0)));
        assert_eq!(
            error.unwrap_err().to_string(),
            "Can't insert into segment #0; memory only has 0 segment"
        );
    }

    #[test]
    fn insert_inconsistent_memory() {
        let key = MaybeRelocatable::from((0, 0));
        let val_a = MaybeRelocatable::from(bigint!(5));
        let val_b = MaybeRelocatable::from(bigint!(6));
        let mut memory = Memory::new();
        memory.data.push(Vec::new());
        memory
            .insert(&key, &val_a)
            .expect("Unexpected memory insert fail");
        let error = memory.insert(&key, &val_b);
        assert_eq!(
            error,
            Err(MemoryError::InconsistentMemory(key, val_a, val_b))
        );
        assert_eq!(error.unwrap_err().to_string(), "Inconsistent memory assignment at address RelocatableValue(Relocatable { segment_index: 0, offset: 0 }). Int(5) != Int(6)");
    }

    #[test]
    fn insert_address_not_relocatable() {
        let key = MaybeRelocatable::from(bigint!(5));
        let val = MaybeRelocatable::from(bigint!(5));
        let mut memory = Memory::new();
        let error = memory.insert(&key, &val);
        assert_eq!(error, Err(MemoryError::AddressNotRelocatable));
        assert_eq!(
            error.unwrap_err().to_string(),
            "Memory addresses must be relocatable"
        );
    }

    #[test]
    fn insert_non_contiguous_element() {
        let key_a = MaybeRelocatable::from((0, 0));
        let key_b = MaybeRelocatable::from((0, 2));
        let val = MaybeRelocatable::from(bigint!(5));
        let mut memory = Memory::new();
        memory.data.push(Vec::new());
        memory.insert(&key_a, &val).unwrap();
        memory.insert(&key_b, &val).unwrap();
        assert_eq!(memory.get(&key_b).unwrap(), Some(&val));
    }

    #[test]
    fn insert_non_contiguous_element_memory_gaps_none() {
        let key_a = MaybeRelocatable::from((0, 0));
        let key_b = MaybeRelocatable::from((0, 5));
        let val = MaybeRelocatable::from(bigint!(5));
        let mut memory = Memory::new();
        memory.data.push(Vec::new());
        memory.insert(&key_a, &val).unwrap();
        memory.insert(&key_b, &val).unwrap();
        assert_eq!(memory.get(&key_b).unwrap(), Some(&val));
        assert_eq!(memory.get(&MaybeRelocatable::from((0, 1))).unwrap(), None);
        assert_eq!(memory.get(&MaybeRelocatable::from((0, 2))).unwrap(), None);
        assert_eq!(memory.get(&MaybeRelocatable::from((0, 3))).unwrap(), None);
        assert_eq!(memory.get(&MaybeRelocatable::from((0, 4))).unwrap(), None);
    }

    #[test]
    fn from_array_test() {
        let mem = memory_from(
            vec![(
                MaybeRelocatable::from((1, 0)),
                MaybeRelocatable::from(bigint!(5)),
            )],
            2,
        )
        .unwrap();
        assert_eq!(
            matches!(mem.get(&MaybeRelocatable::from((1, 0))), _val_clone),
            true
        );
    }

    #[test]
    fn validate_existing_memory_for_range_check_within_bounds() {
        let mut builtin = RangeCheckBuiltinRunner::new(bigint!(8), 8);
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        builtin.initialize_segments(&mut segments, &mut memory);
        builtin.add_validation_rule(&mut memory);
        for _ in 0..3 {
            segments.add(&mut memory);
        }

        memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(45)),
            )
            .unwrap();
        memory.validate_existing_memory().unwrap();
        assert!(memory
            .validated_addresses
            .contains(&MaybeRelocatable::from((0, 0))));
    }

    #[test]
    fn validate_existing_memory_for_range_check_outside_bounds() {
        let mut builtin = RangeCheckBuiltinRunner::new(bigint!(8), 8);
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        segments.add(&mut memory);
        builtin.initialize_segments(&mut segments, &mut memory);
        memory
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(bigint!(-10)),
            )
            .unwrap();
        builtin.add_validation_rule(&mut memory);
        let error = memory.validate_existing_memory();
        assert_eq!(error, Err(MemoryError::NumOutOfBounds));
        assert_eq!(
            error.unwrap_err().to_string(),
            "Range-check validation failed, number is out of valid range"
        );
    }

    #[test]

    fn validate_existing_memory_for_range_check_relocatable_value() {
        let mut builtin = RangeCheckBuiltinRunner::new(bigint!(8), 8);
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        segments.add(&mut memory);
        builtin.initialize_segments(&mut segments, &mut memory);
        memory
            .insert(
                &MaybeRelocatable::from((1, 7)),
                &MaybeRelocatable::from((1, 4)),
            )
            .unwrap();
        builtin.add_validation_rule(&mut memory);
        let error = memory.validate_existing_memory();
        assert_eq!(error, Err(MemoryError::FoundNonInt));
        assert_eq!(
            error.unwrap_err().to_string(),
            "Range-check validation failed, encountered non-int value"
        );
    }

    #[test]
    fn validate_existing_memory_for_range_check_out_of_bounds_diff_segment() {
        let mut builtin = RangeCheckBuiltinRunner::new(bigint!(8), 8);
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        segments.add(&mut memory);
        builtin.initialize_segments(&mut segments, &mut memory);
        memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(-45)),
            )
            .unwrap();
        builtin.add_validation_rule(&mut memory);
        assert_eq!(memory.validate_existing_memory(), Ok(()));
    }

    #[test]
    fn get_integer_valid() {
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        segments.add(&mut memory);
        memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .unwrap();
        assert_eq!(
            memory.get_integer(&Relocatable::from((0, 0))),
            Ok(&bigint!(10))
        );
    }

    #[test]
    fn get_integer_invalid_expected_integer() {
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        segments.add(&mut memory);
        memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((0, 10)),
            )
            .unwrap();
        assert_eq!(
            memory.get_integer(&Relocatable::from((0, 0))),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn default_memory() {
        let mem: Memory = Default::default();
        assert_eq!(mem.data.len(), 0);
    }
}
