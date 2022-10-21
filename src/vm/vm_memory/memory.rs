use std::borrow::Cow;
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
    pub temp_data: Vec<Vec<Option<MaybeRelocatable>>>,
    pub relocation_rules: HashMap<usize, Relocatable>,
    pub validated_addresses: HashSet<MaybeRelocatable>,
    pub validation_rules: HashMap<usize, ValidationRule>,
}

impl Memory {
    pub fn new() -> Memory {
        Memory {
            data: Vec::<Vec<Option<MaybeRelocatable>>>::new(),
            temp_data: Vec::<Vec<Option<MaybeRelocatable>>>::new(),
            relocation_rules: HashMap::new(),
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
        let (value_index, value_offset) = from_relocatable_to_indexes(&relocatable);

        let data = if relocatable.segment_index.is_negative() {
            &mut self.temp_data
        } else {
            &mut self.data
        };

        let data_len = data.len();
        let segment = data
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

    /// Retrieve a value from memory (either normal or temporary) and apply relocation rules
    pub(crate) fn get<'a, 'b: 'a, K: 'a>(
        &'b self,
        key: &'a K,
    ) -> Result<Option<Cow<MaybeRelocatable>>, MemoryError>
    where
        Relocatable: TryFrom<&'a K>,
    {
        let relocatable: Relocatable = key
            .try_into()
            .map_err(|_| MemoryError::AddressNotRelocatable)?;

        let data = if relocatable.segment_index.is_negative() {
            &self.temp_data
        } else {
            &self.data
        };
        let (i, j) = from_relocatable_to_indexes(&relocatable);
        if data.len() > i && data[i].len() > j {
            if let Some(ref element) = data[i][j] {
                return self.relocate_value(Some(Cow::Borrowed(element)));
            }
        }

        self.relocate_value(None)
    }

    /// Relocate a value according to the relocation rules.
    pub fn relocate_value<'a>(
        &self,
        value: Option<Cow<'a, MaybeRelocatable>>,
    ) -> Result<Option<Cow<'a, MaybeRelocatable>>, MemoryError> {
        let value_relocation = match value {
            Some(Cow::Owned(MaybeRelocatable::RelocatableValue(ref x)))
            | Some(Cow::Borrowed(MaybeRelocatable::RelocatableValue(ref x))) => x,
            value => return Ok(value),
        };

        let segment_idx = value_relocation.segment_index;
        if segment_idx >= 0 {
            return Ok(value);
        }

        let relocation = match self.relocation_rules.get(&(-segment_idx as usize)) {
            Some(x) => x,
            None => return Ok(value),
        };

        Ok(self
            .relocate_value(Some(Cow::Owned(relocation.into())))?
            .map(|x| Cow::Owned(x.add_usize_mod(value_relocation.offset, None))))
    }

    /// Add a new relocation rule.
    ///
    /// Will return an error if any of the following conditions are not met:
    ///   - Source address's segment must be negative (temporary).
    ///   - Source address's offset must be zero.
    ///   - There shouldn't already be relocation at the source segment.
    pub fn add_relocation_rule(
        &mut self,
        src_ptr: Relocatable,
        dst_ptr: Relocatable,
    ) -> Result<(), MemoryError> {
        if src_ptr.segment_index >= 0 {
            return Err(MemoryError::AddressNotInTemporarySegment(
                src_ptr.segment_index,
            ));
        }
        if src_ptr.offset != 0 {
            return Err(MemoryError::NonZeroOffset(src_ptr.offset));
        }

        let segment_index = -src_ptr.segment_index as usize;
        if self.relocation_rules.contains_key(&segment_index) {
            return Err(MemoryError::DuplicatedRelocation(src_ptr.segment_index));
        }

        self.relocation_rules.insert(segment_index, dst_ptr);
        Ok(())
    }

    //Gets the value from memory address.
    //If the value is an MaybeRelocatable::Int(Bigint) return &Bigint
    //else raises Err
    pub fn get_integer(&self, key: &Relocatable) -> Result<Cow<BigInt>, VirtualMachineError> {
        match self.get(key).map_err(VirtualMachineError::MemoryError)? {
            Some(Cow::Borrowed(MaybeRelocatable::Int(int))) => Ok(Cow::Borrowed(int)),
            Some(Cow::Owned(MaybeRelocatable::Int(int))) => Ok(Cow::Owned(int)),
            _ => Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from(key),
            )),
        }
    }

    pub fn get_relocatable(
        &self,
        key: &Relocatable,
    ) -> Result<Cow<Relocatable>, VirtualMachineError> {
        match self.get(key).map_err(VirtualMachineError::MemoryError)? {
            Some(Cow::Borrowed(MaybeRelocatable::RelocatableValue(rel))) => Ok(Cow::Borrowed(rel)),
            Some(Cow::Owned(MaybeRelocatable::RelocatableValue(rel))) => Ok(Cow::Owned(rel)),
            _ => Err(VirtualMachineError::ExpectedRelocatable(
                MaybeRelocatable::from(key),
            )),
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
                    if rel_addr.segment_index == *index as isize {
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
                self.validate_memory_cell(&MaybeRelocatable::from((i as isize, j)))?;
            }
        }
        Ok(())
    }

    pub fn get_range(
        &self,
        addr: &MaybeRelocatable,
        size: usize,
    ) -> Result<Vec<Option<Cow<MaybeRelocatable>>>, MemoryError> {
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
    ) -> Result<Vec<Cow<BigInt>>, VirtualMachineError> {
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
        bigint, bigint_str,
        utils::test_utils::mayberelocatable,
        vm::{
            runners::builtin_runner::{
                BuiltinRunner, RangeCheckBuiltinRunner, SignatureBuiltinRunner,
            },
            vm_memory::memory_segments::MemorySegmentManager,
        },
    };

    use super::*;
    use k256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
    use num_bigint::{BigInt, Sign};
    use rand_core::OsRng;

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
            memory.get(&key).unwrap().unwrap().as_ref(),
            &MaybeRelocatable::from(bigint!(5))
        );
    }

    #[test]
    fn get_valuef_from_temp_segment() {
        let mut memory = Memory::new();
        memory.temp_data = vec![vec![None, None, Some(mayberelocatable!(8))]];
        assert_eq!(
            memory
                .get(&mayberelocatable!(-1, 2))
                .unwrap()
                .unwrap()
                .as_ref(),
            &mayberelocatable!(8),
        );
    }

    #[test]
    fn insert_value_in_temp_segment() {
        let key = MaybeRelocatable::from((-1, 3));
        let val = MaybeRelocatable::from(bigint!(8));
        let mut memory = Memory::new();
        memory.temp_data.push(Vec::new());
        memory.insert(&key, &val).unwrap();
        assert_eq!(
            memory.temp_data[0][3],
            Some(MaybeRelocatable::from(bigint!(8)))
        );
    }

    #[test]
    fn insert_and_get_from_temp_segment_succesful() {
        let key = MaybeRelocatable::from((-1, 0));
        let val = MaybeRelocatable::from(bigint!(5));
        let mut memory = Memory::new();
        memory.temp_data.push(Vec::new());
        memory.insert(&key, &val).unwrap();
        assert_eq!(
            memory.get(&key).unwrap().unwrap().as_ref(),
            &MaybeRelocatable::from(bigint!(5)),
        );
    }

    #[test]
    fn insert_and_get_from_temp_segment_failed() {
        let key = mayberelocatable!(-1, 1);
        let mut memory = Memory::new();
        memory.temp_data = vec![vec![None, Some(mayberelocatable!(8))]];
        assert_eq!(
            memory.insert(&key, &mayberelocatable!(5)),
            Err(MemoryError::InconsistentMemory(
                mayberelocatable!(-1, 1),
                mayberelocatable!(8),
                mayberelocatable!(5)
            ))
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
        assert_eq!(memory.get(&key_b).unwrap().unwrap().as_ref(), &val);
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
        assert_eq!(memory.get(&key_b).unwrap().unwrap().as_ref(), &val);
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
        assert!(matches!(
            mem.get(&MaybeRelocatable::from((1, 0))),
            _val_clone
        ));
    }

    #[test]
    fn validate_existing_memory_for_range_check_within_bounds() {
        let mut builtin = RangeCheckBuiltinRunner::new(bigint!(8), 8);
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        builtin.initialize_segments(&mut segments, &mut memory);
        assert_eq!(builtin.add_validation_rule(&mut memory), Ok(()));
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
        assert_eq!(builtin.add_validation_rule(&mut memory), Ok(()));
        let error = memory.validate_existing_memory();
        assert_eq!(error, Err(MemoryError::NumOutOfBounds));
        assert_eq!(
            error.unwrap_err().to_string(),
            "Range-check validation failed, number is out of valid range"
        );
    }

    #[test]
    fn validate_existing_memory_for_signature() {
        let mut builtin = SignatureBuiltinRunner::new(8);
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        segments.add(&mut memory);
        builtin.initialize_segments(&mut segments, &mut memory);
        memory
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(bigint!(1_i32)),
            )
            .unwrap();
        builtin.add_validation_rule(&mut memory).unwrap();
        let _error = memory.validate_existing_memory();
    }

    #[test]
    fn validate_existing_memory_for_signature_two() {
        let mut builtin = SignatureBuiltinRunner::new(8);

        let signing_key = SigningKey::random(&mut OsRng);

        let verifying_key = VerifyingKey::from(&signing_key);

        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        segments.add(&mut memory);
        builtin.initialize_segments(&mut segments, &mut memory);
        memory
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(BigInt::from_bytes_be(
                    Sign::Plus,
                    verifying_key.to_bytes().as_slice(),
                )),
            )
            .unwrap();
        memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint_str!(b"-1472574760335685482768423018116732869320670550222259018541069375211356613248")),
            ).unwrap();
        builtin.add_validation_rule(&mut memory).unwrap();
        let error = memory.validate_existing_memory();
        assert!(error.is_err())
    }

    #[test]
    fn validate_existing_memory_for_valid_signature() {
        let mut builtin = SignatureBuiltinRunner::new(80);
        let signing_key = SigningKey::random(&mut OsRng);

        let verifying_key = VerifyingKey::from(&signing_key);

        let (_sign, msg) = bigint!(1_i32).to_bytes_be();

        let signature: Signature = signing_key.sign(&msg);

        builtin.add_signature(Relocatable::from((1, 0)), signature);

        let mut segments = MemorySegmentManager::new();

        let mut memory = Memory::new();

        segments.add(&mut memory);

        builtin.initialize_segments(&mut segments, &mut memory);

        memory
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(BigInt::from_bytes_be(
                    Sign::Plus,
                    verifying_key.to_bytes().as_slice(),
                )),
            )
            .unwrap();

        memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1_i32)),
            )
            .unwrap();

        builtin.add_validation_rule(&mut memory).unwrap();

        let result = memory.validate_existing_memory();

        assert!(result.is_ok())
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
        assert_eq!(builtin.add_validation_rule(&mut memory), Ok(()));
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
        assert_eq!(builtin.add_validation_rule(&mut memory), Ok(()));
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
            memory
                .get_integer(&Relocatable::from((0, 0)))
                .unwrap()
                .as_ref(),
            &bigint!(10)
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

    #[test]
    fn insert_and_get_temporary_succesful() {
        let mut memory = Memory::new();
        memory.temp_data.push(Vec::new());

        let key = MaybeRelocatable::from((-1, 0));
        let val = MaybeRelocatable::from(bigint!(5));
        memory.insert(&key, &val).unwrap();

        assert_eq!(memory.get(&key).unwrap().unwrap().as_ref(), &val);
    }

    #[test]
    fn add_relocation_rule() {
        let mut memory = Memory::new();

        assert_eq!(
            memory.add_relocation_rule((-1, 0).into(), (1, 2).into()),
            Ok(()),
        );
        assert_eq!(
            memory.add_relocation_rule((-2, 0).into(), (-1, 1).into()),
            Ok(()),
        );
        assert_eq!(
            memory.add_relocation_rule((5, 0).into(), (0, 0).into()),
            Err(MemoryError::AddressNotInTemporarySegment(5)),
        );
        assert_eq!(
            memory.add_relocation_rule((-3, 6).into(), (0, 0).into()),
            Err(MemoryError::NonZeroOffset(6)),
        );
        assert_eq!(
            memory.add_relocation_rule((-1, 0).into(), (0, 0).into()),
            Err(MemoryError::DuplicatedRelocation(-1)),
        );
    }

    #[test]
    fn relocate_value() {
        let mut memory = Memory::new();
        memory.relocation_rules.insert(1, (2, 0).into());
        memory.relocation_rules.insert(2, (2, 2).into());

        // Test when value is None:
        assert_eq!(memory.relocate_value(None), Ok(None));
        // Test when value is Some(BigInt):
        assert_eq!(
            memory.relocate_value(Some(Cow::Owned(MaybeRelocatable::Int(bigint!(0))))),
            Ok(Some(Cow::Owned(MaybeRelocatable::Int(bigint!(0))))),
        );

        // Test when value is Some(MaybeRelocatable) with segment_index >= 0:
        assert_eq!(
            memory.relocate_value(Some(Cow::Owned(MaybeRelocatable::RelocatableValue(
                (0, 0).into()
            )))),
            Ok(Some(Cow::Owned(MaybeRelocatable::RelocatableValue(
                (0, 0).into()
            )))),
        );
        assert_eq!(
            memory.relocate_value(Some(Cow::Owned(MaybeRelocatable::RelocatableValue(
                (5, 0).into()
            )))),
            Ok(Some(Cow::Owned(MaybeRelocatable::RelocatableValue(
                (5, 0).into()
            )))),
        );

        // Test when value is Some(MaybeRelocatable) with segment_index < 0 and
        // there are no applicable relocation rules:
        assert_eq!(
            memory.relocate_value(Some(Cow::Owned(MaybeRelocatable::RelocatableValue(
                (-5, 0).into()
            )))),
            Ok(Some(Cow::Owned(MaybeRelocatable::RelocatableValue(
                (-5, 0).into()
            )))),
        );

        // Test when value is Some(MaybeRelocatable) with segment_index < 0 and
        // there are applicable relocation rules:
        assert_eq!(
            memory.relocate_value(Some(Cow::Owned(MaybeRelocatable::RelocatableValue(
                (-1, 0).into()
            )))),
            Ok(Some(Cow::Owned(MaybeRelocatable::RelocatableValue(
                (2, 0).into()
            )))),
        );
        assert_eq!(
            memory.relocate_value(Some(Cow::Owned(MaybeRelocatable::RelocatableValue(
                (-2, 0).into()
            )))),
            Ok(Some(Cow::Owned(MaybeRelocatable::RelocatableValue(
                (2, 2).into()
            )))),
        );
        assert_eq!(
            memory.relocate_value(Some(Cow::Owned(MaybeRelocatable::RelocatableValue(
                (-1, 5).into()
            )))),
            Ok(Some(Cow::Owned(MaybeRelocatable::RelocatableValue(
                (2, 5).into()
            )))),
        );
        assert_eq!(
            memory.relocate_value(Some(Cow::Owned(MaybeRelocatable::RelocatableValue(
                (-2, 5).into()
            )))),
            Ok(Some(Cow::Owned(MaybeRelocatable::RelocatableValue(
                (2, 7).into()
            )))),
        );
    }
}
