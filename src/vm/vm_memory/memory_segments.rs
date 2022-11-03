use num_bigint::BigInt;
use num_integer::Integer;
use std::any::Any;
use std::cmp;
use std::collections::{HashMap, HashSet};

use crate::types::relocatable::{MaybeRelocatable, Relocatable};
use crate::utils::from_relocatable_to_indexes;
use crate::vm::errors::memory_errors::MemoryError;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::vm_core::VirtualMachine;
use crate::vm::vm_memory::memory::Memory;

pub struct MemorySegmentManager {
    pub num_segments: usize,
    pub num_temp_segments: usize,
    pub segment_sizes: Vec<usize>,
    pub segment_used_sizes: Option<Vec<usize>>,
}

impl MemorySegmentManager {
    ///Adds a new segment and returns its starting location as a RelocatableValue.
    pub fn add(&mut self, memory: &mut Memory) -> Relocatable {
        let segment_index = self.num_segments;
        self.num_segments += 1;
        memory.data.push(Vec::new());
        Relocatable {
            segment_index: segment_index as isize,
            offset: 0,
        }
    }

    ///Adds a new temporary segment and returns its starting location as a RelocatableValue.
    ///Negative segment_index indicates its refer to a temporary segment
    pub fn add_temporary_segment(&mut self, memory: &mut Memory) -> Relocatable {
        self.num_temp_segments += 1;
        memory.temp_data.push(Vec::new());
        Relocatable {
            segment_index: -(self.num_temp_segments as isize),
            offset: 0,
        }
    }

    ///Writes data into the memory at address ptr and returns the first address after the data.
    pub fn load_data(
        &mut self,
        memory: &mut Memory,
        ptr: &MaybeRelocatable,
        data: Vec<MaybeRelocatable>,
    ) -> Result<MaybeRelocatable, MemoryError> {
        for (num, value) in data.iter().enumerate() {
            memory.insert(&ptr.add_usize_mod(num, None), value)?;
        }
        Ok(ptr.add_usize_mod(data.len(), None))
    }

    pub fn new() -> MemorySegmentManager {
        MemorySegmentManager {
            num_segments: 0,
            num_temp_segments: 0,
            segment_sizes: Vec::new(),
            segment_used_sizes: None,
        }
    }

    ///Calculates the size (number of non-none elements) of each memory segment
    pub fn compute_effective_sizes(&mut self, memory: &Memory) {
        if self.segment_used_sizes != None {
            return;
        }
        let mut segment_used_sizes = Vec::new();
        for segment in memory.data.iter() {
            segment_used_sizes.push(segment.len());
        }
        self.segment_used_sizes = Some(segment_used_sizes);
    }

    ///Returns the number of used segments when they are already computed.
    ///Returns None otherwise.
    pub fn get_segment_used_size(&self, index: usize) -> Option<usize> {
        self.segment_used_sizes.as_ref()?.get(index).copied()
    }

    ///Returns a vector that contains the first relocated address of each memory segment
    pub fn relocate_segments(&self) -> Result<Vec<usize>, MemoryError> {
        let first_addr = 1;
        let mut relocation_table = vec![first_addr];
        match &self.segment_used_sizes {
            Some(segment_used_sizes) => {
                for (i, size) in segment_used_sizes.iter().enumerate() {
                    relocation_table.push(relocation_table[i] + size);
                }
            }
            None => return Err(MemoryError::EffectiveSizesNotCalled),
        }
        //The last value corresponds to the total amount of elements across all segments, which isnt needed for relocation.
        relocation_table.pop();
        Ok(relocation_table)
    }

    pub fn gen_arg(
        &mut self,
        arg: &dyn Any,
        prime: Option<&BigInt>,
        memory: &mut Memory,
    ) -> Result<MaybeRelocatable, VirtualMachineError> {
        if let Some(value) = arg.downcast_ref::<MaybeRelocatable>() {
            Ok(match value {
                MaybeRelocatable::RelocatableValue(value) => value.into(),
                MaybeRelocatable::Int(value) => MaybeRelocatable::Int(match prime {
                    Some(prime) => value.mod_floor(prime),
                    None => value.clone(),
                }),
            })
        } else if let Some(value) = arg.downcast_ref::<Vec<MaybeRelocatable>>() {
            let base = self.add(memory);
            self.write_arg(memory, &base, value, prime)?;
            Ok(base.into())
        } else {
            Err(VirtualMachineError::NotImplemented)
        }
    }

    pub fn gen_typed_args(
        &self,
        args: Vec<&dyn Any>,
        vm: &VirtualMachine,
    ) -> Result<Vec<MaybeRelocatable>, VirtualMachineError> {
        let mut cairo_args = Vec::new();
        for arg in args {
            if let Some(value) = arg.downcast_ref::<MaybeRelocatable>() {
                cairo_args.push(match value {
                    MaybeRelocatable::RelocatableValue(value) => value.clone().into(),
                    MaybeRelocatable::Int(value) => {
                        let value = value.mod_floor(vm.get_prime());
                        value.into()
                    }
                });
            } else if let Some(value) = arg.downcast_ref::<Vec<MaybeRelocatable>>() {
                let value = value.iter().map(|x| x as &dyn Any).collect::<Vec<_>>();
                cairo_args.extend(self.gen_typed_args(value, vm)?.into_iter());
            } else {
                return Err(VirtualMachineError::NotImplemented);
            }
        }

        Ok(cairo_args)
    }

    pub fn write_arg(
        &mut self,
        memory: &mut Memory,
        ptr: &Relocatable,
        arg: &dyn Any,
        prime: Option<&BigInt>,
    ) -> Result<MaybeRelocatable, MemoryError> {
        if let Some(vector) = arg.downcast_ref::<Vec<MaybeRelocatable>>() {
            let data = vector
                .iter()
                .map(|value| match value {
                    MaybeRelocatable::RelocatableValue(value) => value.into(),
                    MaybeRelocatable::Int(value) => MaybeRelocatable::Int(match prime {
                        Some(prime) => value.mod_floor(prime),
                        None => value.clone(),
                    }),
                })
                .collect();
            self.load_data(
                memory,
                &MaybeRelocatable::from((ptr.segment_index, ptr.offset)),
                data,
            )
        } else {
            Err(MemoryError::WriteArg)
        }
    }

    pub fn is_valid_memory_value(&self, value: &MaybeRelocatable) -> Result<bool, MemoryError> {
        match &self.segment_used_sizes {
            Some(segment_used_sizes) => match value {
                MaybeRelocatable::Int(_) => Ok(true),
                MaybeRelocatable::RelocatableValue(relocatable) => {
                    let segment_index: usize =
                        relocatable.segment_index.try_into().map_err(|_| {
                            MemoryError::AddressInTemporarySegment(relocatable.segment_index)
                        })?;

                    Ok(segment_index < segment_used_sizes.len())
                }
            },
            None => Err(MemoryError::EffectiveSizesNotCalled),
        }
    }

    pub fn get_memory_holes(
        &self,
        accessed_addresses: &HashSet<Relocatable>,
    ) -> Result<usize, MemoryError> {
        let segment_used_sizes = self
            .segment_used_sizes
            .as_ref()
            .ok_or(MemoryError::MissingSegmentUsedSizes)?;

        let mut accessed_offsets_sets = HashMap::new();
        for addr in accessed_addresses {
            let (index, offset) = from_relocatable_to_indexes(addr);
            let (segment_size, offset_set) = match accessed_offsets_sets.get_mut(&index) {
                Some(x) => x,
                None => {
                    let segment_size = self
                        .get_segment_size(index)
                        .ok_or(MemoryError::SegmentNotFinalized(index))?;

                    accessed_offsets_sets.insert(index, (segment_size, HashSet::new()));
                    accessed_offsets_sets.get_mut(&index).unwrap()
                }
            };
            if offset > *segment_size {
                return Err(MemoryError::NumOutOfBounds);
            }

            offset_set.insert(offset);
        }

        let max = cmp::max(self.segment_sizes.len(), segment_used_sizes.len());
        Ok((0..max)
            .filter_map(|index| accessed_offsets_sets.get(&index))
            .map(|(segment_size, offsets_set)| segment_size - offsets_set.len())
            .sum())
    }

    pub fn get_segment_size(&self, index: usize) -> Option<usize> {
        self.segment_sizes
            .get(index)
            .copied()
            .or_else(|| self.get_segment_used_size(index))
    }
}

impl Default for MemorySegmentManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bigint, relocatable, utils::test_utils::*};
    use num_bigint::{BigInt, Sign};
    use std::vec;

    #[test]
    fn add_segment_no_size() {
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        let base = segments.add(&mut memory);
        assert_eq!(base, relocatable!(0, 0));
        assert_eq!(segments.num_segments, 1);
    }

    #[test]
    fn add_segment_no_size_test_two_segments() {
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        let mut _base = segments.add(&mut memory);
        _base = segments.add(&mut memory);
        assert_eq!(
            _base,
            Relocatable {
                segment_index: 1,
                offset: 0
            }
        );
        assert_eq!(segments.num_segments, 2);
    }

    #[test]
    fn add_one_temporary_segment() {
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        let base = segments.add_temporary_segment(&mut memory);
        assert_eq!(base, relocatable!(-1, 0));
        assert_eq!(segments.num_temp_segments, 1);
    }

    #[test]
    fn add_two_temporary_segments() {
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        let mut _base = segments.add_temporary_segment(&mut memory);
        _base = segments.add_temporary_segment(&mut memory);
        assert_eq!(
            _base,
            Relocatable {
                segment_index: -2,
                offset: 0
            }
        );
        assert_eq!(segments.num_temp_segments, 2);
    }

    #[test]
    fn load_data_empty() {
        let data = Vec::new();
        let ptr = MaybeRelocatable::from((0, 3));
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        let current_ptr = segments.load_data(&mut memory, &ptr, data).unwrap();
        assert_eq!(current_ptr, MaybeRelocatable::from((0, 3)));
    }

    #[test]
    fn load_data_one_element() {
        let data = vec![MaybeRelocatable::from(bigint!(4))];
        let ptr = MaybeRelocatable::from((0, 0));
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        segments.add(&mut memory);
        let current_ptr = segments.load_data(&mut memory, &ptr, data).unwrap();
        assert_eq!(current_ptr, MaybeRelocatable::from((0, 1)));
        assert_eq!(
            memory.get(&ptr).unwrap().unwrap().as_ref(),
            &MaybeRelocatable::from(bigint!(4))
        );
    }

    #[test]
    fn load_data_three_elements() {
        let data = vec![
            MaybeRelocatable::from(bigint!(4)),
            MaybeRelocatable::from(bigint!(5)),
            MaybeRelocatable::from(bigint!(6)),
        ];
        let ptr = MaybeRelocatable::from((0, 0));
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        segments.add(&mut memory);
        let current_ptr = segments.load_data(&mut memory, &ptr, data).unwrap();
        assert_eq!(current_ptr, MaybeRelocatable::from((0, 3)));

        assert_eq!(
            memory.get(&ptr).unwrap().unwrap().as_ref(),
            &MaybeRelocatable::from(bigint!(4))
        );
        assert_eq!(
            memory
                .get(&MaybeRelocatable::from((0, 1)))
                .unwrap()
                .unwrap()
                .as_ref(),
            &MaybeRelocatable::from(bigint!(5))
        );
        assert_eq!(
            memory
                .get(&MaybeRelocatable::from((0, 2)))
                .unwrap()
                .unwrap()
                .as_ref(),
            &MaybeRelocatable::from(bigint!(6))
        );
    }
    #[test]
    fn compute_effective_sizes_for_one_segment_memory() {
        let mut segments = MemorySegmentManager::new();
        let memory = memory![((0, 0), 1), ((0, 1), 1), ((0, 2), 1)];
        segments.compute_effective_sizes(&memory);
        assert_eq!(Some(vec![3]), segments.segment_used_sizes);
    }

    #[test]
    fn compute_effective_sizes_for_one_segment_memory_with_gap() {
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        segments.add(&mut memory);
        memory
            .insert(
                &MaybeRelocatable::from((0, 6)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        segments.compute_effective_sizes(&memory);
        assert_eq!(Some(vec![7]), segments.segment_used_sizes);
    }

    #[test]
    fn compute_effective_sizes_for_one_segment_memory_with_gaps() {
        let mut segments = MemorySegmentManager::new();
        let memory = memory![((0, 3), 1), ((0, 4), 1), ((0, 7), 1), ((0, 9), 1)];
        segments.compute_effective_sizes(&memory);
        assert_eq!(Some(vec![10]), segments.segment_used_sizes);
    }

    #[test]
    fn compute_effective_sizes_for_three_segment_memory() {
        let mut segments = MemorySegmentManager::new();
        let memory = memory![
            ((0, 0), 1),
            ((0, 1), 1),
            ((0, 2), 1),
            ((1, 0), 1),
            ((1, 1), 1),
            ((1, 2), 1),
            ((2, 0), 1),
            ((2, 1), 1),
            ((2, 2), 1)
        ];
        segments.compute_effective_sizes(&memory);
        assert_eq!(Some(vec![3, 3, 3]), segments.segment_used_sizes);
    }

    #[test]
    fn compute_effective_sizes_for_three_segment_memory_with_gaps() {
        let mut segments = MemorySegmentManager::new();
        let memory = memory![
            ((0, 2), 1),
            ((0, 5), 1),
            ((0, 7), 1),
            ((1, 1), 1),
            ((2, 2), 1),
            ((2, 4), 1),
            ((2, 7), 1)
        ];
        segments.compute_effective_sizes(&memory);
        assert_eq!(Some(vec![8, 2, 8]), segments.segment_used_sizes);
    }

    #[test]
    fn get_segment_used_size_after_computing_used() {
        let mut segments = MemorySegmentManager::new();
        let memory = memory![
            ((0, 2), 1),
            ((0, 5), 1),
            ((0, 7), 1),
            ((1, 1), 1),
            ((2, 2), 1),
            ((2, 4), 1),
            ((2, 7), 1)
        ];
        segments.compute_effective_sizes(&memory);
        assert_eq!(Some(8), segments.get_segment_used_size(2));
    }

    #[test]
    fn get_segment_used_size_before_computing_used() {
        let segments = MemorySegmentManager::new();
        assert_eq!(None, segments.get_segment_used_size(2));
    }

    #[test]
    fn relocate_segments_one_segment() {
        let mut segments = MemorySegmentManager::new();
        segments.segment_used_sizes = Some(vec![3]);
        assert_eq!(
            segments
                .relocate_segments()
                .expect("Couldn't relocate after compute effective sizes"),
            vec![1]
        )
    }

    #[test]
    fn relocate_segments_five_segment() {
        let mut segments = MemorySegmentManager::new();
        segments.segment_used_sizes = Some(vec![3, 3, 56, 78, 8]);
        assert_eq!(
            segments
                .relocate_segments()
                .expect("Couldn't relocate after compute effective sizes"),
            vec![1, 4, 7, 63, 141]
        )
    }

    #[test]
    fn write_arg_with_apply_modulo() {
        let data = vec![
            mayberelocatable!(11),
            mayberelocatable!(12),
            mayberelocatable!(13),
        ];
        let ptr = Relocatable::from((1, 0));
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        for _ in 0..2 {
            segments.add(&mut memory);
        }

        let exec = segments.write_arg(&mut memory, &ptr, &data, Some(&bigint!(5)));

        assert_eq!(exec, Ok(MaybeRelocatable::from((1, 3))));
        assert_eq!(
            memory.data[1],
            vec![
                Some(mayberelocatable!(1)),
                Some(mayberelocatable!(2)),
                Some(mayberelocatable!(3)),
            ]
        );
    }

    #[test]
    fn write_arg_with_no_apply_modulo() {
        let data = vec![
            mayberelocatable!(1),
            mayberelocatable!(2),
            mayberelocatable!(3),
        ];
        let ptr = Relocatable::from((0, 0));
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        segments.add(&mut memory);
        let exec = segments.write_arg(&mut memory, &ptr, &data, None);

        assert_eq!(exec, Ok(MaybeRelocatable::from((0, 3))));
        assert_eq!(
            memory.data[0],
            vec![
                Some(mayberelocatable!(1)),
                Some(mayberelocatable!(2)),
                Some(mayberelocatable!(3)),
            ]
        );
    }

    #[test]
    fn segment_default() {
        let segment_mng_new = MemorySegmentManager::new();
        let segment_mng_def: MemorySegmentManager = Default::default();
        assert_eq!(segment_mng_new.num_segments, segment_mng_def.num_segments);
        assert_eq!(
            segment_mng_new.segment_used_sizes,
            segment_mng_def.segment_used_sizes
        );
    }

    #[test]
    fn is_valid_memory_value_missing_effective_sizes() {
        let segment_manager = MemorySegmentManager::new();

        assert_eq!(
            segment_manager.is_valid_memory_value(&mayberelocatable!(0)),
            Err(MemoryError::EffectiveSizesNotCalled),
        );
    }

    #[test]
    fn is_valid_memory_value_temporary_segment() {
        let mut segment_manager = MemorySegmentManager::new();

        segment_manager.segment_used_sizes = Some(vec![10]);
        assert_eq!(
            segment_manager.is_valid_memory_value(&mayberelocatable!(-1, 0)),
            Err(MemoryError::AddressInTemporarySegment(-1)),
        );
    }

    #[test]
    fn is_valid_memory_value_invalid_segment() {
        let mut segment_manager = MemorySegmentManager::new();

        segment_manager.segment_used_sizes = Some(vec![10]);
        assert_eq!(
            segment_manager.is_valid_memory_value(&mayberelocatable!(1, 0)),
            Ok(false),
        );
    }

    #[test]
    fn is_valid_memory_value() {
        let mut segment_manager = MemorySegmentManager::new();

        segment_manager.segment_used_sizes = Some(vec![10]);
        assert_eq!(
            segment_manager.is_valid_memory_value(&mayberelocatable!(0, 5)),
            Ok(true),
        );
    }

    #[test]
    fn get_memory_holes_missing_segment_used_sizes() {
        let memory_segment_manager = MemorySegmentManager::new();
        let accessed_addresses = HashSet::new();

        assert_eq!(
            memory_segment_manager.get_memory_holes(&accessed_addresses),
            Err(MemoryError::MissingSegmentUsedSizes),
        );
    }

    #[test]
    fn get_memory_holes_segment_not_finalized() {
        let mut memory_segment_manager = MemorySegmentManager::new();
        let mut accessed_addresses = HashSet::new();

        memory_segment_manager.segment_used_sizes = Some(Vec::new());
        accessed_addresses.insert((0, 0).into());
        accessed_addresses.insert((0, 1).into());
        accessed_addresses.insert((0, 2).into());
        accessed_addresses.insert((0, 3).into());
        assert_eq!(
            memory_segment_manager.get_memory_holes(&accessed_addresses),
            Err(MemoryError::SegmentNotFinalized(0)),
        );
    }

    #[test]
    fn get_memory_holes_out_of_bounds() {
        let mut memory_segment_manager = MemorySegmentManager::new();
        let mut accessed_addresses = HashSet::new();

        memory_segment_manager.segment_used_sizes = Some(Vec::new());
        accessed_addresses.insert((0, 0).into());
        accessed_addresses.insert((0, 1).into());
        accessed_addresses.insert((0, 2).into());
        accessed_addresses.insert((0, 3).into());

        memory_segment_manager.segment_used_sizes = Some(vec![2]);
        assert_eq!(
            memory_segment_manager.get_memory_holes(&accessed_addresses),
            Err(MemoryError::NumOutOfBounds),
        );
    }

    #[test]
    fn get_memory_holes_empty() {
        let mut memory_segment_manager = MemorySegmentManager::new();
        let accessed_addresses = HashSet::new();

        memory_segment_manager.segment_used_sizes = Some(Vec::new());
        assert_eq!(
            memory_segment_manager.get_memory_holes(&accessed_addresses),
            Ok(0),
        );
    }

    #[test]
    fn get_memory_holes_empty2() {
        let mut memory_segment_manager = MemorySegmentManager::new();
        let accessed_addresses = HashSet::new();

        memory_segment_manager.segment_used_sizes = Some(vec![4]);
        assert_eq!(
            memory_segment_manager.get_memory_holes(&accessed_addresses),
            Ok(0),
        );
    }

    #[test]
    fn get_memory_holes() {
        let mut memory_segment_manager = MemorySegmentManager::new();
        let mut accessed_addresses = HashSet::new();

        memory_segment_manager.segment_used_sizes = Some(vec![10]);
        accessed_addresses.insert((0, 0).into());
        accessed_addresses.insert((0, 1).into());
        accessed_addresses.insert((0, 2).into());
        accessed_addresses.insert((0, 3).into());
        accessed_addresses.insert((0, 6).into());
        accessed_addresses.insert((0, 7).into());
        accessed_addresses.insert((0, 8).into());
        accessed_addresses.insert((0, 9).into());
        assert_eq!(
            memory_segment_manager.get_memory_holes(&accessed_addresses),
            Ok(2),
        );
    }

    #[test]
    fn get_memory_holes2() {
        let mut memory_segment_manager = MemorySegmentManager::new();
        let mut accessed_addresses = HashSet::new();

        memory_segment_manager.segment_sizes = vec![15];
        memory_segment_manager.segment_used_sizes = Some(vec![10]);
        accessed_addresses.insert((0, 0).into());
        accessed_addresses.insert((0, 1).into());
        accessed_addresses.insert((0, 2).into());
        accessed_addresses.insert((0, 3).into());
        accessed_addresses.insert((0, 6).into());
        accessed_addresses.insert((0, 7).into());
        accessed_addresses.insert((0, 8).into());
        accessed_addresses.insert((0, 9).into());
        assert_eq!(
            memory_segment_manager.get_memory_holes(&accessed_addresses),
            Ok(7),
        );
    }

    #[test]
    fn get_memory_size_missing_segment() {
        let memory_segment_manager = MemorySegmentManager::new();

        assert_eq!(memory_segment_manager.get_segment_size(0), None);
    }

    #[test]
    fn get_memory_size_used() {
        let mut memory_segment_manager = MemorySegmentManager::new();
        memory_segment_manager.segment_used_sizes = Some(vec![5]);

        assert_eq!(memory_segment_manager.get_segment_size(0), Some(5));
    }

    #[test]
    fn get_memory_size() {
        let mut memory_segment_manager = MemorySegmentManager::new();
        memory_segment_manager.segment_sizes = vec![5];

        assert_eq!(memory_segment_manager.get_segment_size(0), Some(5));
    }

    #[test]
    fn get_memory_size2() {
        let mut memory_segment_manager = MemorySegmentManager::new();
        memory_segment_manager.segment_sizes = vec![5];
        memory_segment_manager.segment_used_sizes = Some(vec![3]);

        assert_eq!(memory_segment_manager.get_segment_size(0), Some(5));
    }

    #[test]
    fn gen_arg_relocatable() {
        let mut memory_segment_manager = MemorySegmentManager::new();
        let mut vm = vm!();

        assert_eq!(
            memory_segment_manager.gen_arg(&mayberelocatable!(0, 0), None, &mut vm.memory),
            Ok(mayberelocatable!(0, 0)),
        );
    }

    #[test]
    fn gen_arg_bigint() {
        let mut memory_segment_manager = MemorySegmentManager::new();
        let mut vm = vm!();

        assert_eq!(
            memory_segment_manager.gen_arg(&mayberelocatable!(1234), None, &mut vm.memory),
            Ok(mayberelocatable!(1234)),
        );
    }

    #[test]
    fn gen_arg_bigint_prime() {
        let mut memory_segment_manager = MemorySegmentManager::new();
        let mut vm = vm!();

        assert_eq!(
            memory_segment_manager.gen_arg(
                &mayberelocatable!(1234),
                Some(&bigint!(1234)),
                &mut vm.memory
            ),
            Ok(mayberelocatable!(0)),
        );
    }

    #[test]
    fn gen_arg_vec() {
        let mut memory_segment_manager = MemorySegmentManager::new();
        let mut vm = vm!();

        assert_eq!(
            memory_segment_manager.gen_arg(
                &vec![
                    mayberelocatable!(0),
                    mayberelocatable!(1),
                    mayberelocatable!(2),
                    mayberelocatable!(3),
                    mayberelocatable!(0, 0),
                    mayberelocatable!(0, 1),
                    mayberelocatable!(0, 2),
                    mayberelocatable!(0, 3),
                ],
                Some(&bigint!(1234)),
                &mut vm.memory,
            ),
            Ok(mayberelocatable!(0, 0)),
        );
    }

    #[test]
    fn gen_arg_not_implemented() {
        let mut memory_segment_manager = MemorySegmentManager::new();
        let mut vm = vm!();

        assert_eq!(
            memory_segment_manager.gen_arg(&"", None, &mut vm.memory),
            Err(VirtualMachineError::NotImplemented),
        );
    }

    #[test]
    fn gen_typed_args_empty() {
        let memory_segment_manager = MemorySegmentManager::new();
        let vm = vm!();

        assert_eq!(
            memory_segment_manager.gen_typed_args(vec![], &vm),
            Ok(vec![])
        );
    }

    #[test]
    fn gen_typed_args_not_implemented() {
        let memory_segment_manager = MemorySegmentManager::new();
        let vm = vm!();

        assert_eq!(
            memory_segment_manager.gen_typed_args(vec![&0usize], &vm),
            Err(VirtualMachineError::NotImplemented),
        );
    }

    #[test]
    fn gen_typed_args_bigint() {
        let memory_segment_manager = MemorySegmentManager::new();
        let vm = vm!();

        assert_eq!(
            memory_segment_manager.gen_typed_args(
                vec![&MaybeRelocatable::Int(vm.get_prime() + &bigint!(1))],
                &vm,
            ),
            Ok(vec![mayberelocatable!(1)]),
        );
    }

    #[test]
    fn gen_typed_args_relocatable_slice() {
        let memory_segment_manager = MemorySegmentManager::new();
        let vm = vm!();

        assert_eq!(
            memory_segment_manager.gen_typed_args(
                vec![&[
                    mayberelocatable!(0, 0),
                    mayberelocatable!(0, 1),
                    mayberelocatable!(0, 2),
                ]
                .into_iter()
                .collect::<Vec<MaybeRelocatable>>(),],
                &vm,
            ),
            Ok(vec![
                mayberelocatable!(0, 0),
                mayberelocatable!(0, 1),
                mayberelocatable!(0, 2),
            ]),
        );
    }
}
