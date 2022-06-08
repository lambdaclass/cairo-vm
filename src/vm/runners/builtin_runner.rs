use crate::bigint;
use crate::types::relocatable::{MaybeRelocatable, Relocatable};
use crate::vm::vm_memory::memory::Memory;
use crate::vm::vm_memory::memory_segments::MemorySegmentManager;
use num_bigint::{BigInt, Sign};
use num_traits::FromPrimitive;
use starknet_crypto::{pedersen_hash, FieldElement};

pub struct RangeCheckBuiltinRunner {
    included: bool,
    _ratio: BigInt,
    base: Option<Relocatable>,
    _stop_ptr: Option<Relocatable>,
    _cells_per_instance: i32,
    _n_input_cells: i32,
    _inner_rc_bound: BigInt,
    _bound: BigInt,
    _n_parts: u32,
}
pub struct OutputBuiltinRunner {
    included: bool,
    base: Option<Relocatable>,
    _stop_ptr: Option<Relocatable>,
}

pub struct HashBuiltinRunner {
    base: Option<Relocatable>,
    included: bool,
    _ratio: usize,
    _cells_per_instance: usize,
    _n_input_cells: usize,
    _stop_ptr: Option<Relocatable>,
    verified_addresses: Vec<MaybeRelocatable>,
}

pub trait BuiltinRunner {
    ///Creates the necessary segments for the builtin in the MemorySegmentManager and stores the first address on the builtin's base
    fn initialize_segments(&mut self, segments: &mut MemorySegmentManager, memory: &mut Memory);
    fn initial_stack(&self) -> Vec<MaybeRelocatable>;
    ///Returns the builtin's base
    fn base(&self) -> Option<Relocatable>;
    fn validate_existing_memory(
        &self,
        memory: &[Option<MaybeRelocatable>],
    ) -> Option<Vec<MaybeRelocatable>>;
}

impl RangeCheckBuiltinRunner {
    pub fn new(included: bool, ratio: BigInt, n_parts: u32) -> RangeCheckBuiltinRunner {
        let inner_rc_bound = bigint!(2_i32.pow(16));
        RangeCheckBuiltinRunner {
            included,
            _ratio: ratio,
            base: None,
            _stop_ptr: None,
            _cells_per_instance: 1,
            _n_input_cells: 1,
            _inner_rc_bound: inner_rc_bound.clone(),
            _bound: inner_rc_bound.pow(n_parts),
            _n_parts: n_parts,
        }
    }
}
impl BuiltinRunner for RangeCheckBuiltinRunner {
    fn initialize_segments(&mut self, segments: &mut MemorySegmentManager, memory: &mut Memory) {
        self.base = Some(segments.add(memory, None))
    }
    fn initial_stack(&self) -> Vec<MaybeRelocatable> {
        if self.included {
            if let Some(builtin_base) = &self.base {
                vec![MaybeRelocatable::RelocatableValue(builtin_base.clone())]
            } else {
                panic!("Uninitialized self.base")
            }
        } else {
            Vec::new()
        }
    }

    fn base(&self) -> Option<Relocatable> {
        self.base.clone()
    }

    fn validate_existing_memory(
        &self,
        builtin_memory: &[Option<MaybeRelocatable>],
    ) -> Option<Vec<MaybeRelocatable>> {
        let mut validated_addresses = Vec::<MaybeRelocatable>::new();
        for (offset, value) in builtin_memory.iter().enumerate() {
            if let Some(MaybeRelocatable::Int(ref num)) = value {
                if bigint!(0) <= num.clone() && num.clone() < self._bound {
                    validated_addresses.push(MaybeRelocatable::RelocatableValue(Relocatable {
                        segment_index: self.base()?.segment_index,
                        offset,
                    }));
                } else {
                    panic!("Range-check validation failed, number is out of valid range");
                }
            } else {
                panic!("Range-check validation failed, encountered non-int value");
            }
        }
        if validated_addresses.is_empty() {
            return None;
        }
        Some(validated_addresses)
    }
}

impl OutputBuiltinRunner {
    pub fn new(included: bool) -> OutputBuiltinRunner {
        OutputBuiltinRunner {
            included,
            base: None,
            _stop_ptr: None,
        }
    }
}

impl BuiltinRunner for OutputBuiltinRunner {
    fn initialize_segments(&mut self, segments: &mut MemorySegmentManager, memory: &mut Memory) {
        self.base = Some(segments.add(memory, None))
    }

    fn initial_stack(&self) -> Vec<MaybeRelocatable> {
        if self.included {
            if let Some(builtin_base) = &self.base {
                vec![MaybeRelocatable::RelocatableValue(builtin_base.clone())]
            } else {
                panic!("Uninitialized self.base")
            }
        } else {
            Vec::new()
        }
    }

    fn base(&self) -> Option<Relocatable> {
        self.base.clone()
    }
    fn validate_existing_memory(
        &self,
        _memory: &[Option<MaybeRelocatable>],
    ) -> Option<Vec<MaybeRelocatable>> {
        None
    }
}

#[allow(dead_code)]
impl HashBuiltinRunner {
    pub fn new(included: bool, ratio: usize) -> Self {
        HashBuiltinRunner {
            base: None,
            included,
            _ratio: ratio,
            _cells_per_instance: 3,
            _n_input_cells: 2,
            _stop_ptr: None,
            verified_addresses: Vec::new(),
        }
    }
    pub fn deduce_memory_cell(
        &mut self,
        address: &MaybeRelocatable,
        memory: &Memory,
    ) -> Option<MaybeRelocatable> {
        if let &MaybeRelocatable::RelocatableValue(ref relocatable) = address {
            if relocatable.offset % self._cells_per_instance != 2
                || self.verified_addresses.contains(address)
            {
                return None;
            };
            if let (Some(MaybeRelocatable::Int(num_a)), Some(MaybeRelocatable::Int(num_b))) = (
                memory.get(&MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: relocatable.segment_index,
                    offset: relocatable.offset - 1,
                })),
                memory.get(&MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: relocatable.segment_index,
                    offset: relocatable.offset - 2,
                })),
            ) {
                self.verified_addresses.push(address.clone());

                //Convert MaybeRelocatable to FieldElement
                let a_string = num_a.to_str_radix(10);
                let b_string = num_b.to_str_radix(10);
                let y = FieldElement::from_dec_str(&a_string).unwrap();
                let x = FieldElement::from_dec_str(&b_string).unwrap();
                //Compute pedersen Hash
                let fe_result = pedersen_hash(&x, &y);
                //Convert result from FieldElement to MaybeRelocatable
                let r_byte_slice = fe_result.to_bytes_be();
                let result = BigInt::from_bytes_be(Sign::Plus, &r_byte_slice);
                return Some(MaybeRelocatable::from(result));
            }
            None
        } else {
            panic!("Memory address must be relocatable")
        }
    }
}

impl BuiltinRunner for HashBuiltinRunner {
    fn initialize_segments(&mut self, segments: &mut MemorySegmentManager, memory: &mut Memory) {
        self.base = Some(segments.add(memory, None))
    }

    fn initial_stack(&self) -> Vec<MaybeRelocatable> {
        if self.included {
            if let Some(builtin_base) = &self.base {
                vec![MaybeRelocatable::RelocatableValue(builtin_base.clone())]
            } else {
                panic!("Uninitialized self.base")
            }
        } else {
            Vec::new()
        }
    }

    fn base(&self) -> Option<Relocatable> {
        self.base.clone()
    }
    fn validate_existing_memory(
        &self,
        _memory: &[Option<MaybeRelocatable>],
    ) -> Option<Vec<MaybeRelocatable>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::vm_memory::memory::Memory;
    use crate::{bigint_str, relocatable};

    #[test]
    fn initialize_segments_for_output() {
        let mut builtin = OutputBuiltinRunner::new(true);
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        builtin.initialize_segments(&mut segments, &mut memory);
        assert_eq!(builtin.base, Some(relocatable!(0, 0)));
    }

    #[test]
    fn initialize_segments_for_range_check() {
        let mut builtin = RangeCheckBuiltinRunner::new(true, bigint!(8), 8);
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        builtin.initialize_segments(&mut segments, &mut memory);
        assert_eq!(
            builtin.base,
            Some(Relocatable {
                segment_index: 0,
                offset: 0
            })
        );
    }

    #[test]
    fn get_initial_stack_for_range_check_included_with_base() {
        let mut builtin = RangeCheckBuiltinRunner::new(true, bigint!(8), 8);
        builtin.base = Some(relocatable!(1, 0));
        let initial_stack = builtin.initial_stack();
        assert_eq!(
            initial_stack[0].clone(),
            MaybeRelocatable::RelocatableValue(builtin.base().unwrap())
        );
        assert_eq!(initial_stack.len(), 1);
    }

    #[test]
    #[should_panic]
    fn get_initial_stack_for_range_check_included_without_base() {
        let builtin = RangeCheckBuiltinRunner::new(true, bigint!(8), 8);
        let _initial_stack = builtin.initial_stack();
    }

    #[test]
    fn get_initial_stack_for_range_check_not_included() {
        let builtin = RangeCheckBuiltinRunner::new(false, bigint!(8), 8);
        let initial_stack = builtin.initial_stack();
        assert_eq!(initial_stack.len(), 0);
    }

    #[test]
    fn get_initial_stack_for_output_included_with_base() {
        let mut builtin = OutputBuiltinRunner::new(true);
        builtin.base = Some(Relocatable {
            segment_index: 1,
            offset: 0,
        });
        let initial_stack = builtin.initial_stack();
        assert_eq!(
            initial_stack[0].clone(),
            MaybeRelocatable::RelocatableValue(builtin.base().unwrap())
        );
        assert_eq!(initial_stack.len(), 1);
    }

    #[test]
    #[should_panic]
    fn get_initial_stack_for_output_included_without_base() {
        let builtin = OutputBuiltinRunner::new(true);
        let _initial_stack = builtin.initial_stack();
    }

    #[test]
    fn get_initial_stack_for_output_not_included() {
        let builtin = OutputBuiltinRunner::new(false);
        let initial_stack = builtin.initial_stack();
        assert_eq!(initial_stack.len(), 0);
    }

    #[test]
    fn validate_existing_memory_for_range_check_within_bounds() {
        let mut builtin = RangeCheckBuiltinRunner::new(true, bigint!(8), 8);
        builtin.base = Some(relocatable!(1, 0));

        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        for _ in 0..3 {
            segments.add(&mut memory, None);
        }

        memory.insert(
            &MaybeRelocatable::from((1, 0)),
            &MaybeRelocatable::from(bigint!(45)),
        );
        let vec = builtin.validate_existing_memory(&memory.data[1]).unwrap();
        assert_eq!(vec[0], MaybeRelocatable::from((1, 0)));
    }

    #[test]
    #[should_panic]
    fn validate_existing_memory_for_range_check_outside_bounds() {
        let mut builtin = RangeCheckBuiltinRunner::new(true, bigint!(8), 8);
        builtin.base = Some(relocatable!(1, 0));
        let mut memory = Memory::new();
        memory.insert(
            &MaybeRelocatable::from((1, 7)),
            &MaybeRelocatable::from(bigint!(-10)),
        );
        builtin.validate_existing_memory(&memory.data[1]);
    }

    #[test]
    #[should_panic]
    fn validate_existing_memory_for_range_check_relocatable_value() {
        let mut builtin = RangeCheckBuiltinRunner::new(true, bigint!(8), 8);
        builtin.base = Some(relocatable!(1, 0));
        let mut memory = Memory::new();
        memory.insert(
            &MaybeRelocatable::from((1, 7)),
            &MaybeRelocatable::from((1, 4)),
        );
        builtin.validate_existing_memory(&memory.data[1]);
    }

    #[test]
    fn validate_existing_memory_for_range_check_out_of_bounds_diff_segment() {
        let mut builtin = RangeCheckBuiltinRunner::new(true, bigint!(8), 8);
        builtin.base = Some(relocatable!(1, 0));

        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        for _ in 0..3 {
            segments.add(&mut memory, None);
        }
        memory.insert(
            &MaybeRelocatable::from((2, 0)),
            &MaybeRelocatable::from(bigint!(-45)),
        );
        let vec = builtin.validate_existing_memory(&memory.data[1]);
        assert_eq!(vec, None);
    }

    #[test]
    fn deduce_memory_cell_for_preset_memory_valid() {
        let mut memory = Memory::new();
        let mut builtin = HashBuiltinRunner::new(true, 8);
        memory.data.push(Vec::new());
        memory.insert(
            &MaybeRelocatable::from((0, 3)),
            &MaybeRelocatable::Int(bigint!(32)),
        );
        memory.insert(
            &MaybeRelocatable::from((0, 4)),
            &MaybeRelocatable::Int(bigint!(72)),
        );
        memory.insert(
            &MaybeRelocatable::from((0, 5)),
            &MaybeRelocatable::Int(bigint!(0)),
        );
        let result = builtin.deduce_memory_cell(&MaybeRelocatable::from((0, 5)), &memory);
        assert_eq!(
            result,
            Some(MaybeRelocatable::from(bigint_str!(
                b"3270867057177188607814717243084834301278723532952411121381966378910183338911"
            )))
        );
        assert_eq!(
            builtin.verified_addresses,
            vec![MaybeRelocatable::from((0, 5))]
        );
    }

    #[test]
    fn deduce_memory_cell_for_preset_memory_incorrect_offset() {
        let mut memory = Memory::new();
        let mut builtin = HashBuiltinRunner::new(true, 8);
        memory.data.push(Vec::new());
        memory.insert(
            &MaybeRelocatable::from((0, 4)),
            &MaybeRelocatable::Int(bigint!(32)),
        );
        memory.insert(
            &MaybeRelocatable::from((0, 5)),
            &MaybeRelocatable::Int(bigint!(72)),
        );
        memory.insert(
            &MaybeRelocatable::from((0, 6)),
            &MaybeRelocatable::Int(bigint!(0)),
        );
        let result = builtin.deduce_memory_cell(&MaybeRelocatable::from((0, 6)), &memory);
        assert_eq!(result, None);
    }

    #[test]
    fn deduce_memory_cell_for_preset_memory_no_values_to_hash() {
        let mut memory = Memory::new();
        let mut builtin = HashBuiltinRunner::new(true, 8);
        memory.data.push(Vec::new());
        memory.insert(
            &MaybeRelocatable::from((0, 4)),
            &MaybeRelocatable::Int(bigint!(72)),
        );
        memory.insert(
            &MaybeRelocatable::from((0, 5)),
            &MaybeRelocatable::Int(bigint!(0)),
        );
        let result = builtin.deduce_memory_cell(&MaybeRelocatable::from((0, 5)), &memory);
        assert_eq!(result, None);
    }

    #[test]
    fn deduce_memory_cell_for_preset_memory_already_computed() {
        let mut memory = Memory::new();
        let mut builtin = HashBuiltinRunner::new(true, 8);
        memory.data.push(Vec::new());
        memory.insert(
            &MaybeRelocatable::from((0, 3)),
            &MaybeRelocatable::Int(bigint!(32)),
        );
        memory.insert(
            &MaybeRelocatable::from((0, 4)),
            &MaybeRelocatable::Int(bigint!(72)),
        );
        memory.insert(
            &MaybeRelocatable::from((0, 5)),
            &MaybeRelocatable::Int(bigint!(0)),
        );
        builtin.verified_addresses = vec![MaybeRelocatable::from((0, 5))];
        let result = builtin.deduce_memory_cell(&MaybeRelocatable::from((0, 5)), &memory);
        assert_eq!(result, None);
    }
}
