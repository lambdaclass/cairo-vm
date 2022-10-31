use std::borrow::Cow;
use std::ops::Shl;

use num_bigint::BigInt;
use num_traits::{One, Zero};

use crate::bigint;
use crate::types::instance_definitions::range_check_instance_def::CELLS_PER_RANGE_CHECK;
use crate::types::relocatable::{MaybeRelocatable, Relocatable};
use crate::vm::errors::memory_errors::MemoryError;
use crate::vm::errors::runner_errors::RunnerError;
use crate::vm::vm_memory::memory::{Memory, ValidationRule};
use crate::vm::vm_memory::memory_segments::MemorySegmentManager;

pub struct RangeCheckBuiltinRunner {
    _ratio: u32,
    base: isize,
    stop_ptr: Option<usize>,
    _cells_per_instance: u32,
    _n_input_cells: u32,
    _inner_rc_bound: BigInt,
    pub _bound: BigInt,
    _n_parts: u32,
}

impl RangeCheckBuiltinRunner {
    pub fn new(ratio: u32, n_parts: u32) -> RangeCheckBuiltinRunner {
        let inner_rc_bound = bigint!(1i32 << 16);
        RangeCheckBuiltinRunner {
            _ratio: ratio,
            base: 0,
            stop_ptr: None,
            _cells_per_instance: CELLS_PER_RANGE_CHECK,
            _n_input_cells: CELLS_PER_RANGE_CHECK,
            _inner_rc_bound: inner_rc_bound.clone(),
            _bound: inner_rc_bound.pow(n_parts),
            _n_parts: n_parts,
        }
    }

    pub fn initialize_segments(
        &mut self,
        segments: &mut MemorySegmentManager,
        memory: &mut Memory,
    ) {
        self.base = segments.add(memory).segment_index
    }

    pub fn initial_stack(&self) -> Vec<MaybeRelocatable> {
        vec![MaybeRelocatable::from((self.base, 0))]
    }

    pub fn base(&self) -> isize {
        self.base
    }

    pub fn add_validation_rule(&self, memory: &mut Memory) -> Result<(), RunnerError> {
        let rule: ValidationRule = ValidationRule(Box::new(
            |memory: &Memory,
             address: &MaybeRelocatable|
             -> Result<MaybeRelocatable, MemoryError> {
                match memory.get(address)? {
                    Some(Cow::Owned(MaybeRelocatable::Int(ref num)))
                    | Some(Cow::Borrowed(MaybeRelocatable::Int(ref num))) => {
                        if &BigInt::zero() <= num && num < &BigInt::one().shl(128u8) {
                            Ok(address.to_owned())
                        } else {
                            Err(MemoryError::NumOutOfBounds)
                        }
                    }
                    _ => Err(MemoryError::FoundNonInt),
                }
            },
        ));

        let segment_index: usize = self
            .base
            .try_into()
            .map_err(|_| RunnerError::RunnerInTemporarySegment(self.base))?;

        memory.add_validation_rule(segment_index, rule);

        Ok(())
    }

    pub fn deduce_memory_cell(
        &mut self,
        _address: &Relocatable,
        _memory: &Memory,
    ) -> Result<Option<MaybeRelocatable>, RunnerError> {
        Ok(None)
    }

    pub fn get_memory_segment_addresses(&self) -> (&'static str, (isize, Option<usize>)) {
        ("range_check", (self.base, self.stop_ptr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        utils::test_utils::vm, vm::runners::builtin_runner::BuiltinRunner,
        vm::vm_core::VirtualMachine,
    };
    use num_bigint::Sign;

    #[test]
    fn initialize_segments_for_range_check() {
        let mut builtin = RangeCheckBuiltinRunner::new(8, 8);
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        builtin.initialize_segments(&mut segments, &mut memory);
        assert_eq!(builtin.base, 0);
    }

    #[test]
    fn get_initial_stack_for_range_check_with_base() {
        let mut builtin = RangeCheckBuiltinRunner::new(8, 8);
        builtin.base = 1;
        let initial_stack = builtin.initial_stack();
        assert_eq!(
            initial_stack[0].clone(),
            MaybeRelocatable::RelocatableValue((builtin.base(), 0).into())
        );
        assert_eq!(initial_stack.len(), 1);
    }

    #[test]
    fn get_memory_segment_addresses() {
        let builtin = RangeCheckBuiltinRunner::new(8, 8);

        assert_eq!(
            builtin.get_memory_segment_addresses(),
            ("range_check", (0, None)),
        );
    }

    #[test]
    fn get_memory_accesses_missing_segment_used_sizes() {
        let builtin = BuiltinRunner::RangeCheck(RangeCheckBuiltinRunner::new(256, 8));
        let vm = vm!();

        assert_eq!(
            builtin.get_memory_accesses(&vm),
            Err(MemoryError::MissingSegmentUsedSizes),
        );
    }

    #[test]
    fn get_memory_accesses_empty() {
        let builtin = BuiltinRunner::RangeCheck(RangeCheckBuiltinRunner::new(256, 8));
        let mut vm = vm!();

        vm.segments.segment_used_sizes = Some(vec![0]);
        assert_eq!(builtin.get_memory_accesses(&vm), Ok(vec![]));
    }

    #[test]
    fn get_memory_accesses() {
        let builtin = BuiltinRunner::RangeCheck(RangeCheckBuiltinRunner::new(256, 8));
        let mut vm = vm!();

        vm.segments.segment_used_sizes = Some(vec![4]);
        assert_eq!(
            builtin.get_memory_accesses(&vm),
            Ok(vec![
                (builtin.base(), 0).into(),
                (builtin.base(), 1).into(),
                (builtin.base(), 2).into(),
                (builtin.base(), 3).into(),
            ]),
        );
    }
}
