use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};
use std::borrow::Cow;
use std::cmp::{max, min};
use std::ops::Shl;

use crate::bigint;
use crate::math_utils::safe_div;
use crate::types::instance_definitions::range_check_instance_def::CELLS_PER_RANGE_CHECK;
use crate::types::relocatable::{MaybeRelocatable, Relocatable};
use crate::vm::errors::memory_errors::MemoryError;
use crate::vm::errors::runner_errors::RunnerError;
use crate::vm::vm_core::VirtualMachine;
use crate::vm::vm_memory::memory::{Memory, ValidationRule};
use crate::vm::vm_memory::memory_segments::MemorySegmentManager;

pub struct RangeCheckBuiltinRunner {
    ratio: u32,
    base: isize,
    stop_ptr: Option<usize>,
    pub(crate) cells_per_instance: u32,
    pub(crate) n_input_cells: u32,
    inner_rc_bound: usize,
    pub _bound: BigInt,
    n_parts: u32,
    instances_per_component: u32,
}

impl RangeCheckBuiltinRunner {
    pub fn new(ratio: u32, n_parts: u32) -> RangeCheckBuiltinRunner {
        let inner_rc_bound = 1usize << 16;
        RangeCheckBuiltinRunner {
            ratio,
            base: 0,
            stop_ptr: None,
            cells_per_instance: CELLS_PER_RANGE_CHECK,
            n_input_cells: CELLS_PER_RANGE_CHECK,
            inner_rc_bound,
            _bound: bigint!(inner_rc_bound).pow(n_parts),
            n_parts,
            instances_per_component: 1,
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

    pub fn get_allocated_memory_units(&self, vm: &VirtualMachine) -> Result<usize, MemoryError> {
        let value = safe_div(&bigint!(vm.current_step), &bigint!(self.ratio))
            .map_err(|_| MemoryError::ErrorCalculatingMemoryUnits)?;
        match (self.cells_per_instance * value).to_usize() {
            Some(result) => Ok(result),
            _ => Err(MemoryError::ErrorCalculatingMemoryUnits),
        }
    }

    pub fn get_memory_segment_addresses(&self) -> (&'static str, (isize, Option<usize>)) {
        ("range_check", (self.base, self.stop_ptr))
    }

    pub fn get_used_cells(&self, vm: &VirtualMachine) -> Result<usize, MemoryError> {
        let base = self.base();
        vm.segments
            .get_segment_used_size(
                base.try_into()
                    .map_err(|_| MemoryError::AddressInTemporarySegment(base))?,
            )
            .ok_or(MemoryError::MissingSegmentUsedSizes)
    }

    pub fn get_used_cells_and_allocated_size(
        &self,
        vm: &VirtualMachine,
    ) -> Result<(usize, BigInt), MemoryError> {
        let ratio = self.ratio as usize;
        let cells_per_instance = self.cells_per_instance;
        let min_step = ratio * self.instances_per_component as usize;
        if vm.current_step < min_step {
            Err(MemoryError::InsufficientAllocatedCells)
        } else {
            let used = self.get_used_cells(vm)?;
            let size = cells_per_instance
                * safe_div(&bigint!(vm.current_step), &bigint!(ratio))
                    .map_err(|_| MemoryError::InsufficientAllocatedCells)?;
            Ok((used, size))
        }
    }

    pub fn get_range_check_usage(&self, memory: &Memory) -> Option<(usize, usize)> {
        let mut rc_bounds: Option<(usize, usize)> = None;
        let range_check_segment = memory.data.get(self.base as usize)?;
        let inner_rc_bound = bigint!(self.inner_rc_bound);
        for value in range_check_segment {
            //Split val into n_parts parts.
            for _ in 0..self.n_parts {
                let part_val = value
                    .as_ref()?
                    .get_int_ref()
                    .ok()?
                    .mod_floor(&inner_rc_bound)
                    .to_usize()?;
                rc_bounds = Some(match rc_bounds {
                    None => (part_val, part_val),
                    Some((rc_min, rc_max)) => {
                        let rc_min = min(rc_min, part_val);
                        let rc_max = max(rc_max, part_val);

                        (rc_min, rc_max)
                    }
                });
            }
        }
        rc_bounds
    }

    /// Returns the number of range check units used by the builtin.
    pub fn get_used_perm_range_check_units(
        &self,
        vm: &VirtualMachine,
    ) -> Result<usize, MemoryError> {
        let (used_cells, _) = self.get_used_cells_and_allocated_size(vm)?;
        Ok(used_cells * self.n_parts as usize)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
    use crate::serde::deserialize_program::ReferenceManager;
    use crate::types::program::Program;
    use crate::vm::runners::cairo_runner::CairoRunner;
    use crate::{bigint, utils::test_utils::*};
    use crate::{
        utils::test_utils::vm, vm::runners::builtin_runner::BuiltinRunner,
        vm::vm_core::VirtualMachine,
    };
    use num_bigint::Sign;

    #[test]
    fn get_used_cells_and_allocated_size_test() {
        let builtin = RangeCheckBuiltinRunner::new(10, 12);

        let mut vm = vm!();

        vm.segments.segment_used_sizes = Some(vec![0]);

        let program = Program {
            builtins: vec![String::from("pedersen")],
            prime: bigint!(17),
            data: vec_data!(
                (4612671182993129469_i64),
                (5189976364521848832_i64),
                (18446744073709551615_i128),
                (5199546496550207487_i64),
                (4612389712311386111_i64),
                (5198983563776393216_i64),
                (2),
                (2345108766317314046_i64),
                (5191102247248822272_i64),
                (5189976364521848832_i64),
                (7),
                (1226245742482522112_i64),
                ((
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020470",
                    10
                )),
                (2345108766317314046_i64)
            ),
            constants: HashMap::new(),
            main: Some(8),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let mut cairo_runner = CairoRunner::new(&program, &"all".to_string()).unwrap();

        let hint_processor = BuiltinHintProcessor::new_empty();

        let address = cairo_runner.initialize(&mut vm).unwrap();

        cairo_runner
            .run_until_pc(address, &mut vm, &hint_processor)
            .unwrap();

        assert_eq!(
            builtin.get_used_cells_and_allocated_size(&vm),
            Ok((0, bigint!(1)))
        );
    }

    #[test]
    fn get_allocated_memory_units() {
        let builtin = RangeCheckBuiltinRunner::new(10, 12);

        let mut vm = vm!();

        let program = Program {
            builtins: vec![String::from("pedersen")],
            prime: bigint!(17),
            data: vec_data!(
                (4612671182993129469_i64),
                (5189976364521848832_i64),
                (18446744073709551615_i128),
                (5199546496550207487_i64),
                (4612389712311386111_i64),
                (5198983563776393216_i64),
                (2),
                (2345108766317314046_i64),
                (5191102247248822272_i64),
                (5189976364521848832_i64),
                (7),
                (1226245742482522112_i64),
                ((
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020470",
                    10
                )),
                (2345108766317314046_i64)
            ),
            constants: HashMap::new(),
            main: Some(8),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let mut cairo_runner = cairo_runner!(program);

        let hint_processor = BuiltinHintProcessor::new_empty();

        let address = cairo_runner.initialize(&mut vm).unwrap();

        cairo_runner
            .run_until_pc(address, &mut vm, &hint_processor)
            .unwrap();

        assert_eq!(builtin.get_allocated_memory_units(&vm), Ok(1));
    }

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

    #[test]
    fn get_used_cells_missing_segment_used_sizes() {
        let builtin = BuiltinRunner::RangeCheck(RangeCheckBuiltinRunner::new(256, 8));
        let vm = vm!();

        assert_eq!(
            builtin.get_used_cells(&vm),
            Err(MemoryError::MissingSegmentUsedSizes)
        );
    }

    #[test]
    fn get_used_cells_empty() {
        let builtin = BuiltinRunner::RangeCheck(RangeCheckBuiltinRunner::new(256, 8));
        let mut vm = vm!();

        vm.segments.segment_used_sizes = Some(vec![0]);
        assert_eq!(builtin.get_used_cells(&vm), Ok(0));
    }

    #[test]
    fn get_used_cells() {
        let builtin = BuiltinRunner::RangeCheck(RangeCheckBuiltinRunner::new(256, 8));
        let mut vm = vm!();

        vm.segments.segment_used_sizes = Some(vec![4]);
        assert_eq!(builtin.get_used_cells(&vm), Ok(4));
    }

    #[test]
    fn get_range_check_usage_succesful_a() {
        let builtin = RangeCheckBuiltinRunner::new(8, 8);
        let memory = memory![((0, 0), 1), ((0, 1), 2), ((0, 2), 3), ((0, 3), 4)];
        assert_eq!(builtin.get_range_check_usage(&memory), Some((1, 4)));
    }

    #[test]
    fn get_range_check_usage_succesful_b() {
        let builtin = RangeCheckBuiltinRunner::new(8, 8);
        let memory = memory![
            ((0, 0), 1465218365),
            ((0, 1), 2134570341),
            ((0, 2), 31349610736_i64),
            ((0, 3), 413468326585859_i64)
        ];
        assert_eq!(builtin.get_range_check_usage(&memory), Some((6384, 62821)));
    }

    #[test]
    fn get_range_check_usage_succesful_c() {
        let builtin = RangeCheckBuiltinRunner::new(8, 8);
        let memory = memory![
            ((0, 0), 634834751465218365_i64),
            ((0, 1), 42876922134570341_i64),
            ((0, 2), 23469831349610736_i64),
            ((0, 3), 23468413468326585859_i128),
            ((0, 4), 75346043276073460326_i128),
            ((0, 5), 87234598724867609478353436890268_i128)
        ];
        assert_eq!(builtin.get_range_check_usage(&memory), Some((10480, 42341)));
    }

    #[test]
    fn get_range_check_empty_memory() {
        let builtin = RangeCheckBuiltinRunner::new(8, 8);
        let memory = Memory::new();
        assert_eq!(builtin.get_range_check_usage(&memory), None);
    }

    /// Test that the method get_used_perm_range_check_units works as intended.
    #[test]
    fn get_used_perm_range_check_units() {
        let builtin_runner = RangeCheckBuiltinRunner::new(8, 8);
        let mut vm = vm!();

        vm.current_step = 8;
        vm.segments.segment_used_sizes = Some(vec![5]);
        assert_eq!(builtin_runner.get_used_perm_range_check_units(&vm), Ok(40));
    }
}
