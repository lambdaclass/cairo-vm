use std::ops::Shl;

use num_bigint::BigInt;
use num_integer::Integer;

use crate::bigint;
use crate::types::relocatable::{MaybeRelocatable, Relocatable};
use crate::vm::errors::runner_errors::RunnerError;
use crate::vm::vm_memory::memory::Memory;
use crate::vm::vm_memory::memory_segments::MemorySegmentManager;

pub struct BitwiseBuiltinRunner {
    _ratio: usize,
    pub base: isize,
    stop_ptr: Option<usize>,
    pub(crate) cells_per_instance: usize,
    _n_input_cells: usize,
    total_n_bits: u32,
}

impl BitwiseBuiltinRunner {
    pub fn new(ratio: usize) -> Self {
        BitwiseBuiltinRunner {
            base: 0,
            stop_ptr: None,

            _ratio: ratio,
            cells_per_instance: 5,
            _n_input_cells: 2,
            total_n_bits: 251,
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

    pub fn add_validation_rule(&self, _memory: &mut Memory) -> Result<(), RunnerError> {
        Ok(())
    }

    pub fn deduce_memory_cell(
        &mut self,
        address: &Relocatable,
        memory: &Memory,
    ) -> Result<Option<MaybeRelocatable>, RunnerError> {
        let index = address.offset.mod_floor(&self.cells_per_instance);
        if index == 0 || index == 1 {
            return Ok(None);
        }
        let x_addr = MaybeRelocatable::from((address.segment_index, address.offset - index));
        let y_addr = x_addr.add_usize_mod(1, None);

        let num_x = memory.get(&x_addr);
        let num_y = memory.get(&y_addr);
        if let (Ok(Some(MaybeRelocatable::Int(num_x))), Ok(Some(MaybeRelocatable::Int(num_y)))) = (
            num_x.as_ref().map(|x| x.as_ref().map(|x| x.as_ref())),
            num_y.as_ref().map(|x| x.as_ref().map(|x| x.as_ref())),
        ) {
            let _2_pow_bits = bigint!(1).shl(self.total_n_bits);
            if num_x >= &_2_pow_bits {
                return Err(RunnerError::IntegerBiggerThanPowerOfTwo(
                    x_addr,
                    self.total_n_bits,
                    num_x.clone(),
                ));
            };
            if num_y >= &_2_pow_bits {
                return Err(RunnerError::IntegerBiggerThanPowerOfTwo(
                    y_addr,
                    self.total_n_bits,
                    num_y.clone(),
                ));
            };
            let res = match index {
                2 => Some(MaybeRelocatable::from(num_x & num_y)),
                3 => Some(MaybeRelocatable::from(num_x ^ num_y)),
                4 => Some(MaybeRelocatable::from(num_x | num_y)),
                _ => None,
            };
            return Ok(res);
        }
        Ok(None)
    }

    pub fn get_memory_segment_addresses(&self) -> (&'static str, (isize, Option<usize>)) {
        ("bitwise", (self.base, self.stop_ptr))
    }

    pub fn get_used_diluted_check_units(&self, diluted_spacing: u32, diluted_n_bits: u32) -> usize {
        let total_n_bits = self.total_n_bits;
        let mut partition = Vec::with_capacity(total_n_bits as usize);
        for i in (0..total_n_bits).step_by((diluted_spacing * diluted_n_bits) as usize) {
            for j in 0..diluted_spacing {
                if i + j < total_n_bits {
                    partition.push(i + j)
                };
            }
        }
        let partition_lengh = partition.len();
        let num_trimmed = partition
            .into_iter()
            .filter(|elem| elem + diluted_spacing * (diluted_n_bits - 1) + 1 > total_n_bits)
            .count();
        4 * partition_lengh + num_trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::*;
    use crate::vm::{
        errors::memory_errors::MemoryError, runners::builtin_runner::BuiltinRunner,
        vm_core::VirtualMachine,
    };
    use num_bigint::Sign;

    #[test]
    fn deduce_memory_cell_bitwise_for_preset_memory_valid_and() {
        let memory = memory![((0, 5), 10), ((0, 6), 12), ((0, 7), 0)];
        let mut builtin = BitwiseBuiltinRunner::new(256);
        let result = builtin.deduce_memory_cell(&Relocatable::from((0, 7)), &memory);
        assert_eq!(result, Ok(Some(MaybeRelocatable::from(bigint!(8)))));
    }

    #[test]
    fn deduce_memory_cell_bitwise_for_preset_memory_valid_xor() {
        let memory = memory![((0, 5), 10), ((0, 6), 12), ((0, 8), 0)];
        let mut builtin = BitwiseBuiltinRunner::new(256);
        let result = builtin.deduce_memory_cell(&Relocatable::from((0, 8)), &memory);
        assert_eq!(result, Ok(Some(MaybeRelocatable::from(bigint!(6)))));
    }

    #[test]
    fn deduce_memory_cell_bitwise_for_preset_memory_valid_or() {
        let memory = memory![((0, 5), 10), ((0, 6), 12), ((0, 9), 0)];
        let mut builtin = BitwiseBuiltinRunner::new(256);
        let result = builtin.deduce_memory_cell(&Relocatable::from((0, 9)), &memory);
        assert_eq!(result, Ok(Some(MaybeRelocatable::from(bigint!(14)))));
    }

    #[test]
    fn deduce_memory_cell_bitwise_for_preset_memory_incorrect_offset() {
        let memory = memory![((0, 3), 10), ((0, 4), 12), ((0, 5), 0)];
        let mut builtin = BitwiseBuiltinRunner::new(256);
        let result = builtin.deduce_memory_cell(&Relocatable::from((0, 5)), &memory);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn deduce_memory_cell_bitwise_for_preset_memory_no_values_to_operate() {
        let memory = memory![((0, 5), 12), ((0, 7), 0)];
        let mut builtin = BitwiseBuiltinRunner::new(256);
        let result = builtin.deduce_memory_cell(&Relocatable::from((0, 5)), &memory);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn get_memory_segment_addresses() {
        let builtin = BitwiseBuiltinRunner::new(256);

        assert_eq!(
            builtin.get_memory_segment_addresses(),
            ("bitwise", (0, None)),
        );
    }

    #[test]
    fn get_memory_accesses_missing_segment_used_sizes() {
        let builtin = BuiltinRunner::Bitwise(BitwiseBuiltinRunner::new(256));
        let vm = vm!();

        assert_eq!(
            builtin.get_memory_accesses(&vm),
            Err(MemoryError::MissingSegmentUsedSizes),
        );
    }

    #[test]
    fn get_memory_accesses_empty() {
        let builtin = BuiltinRunner::Bitwise(BitwiseBuiltinRunner::new(256));
        let mut vm = vm!();

        vm.segments.segment_used_sizes = Some(vec![0]);
        assert_eq!(builtin.get_memory_accesses(&vm), Ok(vec![]));
    }

    #[test]
    fn get_memory_accesses() {
        let builtin = BuiltinRunner::Bitwise(BitwiseBuiltinRunner::new(256));
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
        let builtin = BuiltinRunner::Bitwise(BitwiseBuiltinRunner::new(256));
        let vm = vm!();

        assert_eq!(
            builtin.get_used_cells(&vm),
            Err(MemoryError::MissingSegmentUsedSizes)
        );
    }

    #[test]
    fn get_used_cells_empty() {
        let builtin = BuiltinRunner::Bitwise(BitwiseBuiltinRunner::new(256));
        let mut vm = vm!();

        vm.segments.segment_used_sizes = Some(vec![0]);
        assert_eq!(builtin.get_used_cells(&vm), Ok(0));
    }

    #[test]
    fn get_used_cells() {
        let builtin = BuiltinRunner::Bitwise(BitwiseBuiltinRunner::new(256));
        let mut vm = vm!();

        vm.segments.segment_used_sizes = Some(vec![4]);
        assert_eq!(builtin.get_used_cells(&vm), Ok(4));
    }

    #[test]
    fn get_used_diluted_check_units_a() {
        let builtin = BuiltinRunner::Bitwise(BitwiseBuiltinRunner::new(256));
        assert_eq!(builtin.get_used_diluted_check_units(12, 2), 535);
    }

    #[test]
    fn get_used_diluted_check_units_b() {
        let builtin = BuiltinRunner::Bitwise(BitwiseBuiltinRunner::new(256));
        assert_eq!(builtin.get_used_diluted_check_units(30, 56), 150);
    }

    #[test]
    fn get_used_diluted_check_units_c() {
        let builtin = BuiltinRunner::Bitwise(BitwiseBuiltinRunner::new(256));
        assert_eq!(builtin.get_used_diluted_check_units(50, 25), 250);
    }
}
