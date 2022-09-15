use std::any::Any;
use std::ops::Shl;

use num_bigint::BigInt;
use num_integer::Integer;

use crate::bigint;
use crate::types::relocatable::{FieldElement, MaybeRelocatable, Relocatable};
use crate::vm::errors::runner_errors::RunnerError;
use crate::vm::runners::builtin_runner::BuiltinRunner;
use crate::vm::vm_memory::memory::Memory;
use crate::vm::vm_memory::memory_segments::MemorySegmentManager;

pub struct BitwiseBuiltinRunner {
    _ratio: usize,
    pub base: usize,
    cells_per_instance: usize,
    _n_input_cells: usize,
    total_n_bits: u32,
}

impl BitwiseBuiltinRunner {
    pub fn new(ratio: usize) -> Self {
        BitwiseBuiltinRunner {
            base: 0,

            _ratio: ratio,
            cells_per_instance: 5,
            _n_input_cells: 2,
            total_n_bits: 251,
        }
    }
}

impl BuiltinRunner for BitwiseBuiltinRunner {
    fn initialize_segments(&mut self, segments: &mut MemorySegmentManager, memory: &mut Memory) {
        self.base = segments.add(memory).segment_index
    }

    fn initial_stack(&self) -> Vec<MaybeRelocatable> {
        vec![MaybeRelocatable::from((self.base, 0))]
    }

    fn base(&self) -> Relocatable {
        Relocatable::from((self.base, 0))
    }

    fn add_validation_rule(&self, _memory: &mut Memory) {}

    fn deduce_memory_cell(
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
        if let (
            Ok(Some(MaybeRelocatable::Int(FieldElement { num: num_x }))),
            Ok(Some(MaybeRelocatable::Int(FieldElement { num: num_y }))),
        ) = (memory.get(&x_addr), memory.get(&y_addr))
        {
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

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::*;
    use crate::vm::errors::memory_errors::MemoryError;

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
}
