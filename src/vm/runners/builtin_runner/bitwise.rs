use std::any::Any;
use std::ops::Shl;

use nom::ToUsize;
use num_bigint::BigInt;
use num_integer::Integer;

use crate::bigint;
use crate::types::instance_definitions::bitwise_instance_def::{
    BitwiseInstanceDef, CELLS_PER_BITWISE, INPUT_CELLS_PER_BITWISE,
};
use crate::types::relocatable::{MaybeRelocatable, Relocatable};
use crate::vm::errors::runner_errors::RunnerError;
use crate::vm::runners::builtin_runner::BuiltinRunner;
use crate::vm::vm_memory::memory::Memory;
use crate::vm::vm_memory::memory_segments::MemorySegmentManager;

pub struct BitwiseBuiltinRunner {
    _ratio: u32,
    pub base: isize,
    cells_per_instance: u32,
    _n_input_cells: u32,
    bitwise_builtin: BitwiseInstanceDef,
}

impl BitwiseBuiltinRunner {
    pub(crate) fn new(instance_def: &BitwiseInstanceDef) -> Self {
        BitwiseBuiltinRunner {
            base: 0,
            _ratio: instance_def.ratio,
            cells_per_instance: CELLS_PER_BITWISE,
            _n_input_cells: INPUT_CELLS_PER_BITWISE,
            bitwise_builtin: instance_def.clone(),
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

    fn add_validation_rule(&self, _memory: &mut Memory) -> Result<(), RunnerError> {
        Ok(())
    }

    fn deduce_memory_cell(
        &mut self,
        address: &Relocatable,
        memory: &Memory,
    ) -> Result<Option<MaybeRelocatable>, RunnerError> {
        let index = address
            .offset
            .mod_floor(&self.cells_per_instance.to_usize());
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
            let _2_pow_bits = bigint!(1).shl(self.bitwise_builtin.total_n_bits);
            if num_x >= &_2_pow_bits {
                return Err(RunnerError::IntegerBiggerThanPowerOfTwo(
                    x_addr,
                    self.bitwise_builtin.total_n_bits,
                    num_x.clone(),
                ));
            };
            if num_y >= &_2_pow_bits {
                return Err(RunnerError::IntegerBiggerThanPowerOfTwo(
                    y_addr,
                    self.bitwise_builtin.total_n_bits,
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
        let mut builtin = BitwiseBuiltinRunner::new(&BitwiseInstanceDef::default());
        let result = builtin.deduce_memory_cell(&Relocatable::from((0, 7)), &memory);
        assert_eq!(result, Ok(Some(MaybeRelocatable::from(bigint!(8)))));
    }

    #[test]
    fn deduce_memory_cell_bitwise_for_preset_memory_valid_xor() {
        let memory = memory![((0, 5), 10), ((0, 6), 12), ((0, 8), 0)];
        let mut builtin = BitwiseBuiltinRunner::new(&BitwiseInstanceDef::default());
        let result = builtin.deduce_memory_cell(&Relocatable::from((0, 8)), &memory);
        assert_eq!(result, Ok(Some(MaybeRelocatable::from(bigint!(6)))));
    }

    #[test]
    fn deduce_memory_cell_bitwise_for_preset_memory_valid_or() {
        let memory = memory![((0, 5), 10), ((0, 6), 12), ((0, 9), 0)];
        let mut builtin = BitwiseBuiltinRunner::new(&BitwiseInstanceDef::default());
        let result = builtin.deduce_memory_cell(&Relocatable::from((0, 9)), &memory);
        assert_eq!(result, Ok(Some(MaybeRelocatable::from(bigint!(14)))));
    }

    #[test]
    fn deduce_memory_cell_bitwise_for_preset_memory_incorrect_offset() {
        let memory = memory![((0, 3), 10), ((0, 4), 12), ((0, 5), 0)];
        let mut builtin = BitwiseBuiltinRunner::new(&BitwiseInstanceDef::default());
        let result = builtin.deduce_memory_cell(&Relocatable::from((0, 5)), &memory);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn deduce_memory_cell_bitwise_for_preset_memory_no_values_to_operate() {
        let memory = memory![((0, 5), 12), ((0, 7), 0)];
        let mut builtin = BitwiseBuiltinRunner::new(&BitwiseInstanceDef::default());
        let result = builtin.deduce_memory_cell(&Relocatable::from((0, 5)), &memory);
        assert_eq!(result, Ok(None));
    }
}
