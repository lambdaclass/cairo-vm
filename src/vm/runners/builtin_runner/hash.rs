use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_traits::ToPrimitive;
use starknet_crypto::{pedersen_hash, FieldElement};

use crate::bigint;
use crate::math_utils::safe_div;
use crate::types::instance_definitions::pedersen_instance_def::{
    CELLS_PER_HASH, INPUT_CELLS_PER_HASH,
};
use crate::types::relocatable::{MaybeRelocatable, Relocatable};
use crate::vm::errors::memory_errors::MemoryError;
use crate::vm::errors::runner_errors::RunnerError;
use crate::vm::vm_core::VirtualMachine;
use crate::vm::vm_memory::memory::Memory;
use crate::vm::vm_memory::memory_segments::MemorySegmentManager;

#[derive(Debug)]
pub struct HashBuiltinRunner {
    pub base: isize,
    _ratio: u32,
    pub(crate) cells_per_instance: u32,
    pub(crate) n_input_cells: u32,
    stop_ptr: Option<usize>,
    verified_addresses: Vec<Relocatable>,
    pub(crate) _included: bool,
    instances_per_component: u32,
}

impl HashBuiltinRunner {
    pub fn new(ratio: u32, included: bool) -> Self {
        HashBuiltinRunner {
            base: 0,
            _ratio: ratio,
            cells_per_instance: CELLS_PER_HASH,
            n_input_cells: INPUT_CELLS_PER_HASH,
            stop_ptr: None,
            verified_addresses: Vec::new(),
            _included: included,
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
        if self._included {
            vec![MaybeRelocatable::from((self.base, 0))]
        } else {
            vec![]
        }
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
        if address
            .offset
            .mod_floor(&(self.cells_per_instance as usize))
            != 2
            || self.verified_addresses.contains(address)
        {
            return Ok(None);
        };

        let num_a = memory.get(&MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: address.segment_index,
            offset: address.offset - 1,
        }));
        let num_b = memory.get(&MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: address.segment_index,
            offset: address.offset - 2,
        }));
        if let (Ok(Some(MaybeRelocatable::Int(num_a))), Ok(Some(MaybeRelocatable::Int(num_b)))) = (
            num_a.as_ref().map(|x| x.as_ref().map(|x| x.as_ref())),
            num_b.as_ref().map(|x| x.as_ref().map(|x| x.as_ref())),
        ) {
            self.verified_addresses.push(address.clone());

            //Convert MaybeRelocatable to FieldElement
            let a_string = num_a.to_str_radix(10);
            let b_string = num_b.to_str_radix(10);
            let (y, x) = match (
                FieldElement::from_dec_str(&a_string),
                FieldElement::from_dec_str(&b_string),
            ) {
                (Ok(field_element_a), Ok(field_element_b)) => (field_element_a, field_element_b),
                _ => return Err(RunnerError::FailedStringConversion),
            };
            //Compute pedersen Hash
            let fe_result = pedersen_hash(&x, &y);
            //Convert result from FieldElement to MaybeRelocatable
            let r_byte_slice = fe_result.to_bytes_be();
            let result = BigInt::from_bytes_be(Sign::Plus, &r_byte_slice);
            return Ok(Some(MaybeRelocatable::from(result)));
        }
        Ok(None)
    }

    pub fn get_allocated_memory_units(&self, vm: &VirtualMachine) -> Result<usize, MemoryError> {
        let value = safe_div(&bigint!(vm.current_step), &bigint!(self._ratio))
            .map_err(|_| MemoryError::ErrorCalculatingMemoryUnits)?;
        match (self.cells_per_instance * value).to_usize() {
            Some(result) => Ok(result),
            _ => Err(MemoryError::ErrorCalculatingMemoryUnits),
        }
    }

    pub fn get_memory_segment_addresses(&self) -> (&'static str, (isize, Option<usize>)) {
        ("pedersen", (self.base, self.stop_ptr))
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
    ) -> Result<(usize, usize), MemoryError> {
        let ratio = self._ratio as usize;
        let cells_per_instance = self.cells_per_instance;
        let min_step = ratio * self.instances_per_component as usize;
        if vm.current_step < min_step {
            Err(MemoryError::InsufficientAllocatedCells)
        } else {
            let used = self.get_used_cells(vm)?;
            let size = (cells_per_instance
                * safe_div(&bigint!(vm.current_step), &bigint!(ratio))
                    .map_err(|_| MemoryError::InsufficientAllocatedCells)?)
            .to_usize()
            .ok_or(MemoryError::InsufficientAllocatedCells)?;
            Ok((used, size))
        }
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
    use crate::vm::{
        errors::memory_errors::MemoryError, runners::builtin_runner::BuiltinRunner,
        vm_core::VirtualMachine,
    };
    use crate::{bigint, bigint_str, utils::test_utils::*};
    use num_bigint::Sign;

    #[test]
    fn get_used_cells_and_allocated_size_test() {
        let builtin = HashBuiltinRunner::new(10, true);

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

        let mut cairo_runner = cairo_runner!(program);

        let hint_processor = BuiltinHintProcessor::new_empty();

        let address = cairo_runner.initialize(&mut vm).unwrap();

        cairo_runner
            .run_until_pc(address, &mut vm, &hint_processor)
            .unwrap();

        assert_eq!(
            builtin.get_used_cells_and_allocated_size(&vm),
            Ok((0_usize, 3))
        );
    }

    #[test]
    fn get_allocated_memory_units() {
        let builtin = HashBuiltinRunner::new(10, true);

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

        assert_eq!(builtin.get_allocated_memory_units(&vm), Ok(3));
    }

    #[test]
    fn deduce_memory_cell_pedersen_for_preset_memory_valid() {
        let memory = memory![((0, 3), 32), ((0, 4), 72), ((0, 5), 0)];
        let mut builtin = HashBuiltinRunner::new(8, true);

        let result = builtin.deduce_memory_cell(&Relocatable::from((0, 5)), &memory);
        assert_eq!(
            result,
            Ok(Some(MaybeRelocatable::from(bigint_str!(
                b"3270867057177188607814717243084834301278723532952411121381966378910183338911"
            ))))
        );
        assert_eq!(builtin.verified_addresses, vec![Relocatable::from((0, 5))]);
    }

    #[test]
    fn deduce_memory_cell_pedersen_for_preset_memory_incorrect_offset() {
        let memory = memory![((0, 4), 32), ((0, 5), 72), ((0, 6), 0)];
        let mut builtin = HashBuiltinRunner::new(8, true);
        let result = builtin.deduce_memory_cell(&Relocatable::from((0, 6)), &memory);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn deduce_memory_cell_pedersen_for_preset_memory_no_values_to_hash() {
        let memory = memory![((0, 4), 72), ((0, 5), 0)];
        let mut builtin = HashBuiltinRunner::new(8, true);
        let result = builtin.deduce_memory_cell(&Relocatable::from((0, 5)), &memory);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn deduce_memory_cell_pedersen_for_preset_memory_already_computed() {
        let memory = memory![((0, 3), 32), ((0, 4), 72), ((0, 5), 0)];
        let mut builtin = HashBuiltinRunner::new(8, true);
        builtin.verified_addresses = vec![Relocatable::from((0, 5))];
        let result = builtin.deduce_memory_cell(&Relocatable::from((0, 5)), &memory);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn get_memory_segment_addresses() {
        let builtin = HashBuiltinRunner::new(256, true);

        assert_eq!(
            builtin.get_memory_segment_addresses(),
            ("pedersen", (0, None)),
        );
    }

    #[test]
    fn get_memory_accesses_missing_segment_used_sizes() {
        let builtin = BuiltinRunner::Hash(HashBuiltinRunner::new(256, true));
        let vm = vm!();

        assert_eq!(
            builtin.get_memory_accesses(&vm),
            Err(MemoryError::MissingSegmentUsedSizes),
        );
    }

    #[test]
    fn get_memory_accesses_empty() {
        let builtin = BuiltinRunner::Hash(HashBuiltinRunner::new(256, true));
        let mut vm = vm!();

        vm.segments.segment_used_sizes = Some(vec![0]);
        assert_eq!(builtin.get_memory_accesses(&vm), Ok(vec![]));
    }

    #[test]
    fn get_memory_accesses() {
        let builtin = BuiltinRunner::Hash(HashBuiltinRunner::new(256, true));
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
        let builtin = BuiltinRunner::Hash(HashBuiltinRunner::new(256, true));
        let vm = vm!();

        assert_eq!(
            builtin.get_used_cells(&vm),
            Err(MemoryError::MissingSegmentUsedSizes)
        );
    }

    #[test]
    fn get_used_cells_empty() {
        let builtin = BuiltinRunner::Hash(HashBuiltinRunner::new(256, true));
        let mut vm = vm!();

        vm.segments.segment_used_sizes = Some(vec![0]);
        assert_eq!(builtin.get_used_cells(&vm), Ok(0));
    }

    #[test]
    fn get_used_cells() {
        let builtin = BuiltinRunner::Hash(HashBuiltinRunner::new(256, true));
        let mut vm = vm!();

        vm.segments.segment_used_sizes = Some(vec![4]);
        assert_eq!(builtin.get_used_cells(&vm), Ok(4));
    }
}
