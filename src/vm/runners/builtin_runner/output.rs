use crate::types::relocatable::{MaybeRelocatable, Relocatable};
use crate::vm::errors::memory_errors::MemoryError;
use crate::vm::errors::runner_errors::RunnerError;
use crate::vm::vm_core::VirtualMachine;
use crate::vm::vm_memory::memory::Memory;
use crate::vm::vm_memory::memory_segments::MemorySegmentManager;

pub struct OutputBuiltinRunner {
    base: isize,
    stop_ptr: Option<usize>,
}

impl OutputBuiltinRunner {
    pub fn new() -> OutputBuiltinRunner {
        OutputBuiltinRunner {
            base: 0,
            stop_ptr: None,
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
        _address: &Relocatable,
        _memory: &Memory,
    ) -> Result<Option<MaybeRelocatable>, RunnerError> {
        Ok(None)
    }

    pub fn get_allocated_memory_units(&self, _vm: &VirtualMachine) -> Result<usize, MemoryError> {
        Ok(0)
    }

    pub fn get_memory_segment_addresses(&self) -> (&'static str, (isize, Option<usize>)) {
        ("output", (self.base, self.stop_ptr))
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
        let used = self.get_used_cells(vm)?;
        Ok((used, used))
    }
}

impl Default for OutputBuiltinRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        utils::test_utils::vm,
        vm::{
            errors::memory_errors::MemoryError, runners::builtin_runner::BuiltinRunner,
            vm_core::VirtualMachine,
        },
    };
    use num_bigint::{BigInt, Sign};

    #[test]
    fn get_used_cells_and_allocated_size_test() {
        let builtin = OutputBuiltinRunner::new();

        let mut vm = vm!();

        vm.segments.segment_used_sizes = Some(vec![0]);

        assert_eq!(
            builtin.get_used_cells_and_allocated_size(&vm),
            Ok((0_usize, 0))
        );
    }

    #[test]
    fn get_allocated_memory_units() {
        let builtin = OutputBuiltinRunner::new();

        let vm = vm!();

        assert_eq!(builtin.get_allocated_memory_units(&vm), Ok(0));
    }

    #[test]
    fn initialize_segments_for_output() {
        let mut builtin = OutputBuiltinRunner::new();
        let mut segments = MemorySegmentManager::new();
        let mut memory = Memory::new();
        builtin.initialize_segments(&mut segments, &mut memory);
        assert_eq!(builtin.base, 0);
    }

    #[test]
    fn get_initial_stack_for_output_with_base() {
        let mut builtin = OutputBuiltinRunner::new();
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
        let builtin = OutputBuiltinRunner::new();

        assert_eq!(
            builtin.get_memory_segment_addresses(),
            ("output", (0, None)),
        );
    }

    #[test]
    fn get_memory_accesses_missing_segment_used_sizes() {
        let builtin = BuiltinRunner::Output(OutputBuiltinRunner::new());
        let vm = vm!();

        assert_eq!(
            builtin.get_memory_accesses(&vm),
            Err(MemoryError::MissingSegmentUsedSizes),
        );
    }

    #[test]
    fn get_memory_accesses_empty() {
        let builtin = BuiltinRunner::Output(OutputBuiltinRunner::new());
        let mut vm = vm!();

        vm.segments.segment_used_sizes = Some(vec![0]);
        assert_eq!(builtin.get_memory_accesses(&vm), Ok(vec![]));
    }

    #[test]
    fn get_memory_accesses() {
        let builtin = BuiltinRunner::Output(OutputBuiltinRunner::new());
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
        let builtin = OutputBuiltinRunner::new();
        let vm = vm!();

        assert_eq!(
            builtin.get_used_cells(&vm),
            Err(MemoryError::MissingSegmentUsedSizes)
        );
    }

    #[test]
    fn get_used_cells_empty() {
        let builtin = OutputBuiltinRunner::new();
        let mut vm = vm!();

        vm.segments.segment_used_sizes = Some(vec![0]);
        assert_eq!(builtin.get_used_cells(&vm), Ok(0));
    }

    #[test]
    fn get_used_cells() {
        let builtin = OutputBuiltinRunner::new();
        let mut vm = vm!();

        vm.segments.segment_used_sizes = Some(vec![4]);
        assert_eq!(builtin.get_used_cells(&vm), Ok(4));
    }
}
