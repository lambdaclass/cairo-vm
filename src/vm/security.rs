use num_traits::ToPrimitive;

use super::{
    errors::{
        memory_errors::MemoryError, runner_errors::RunnerError, vm_errors::VirtualMachineError,
    },
    runners::cairo_runner::CairoRunner,
    vm_core::VirtualMachine,
};
use crate::types::relocatable::{MaybeRelocatable, Relocatable};
use std::{collections::HashMap, mem::swap};

/// Verify that the completed run in a runner is safe to be relocated and be
/// used by other Cairo programs.
///
/// Checks include:
///   - All accesses to the builtin segments must be within the range defined by
///     the builtins themselves.
///   - There must not be accesses to the program segment outside the program
///     data range.
///   - All addresses in memory must be real (not temporary)
///
/// Note: Each builtin is responsible for checking its own segments' data.
pub fn verify_secure_runner(
    runner: &CairoRunner,
    verify_builtins: bool,
    vm: &mut VirtualMachine,
) -> Result<(), VirtualMachineError> {
    let builtins_segment_info = match verify_builtins {
        true => runner.get_builtin_segments_info(vm)?, //.iter().map(|(_, segment_info)| (segment_info.index, segment_info.size)).collect(),
        false => HashMap::new(),
    };
    // Check builtin segment out of bounds.
    for (_, segment_info) in builtins_segment_info {
        let current_size = segment_info
            .index
            .to_usize()
            .map(|index| vm.memory.data.get(index))
            .flatten()
            .map(|segment| segment.len());
        // + 1 here accounts for maximum segment offset being segment.len() -1
        if current_size >= Some(segment_info.size + 1) {
            return Err(VirtualMachineError::OutOfBoundsBuiltinSegmentAccess);
        }
    }
    // Check out of bounds for program segment.
    let program_segment_index = runner
        .program_base
        .map(|rel| rel.segment_index.to_usize())
        .flatten()
        .ok_or(RunnerError::NoProgBase)?;
    let program_segment_size = vm
        .memory
        .data
        .get(program_segment_index)
        .map(|segment| segment.len());
    // + 1 here accounts for maximum segment offset being segment.len() -1
    if program_segment_size >= Some(runner.program.data.len() + 1) {
        return Err(VirtualMachineError::OutOfBoundsProgramSegmentAccess);
    }

    // Check that the addresses in memory are valid
    // This means that every temporary address has been properly relocated to a real address
    // Asumption: If temporary memory is empty, this means no temporary memory addresses were generated and all addresses in memory are real
    if !vm.memory.temp_data.is_empty() {
        for value in vm.memory.data.iter().flatten() {
            match value {
                Some(MaybeRelocatable::RelocatableValue(addr)) if addr.segment_index < 0 => {
                    return Err(VirtualMachineError::InvalidMemoryValueTemporaryAddress(
                        *addr,
                    ))
                }
                _ => {}
            }
        }
    }
    for (_, builtin) in vm.builtin_runners.iter() {
        builtin.run_security_checks(vm)?;
    }

    Ok(())
}

/// Verify that the completed run in a runner is safe to be relocated and be
/// used by other Cairo programs.
///
/// Checks include:
///   - All accesses to the builtin segments must be within the range defined by
///     the builtins themselves.
///   - There mustn't be accesses to the program segment outside the program
///     data range.
///
/// Note: Each builtin is responsible for checking its own segments' data.
pub fn verify_secure_runner_(
    runner: &CairoRunner,
    verify_builtins: bool,
    vm: &mut VirtualMachine,
) -> Result<(), VirtualMachineError> {
    let program_base = runner
        .program_base
        .as_ref()
        .ok_or(RunnerError::NoProgBase)?;

    let builtin_segments = match verify_builtins {
        true => runner.get_builtin_segments_info(vm)?,
        false => HashMap::new(),
    };

    let builtin_segment_by_index = builtin_segments
        .iter()
        .map(|(seg_name, seg_info)| (seg_info.index, (seg_name, seg_info)))
        .collect::<HashMap<_, _>>();

    let memory_iter = vm
        .memory
        .data
        .iter()
        .enumerate()
        .flat_map(|(idx, segment)| {
            segment.iter().enumerate().filter_map(move |(off, value)| {
                value
                    .as_ref()
                    .map(|val| (Relocatable::from((idx as _, off)), val))
            })
        });
    for (addr, value) in memory_iter {
        // Check builtin segment bounds.
        if let Some((_, seg_info)) = builtin_segment_by_index.get(&addr.segment_index) {
            if addr.offset >= seg_info.size {
                return Err(RunnerError::FailedMemoryGet(MemoryError::NumOutOfBounds).into());
            }
        }

        // Check program segment bounds.
        if addr.segment_index == program_base.segment_index
            && addr.offset >= runner.program.data.len()
        {
            return Err(RunnerError::FailedMemoryGet(MemoryError::NumOutOfBounds).into());
        }

        // Check value validity (when relocatable, that the segment exists and
        // is not temporary).
        if !vm
            .segments
            .is_valid_memory_value(value)
            .map_err(RunnerError::FailedMemoryGet)?
        {
            return Err(
                RunnerError::FailedMemoryGet(MemoryError::InvalidMemoryValue(addr, value.clone()))
                    .into(),
            );
        }
    }

    // This swap is needed to avoid double mutable borrows.
    let mut tmp = Vec::new();
    swap(&mut tmp, &mut vm.builtin_runners);
    for (_, builtin_runner) in &tmp {
        builtin_runner.run_security_checks(vm)?;
    }
    swap(&mut tmp, &mut vm.builtin_runners);

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
    use crate::types::relocatable::MaybeRelocatable;
    use crate::vm::vm_memory::memory::Memory;
    use crate::{relocatable, types::program::Program, utils::test_utils::*};
    use felt::Felt;
    use num_traits::Zero;

    #[test]
    fn verify_secure_runner_without_program_base() {
        let program = program!();

        let runner = cairo_runner!(program);
        let mut vm = vm!();

        assert_eq!(
            verify_secure_runner(&runner, true, &mut vm),
            Err(RunnerError::NoProgBase.into()),
        );
    }

    #[test]
    fn verify_secure_runner_empty_memory() {
        let program = program!(main = Some(0),);

        let mut runner = cairo_runner!(program);
        let mut vm = vm!();

        runner.initialize(&mut vm).unwrap();
        vm.segments.compute_effective_sizes(&vm.memory);
        assert_eq!(verify_secure_runner(&runner, true, &mut vm), Ok(()));
    }

    #[test]
    fn verify_secure_runner_program_access_out_of_bounds() {
        let program = program!(main = Some(0),);

        let mut runner = cairo_runner!(program);
        let mut vm = vm!();

        runner.initialize(&mut vm).unwrap();

        vm.memory = memory![((0, 0), 100)];
        vm.segments.segment_used_sizes = Some(vec![1]);

        assert_eq!(
            verify_secure_runner(&runner, true, &mut vm),
            Err(VirtualMachineError::OutOfBoundsProgramSegmentAccess)
        );
    }

    #[test]
    fn verify_secure_runner_builtin_access_out_of_bounds() {
        let program = program!(main = Some(0), builtins = vec!["range_check".to_string()],);

        let mut runner = cairo_runner!(program);
        let mut vm = vm!();
        runner.initialize(&mut vm).unwrap();
        vm.builtin_runners[0].1.set_stop_ptr(0);

        vm.memory.data = vec![vec![], vec![], vec![Some(mayberelocatable!(1))]];
        vm.segments.segment_used_sizes = Some(vec![0, 0, 0, 0]);

        assert_eq!(
            verify_secure_runner(&runner, true, &mut vm),
            Err(VirtualMachineError::OutOfBoundsBuiltinSegmentAccess)
        );
    }

    #[test]
    fn verify_secure_runner_builtin_access_correct() {
        let program = program!(main = Some(0), builtins = vec!["range_check".to_string()],);

        let mut runner = cairo_runner!(program);
        let mut vm = vm!();
        runner.initialize(&mut vm).unwrap();
        let mut hint_processor = BuiltinHintProcessor::new_empty();
        runner
            .end_run(false, false, &mut vm, &mut hint_processor)
            .unwrap();
        vm.builtin_runners[0].1.set_stop_ptr(1);

        vm.memory.data = vec![vec![], vec![], vec![Some(mayberelocatable!(1))]];
        vm.segments.segment_used_sizes = Some(vec![0, 0, 1, 0]);

        assert_eq!(verify_secure_runner(&runner, true, &mut vm), Ok(()));
    }

    #[test]
    fn verify_secure_runner_success() {
        let program = program!(
            data = vec![
                Felt::zero().into(),
                Felt::zero().into(),
                Felt::zero().into(),
                Felt::zero().into(),
            ],
            main = Some(0),
        );

        let mut runner = cairo_runner!(program);
        let mut vm = vm!();

        runner.initialize(&mut vm).unwrap();

        vm.memory.data = vec![vec![
            Some(relocatable!(1, 0).into()),
            Some(relocatable!(2, 1).into()),
            Some(relocatable!(3, 2).into()),
            Some(relocatable!(4, 3).into()),
        ]];
        vm.segments.segment_used_sizes = Some(vec![5, 1, 2, 3, 4]);

        assert_eq!(verify_secure_runner(&runner, true, &mut vm), Ok(()));
    }
}
