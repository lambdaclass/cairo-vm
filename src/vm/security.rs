use super::{
    errors::{memory_errors::MemoryError, runner_errors::RunnerError},
    runners::cairo_runner::CairoRunner,
    vm_core::VirtualMachine,
};
use crate::types::relocatable::Relocatable;
use std::collections::HashMap;

/// Verify that the complete run in a runner is safe to relocate and be ran by
/// another Cairo program.
///
/// Checks include:
///   - There mustn't be memory accesses to any temporary segment.
///   - All accesses to the builtin segments must be within the range defined by
///     the builtins themselves.
///   - There mustn't be accesses to the program segment outside the program
///     data range.
///
/// Note: Each builtin is responsible for checking its own segments' data.
pub fn verify_secure_runner(
    runner: &CairoRunner,
    verify_builtins: Option<bool>,
    vm: &VirtualMachine,
) -> Result<(), RunnerError> {
    let verify_builtins = verify_builtins.unwrap_or(true);

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
                return Err(RunnerError::FailedMemoryGet(MemoryError::NumOutOfBounds));
            }
        }

        // Check program segment bounds.
        if addr.segment_index == program_base.segment_index
            && addr.offset >= runner.program.data.len()
        {
            return Err(RunnerError::FailedMemoryGet(MemoryError::NumOutOfBounds));
        }

        // Check value validity (when relocatable, that the segment exists and
        // is not temporary).
        if !vm
            .segments
            .is_valid_memory_value(value)
            .map_err(RunnerError::FailedMemoryGet)?
        {
            return Err(RunnerError::FailedMemoryGet(
                MemoryError::InvalidMemoryValue(addr, value.clone()),
            ));
        }
    }

    Ok(())
}
