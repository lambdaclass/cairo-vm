use super::{
    errors::{memory_errors::MemoryError, runner_errors::RunnerError},
    runners::cairo_runner::CairoRunner,
    vm_core::VirtualMachine,
};
use crate::types::relocatable::Relocatable;
use std::collections::HashMap;

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
        .map(|(seg_name, seg_info)| (seg_info.index, (seg_name.as_str(), seg_info)))
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
        if let Some((_, seg_info)) = builtin_segment_by_index.get(&addr.segment_index) {
            if addr.offset >= seg_info.size {
                return Err(RunnerError::FailedMemoryGet(MemoryError::NumOutOfBounds));
            }
        }

        if addr.segment_index == program_base.segment_index
            && addr.offset >= runner.program.data.len()
        {
            return Err(RunnerError::FailedMemoryGet(MemoryError::NumOutOfBounds));
        }

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
