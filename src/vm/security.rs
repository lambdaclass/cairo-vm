use super::{
    errors::{memory_errors::MemoryError, runner_errors::RunnerError},
    runners::cairo_runner::CairoRunner,
    vm_core::VirtualMachine,
};
use crate::types::relocatable::Relocatable;
use std::collections::HashMap;

/// Verify that the completed run in a runner is safe to be relocated and be
/// used by other Cairo programs.
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
    verify_builtins: bool,
    vm: &VirtualMachine,
) -> Result<(), RunnerError> {
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

    // for (_, builtin_runner) in &vm.builtin_runners {
    //     builtin_runner.run_security_checks(vm)?;
    // }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        bigint, bigint_str, relocatable, serde::deserialize_program::ReferenceManager,
        types::program::Program, utils::test_utils::vm,
    };
    use num_bigint::{BigInt, Sign};

    #[test]
    fn verify_secure_runner_without_program_base() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: None,
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let runner = CairoRunner::new(&program).unwrap();
        let vm = vm!();

        assert_eq!(
            verify_secure_runner(&runner, true, &vm),
            Err(RunnerError::NoProgBase),
        );
    }

    #[test]
    fn verify_secure_runner_empty_memory() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: Some(0),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let mut runner = CairoRunner::new(&program).unwrap();
        let mut vm = vm!();

        runner.initialize(&mut vm).unwrap();
        vm.segments.compute_effective_sizes(&vm.memory);
        assert_eq!(verify_secure_runner(&runner, true, &vm), Ok(()));
    }

    #[test]
    fn verify_secure_runner_program_out_of_bounds() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: Vec::new(),
            constants: HashMap::new(),
            main: Some(0),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let mut runner = CairoRunner::new(&program).unwrap();
        let mut vm = vm!();

        runner.initialize(&mut vm).unwrap();

        vm.memory.data = vec![vec![Some(relocatable!(0, 1000).into())]];
        vm.segments.segment_used_sizes = Some(vec![0, 0, 0, 0]);

        assert_eq!(
            verify_secure_runner(&runner, true, &vm),
            Err(RunnerError::FailedMemoryGet(MemoryError::NumOutOfBounds)),
        );
    }

    #[test]
    fn verify_secure_runner_success() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
            ),
            data: vec![
                bigint!(0).into(),
                bigint!(0).into(),
                bigint!(0).into(),
                bigint!(0).into(),
            ],
            constants: HashMap::new(),
            main: Some(0),
            hints: HashMap::new(),
            reference_manager: ReferenceManager {
                references: Vec::new(),
            },
            identifiers: HashMap::new(),
        };

        let mut runner = CairoRunner::new(&program).unwrap();
        let mut vm = vm!();

        runner.initialize(&mut vm).unwrap();

        vm.memory.data = vec![vec![
            Some(relocatable!(1, 0).into()),
            Some(relocatable!(2, 1).into()),
            Some(relocatable!(3, 2).into()),
            Some(relocatable!(4, 3).into()),
        ]];
        vm.segments.segment_used_sizes = Some(vec![5, 1, 2, 3, 4]);

        assert_eq!(verify_secure_runner(&runner, true, &vm), Ok(()));
    }
}
