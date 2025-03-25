#![cfg(feature = "cairo-runner-2")]

use core::any::Any;

use crate::{
    hint_processor::hint_processor_definition::{HintProcessor, HintReference},
    serde::deserialize_program::HintParams,
    stdlib::{
        collections::{BTreeMap, HashMap, HashSet},
        prelude::*,
    },
    types::{
        builtin_name::BuiltinName,
        errors::program_errors::ProgramError,
        exec_scope::ExecutionScopes,
        layout::CairoLayout,
        program::HintsCollection,
        relocatable::{MaybeRelocatable, Relocatable},
    },
    utils::is_subsequence,
    vm::{
        context::run_context::RunContext,
        errors::{runner_errors::RunnerError, vm_errors::VirtualMachineError},
        runners::builtin_runner::{
            BitwiseBuiltinRunner, BuiltinRunner, EcOpBuiltinRunner, HashBuiltinRunner,
            KeccakBuiltinRunner, ModBuiltinRunner, OutputBuiltinRunner, PoseidonBuiltinRunner,
            RangeCheckBuiltinRunner, SignatureBuiltinRunner, RC_N_PARTS_96, RC_N_PARTS_STANDARD,
        },
        vm_core::VirtualMachine,
        vm_memory::{memory::Memory, memory_segments::MemorySegmentManager},
    },
    Felt252,
};

/// This type is originally defined in `cairo-lang-executable`.
/// We redefine it here to avoid a cyclic dependencies.
#[derive(Debug)]
pub struct ExecutableEntryPoint {
    pub builtins: Vec<BuiltinName>,
    pub offset: usize,
    pub kind: EntryPointKind,
}

/// This type is originally defined in `cairo-lang-executable`.
/// We redefine it here to avoid a cyclic dependencies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryPointKind {
    Bootloader,
    Standalone,
}

pub struct Program2 {
    pub bytecode: Vec<MaybeRelocatable>,
    pub hints_collection: HintsCollection,
    pub entrypoint: ExecutableEntryPoint,

    pub reference_manager: Vec<HintReference>,
    pub constants: HashMap<String, Felt252>,
}

impl Program2 {
    pub fn new(
        bytecode: Vec<MaybeRelocatable>,
        hints: BTreeMap<usize, Vec<HintParams>>,
        entrypoint: ExecutableEntryPoint,
        reference_manager: Vec<HintReference>,
        constants: HashMap<String, Felt252>,
    ) -> Result<Program2, ProgramError> {
        let hints_collection = HintsCollection::new(&hints, bytecode.len())?;

        Ok(Self {
            bytecode,
            hints_collection,
            entrypoint,
            reference_manager,
            constants,
        })
    }
}

#[allow(dead_code)]
pub struct CairoRunner2 {
    vm: VirtualMachine,
    program_base: Relocatable,
    execution_base: Relocatable,
    final_pc: Relocatable,
    execution_scopes: ExecutionScopes,

    // Configuration
    program: Program2,
    layout: CairoLayout,
}

impl CairoRunner2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        program: Program2,
        layout: CairoLayout,
        trace_enabled: bool,
    ) -> Result<Self, RunnerError> {
        let mut vm = VirtualMachine::new(trace_enabled, false);

        check_builtin_order(&(&program.entrypoint).builtins)?;
        vm.builtin_runners =
            initialize_builtin_runners(&layout, &program.entrypoint.builtins, true, true)?;

        let program_base = vm.add_memory_segment();
        let execution_base = vm.add_memory_segment();

        initialize_builtin_runner_segments(&mut vm.builtin_runners, &mut vm.segments);

        load_program(&mut vm, program_base, &program.bytecode)?;

        let mut stack = Vec::new();

        let initial_pc = (program_base + program.entrypoint.offset)?;

        let (initial_fp, final_pc) = match program.entrypoint.kind {
            EntryPointKind::Bootloader => {
                // On bootloader, we execute until control flow is returned.
                // The stack is arranged as if we are at the start of a function call.
                // Input arguments are set as input arguments to the the function.
                //
                // <-------- ARGUMENTS ----
                //     ┌────┬────┬────┬────┬────────┬────────┬ ─ ─ ─ ─ ┐
                // ... │    │    │    │    │ RET FP │ RET PC │
                //     └────┴────┴────┴────┴────────┴────────┴ ─ ─ ─ ─ ┘
                //                                             INIT FP
                // Note: The size of the cells is not relevant
                //
                // The initial fp variable points to the cell after the return pc.

                extend_stack_with_builtins(
                    &mut stack,
                    &program.entrypoint.builtins,
                    &vm.builtin_runners,
                );

                let return_fp = vm.add_memory_segment();
                let return_pc = vm.add_memory_segment();
                stack.push(MaybeRelocatable::RelocatableValue(return_fp));
                stack.push(MaybeRelocatable::RelocatableValue(return_pc));

                let initial_fp = (execution_base + stack.len())?;

                (initial_fp, return_pc)
            }
            EntryPointKind::Standalone => {
                // On standalone, we execute until a fixed address.
                // Input arguments are set as local variables to the current frame.
                //
                //         -------------- ARGUMENTS ------------------>
                // ┌──────┬─────────┬────┬────┬────┬────┬────┬────┐
                // │ ZERO │         │    │    │    │    │    │    │ ...
                // └──────┴─────────┴────┴────┴────┴────┴────┴────┘
                //          INIT FP
                // Note: The size of the cells is not relevant
                //
                // The initial fp variable points to the cell after the zero element.
                //
                // The zero element is necessary because the compiler asumes that `fp`
                // is not pointing to the start of a segment - it fails otherwise.

                let stack_prefix = &[MaybeRelocatable::Int(Felt252::ZERO)];
                stack.extend_from_slice(stack_prefix);
                extend_stack_with_builtins(
                    &mut stack,
                    &program.entrypoint.builtins,
                    &vm.builtin_runners,
                );

                let final_pc = (initial_pc + 4)?;
                let initial_fp = (execution_base + stack_prefix.len())?;

                (initial_fp, final_pc)
            }
        };

        let initial_ap = initial_fp;
        let run_context = RunContext::new(initial_pc, initial_ap.offset, initial_fp.offset);
        vm.set_run_context(run_context);

        load_stack(&mut vm, execution_base, &stack)?;

        add_builtin_validation_rules(&mut vm.segments.memory, &mut vm.builtin_runners)?;

        Ok(Self {
            vm,
            program_base,
            execution_base,
            final_pc,
            execution_scopes: ExecutionScopes::new(),
            program,
            layout,
        })
    }

    pub fn run(
        &mut self,
        hint_processor: &mut dyn HintProcessor,
    ) -> Result<(), VirtualMachineError> {
        #[cfg_attr(not(feature = "extensive_hints"), allow(unused_mut))]
        let mut hint_data = get_hint_data(
            &self.program.hints_collection,
            &self.program.reference_manager,
            hint_processor,
        )?;

        #[cfg(feature = "extensive_hints")]
        let mut hint_ranges = self.program.hints_collection.hints_ranges.clone();

        while self.vm.get_pc() != self.final_pc && !hint_processor.consumed() {
            #[cfg(feature = "extensive_hints")]
            let hint_data = &mut hint_data;
            #[cfg(not(feature = "extensive_hints"))]
            let hint_data = self
                .program
                .hints_collection
                .get_hint_range_for_pc(self.vm.get_pc().offset)
                .and_then(|range| {
                    range.and_then(|(start, length)| hint_data.get(start..start + length.get()))
                })
                .unwrap_or(&[]);

            self.vm.step(
                hint_processor,
                &mut self.execution_scopes,
                hint_data,
                #[cfg(feature = "extensive_hints")]
                &mut hint_ranges,
                &self.program.constants,
            )?;

            hint_processor.consume_step();
        }

        if self.vm.get_pc() != self.final_pc {
            return Err(VirtualMachineError::UnfinishedExecution);
        }

        Ok(())
    }
}

pub fn check_builtin_order(builtins: &[BuiltinName]) -> Result<(), RunnerError> {
    let ordered_builtins = vec![
        BuiltinName::output,
        BuiltinName::pedersen,
        BuiltinName::range_check,
        BuiltinName::ecdsa,
        BuiltinName::bitwise,
        BuiltinName::ec_op,
        BuiltinName::keccak,
        BuiltinName::poseidon,
        BuiltinName::range_check96,
        BuiltinName::add_mod,
        BuiltinName::mul_mod,
    ];
    if !is_subsequence(builtins, &ordered_builtins) {
        return Err(RunnerError::DisorderedBuiltins);
    };

    Ok(())
}

pub fn initialize_builtin_runners(
    layout: &CairoLayout,
    builtins: &[BuiltinName],
    allow_missing_builtins: bool,
    create_all_builtins: bool,
) -> Result<Vec<BuiltinRunner>, RunnerError> {
    let mut builtin_runners = Vec::new();

    let mut builtins: HashSet<BuiltinName> = builtins.iter().map(ToOwned::to_owned).collect();

    if layout.builtins.output {
        let included = builtins.remove(&BuiltinName::output);
        if included || create_all_builtins {
            builtin_runners.push(OutputBuiltinRunner::new(included).into());
        }
    }

    if let Some(instance_def) = layout.builtins.pedersen.as_ref() {
        let included = builtins.remove(&BuiltinName::pedersen);
        if included || create_all_builtins {
            builtin_runners.push(HashBuiltinRunner::new(instance_def.ratio, included).into());
        }
    }

    if let Some(instance_def) = layout.builtins.range_check.as_ref() {
        let included = builtins.remove(&BuiltinName::range_check);
        if included || create_all_builtins {
            builtin_runners.push(
                RangeCheckBuiltinRunner::<RC_N_PARTS_STANDARD>::new_with_low_ratio(
                    instance_def.ratio,
                    included,
                )
                .into(),
            );
        }
    }

    if let Some(instance_def) = layout.builtins.ecdsa.as_ref() {
        let included = builtins.remove(&BuiltinName::ecdsa);
        if included || create_all_builtins {
            builtin_runners.push(SignatureBuiltinRunner::new(instance_def.ratio, included).into());
        }
    }

    if let Some(instance_def) = layout.builtins.bitwise.as_ref() {
        let included = builtins.remove(&BuiltinName::bitwise);
        if included || create_all_builtins {
            builtin_runners.push(BitwiseBuiltinRunner::new(instance_def.ratio, included).into());
        }
    }

    if let Some(instance_def) = layout.builtins.ec_op.as_ref() {
        let included = builtins.remove(&BuiltinName::ec_op);
        if included || create_all_builtins {
            builtin_runners.push(EcOpBuiltinRunner::new(instance_def.ratio, included).into());
        }
    }

    if let Some(instance_def) = layout.builtins.keccak.as_ref() {
        let included = builtins.remove(&BuiltinName::keccak);
        if included || create_all_builtins {
            builtin_runners.push(KeccakBuiltinRunner::new(instance_def.ratio, included).into());
        }
    }

    if let Some(instance_def) = layout.builtins.poseidon.as_ref() {
        let included = builtins.remove(&BuiltinName::poseidon);
        if included || create_all_builtins {
            builtin_runners.push(PoseidonBuiltinRunner::new(instance_def.ratio, included).into());
        }
    }

    if let Some(instance_def) = layout.builtins.range_check96.as_ref() {
        let included = builtins.remove(&BuiltinName::range_check96);
        if included || create_all_builtins {
            builtin_runners.push(
                RangeCheckBuiltinRunner::<RC_N_PARTS_96>::new_with_low_ratio(
                    instance_def.ratio,
                    included,
                )
                .into(),
            );
        }
    }
    if let Some(instance_def) = layout.builtins.add_mod.as_ref() {
        let included = builtins.remove(&BuiltinName::add_mod);
        if included || create_all_builtins {
            builtin_runners.push(ModBuiltinRunner::new_add_mod(instance_def, included).into());
        }
    }
    if let Some(instance_def) = layout.builtins.mul_mod.as_ref() {
        let included = builtins.remove(&BuiltinName::mul_mod);
        if included || create_all_builtins {
            builtin_runners.push(ModBuiltinRunner::new_mul_mod(instance_def, included).into());
        }
    }

    if !builtins.is_empty() && !allow_missing_builtins {
        return Err(RunnerError::NoBuiltinForInstance(Box::new((
            builtins,
            layout.name,
        ))));
    }

    Ok(builtin_runners)
}

fn initialize_builtin_runner_segments(
    builtin_runners: &mut [BuiltinRunner],
    segments: &mut MemorySegmentManager,
) {
    for builtin_runner in builtin_runners.iter_mut() {
        builtin_runner.initialize_segments(segments);
    }

    for builtin_runner in builtin_runners.iter_mut() {
        if let BuiltinRunner::Mod(mod_builtin_runner) = builtin_runner {
            mod_builtin_runner.initialize_zero_segment(segments);
        }
    }
}

fn extend_stack_with_builtins(
    stack: &mut Vec<MaybeRelocatable>,
    builtins: &[BuiltinName],
    runners: &[BuiltinRunner],
) {
    let runner_map: HashMap<BuiltinName, &BuiltinRunner> = runners
        .iter()
        .map(|builtin_runner| (builtin_runner.name(), builtin_runner))
        .collect();
    for builtin in builtins {
        if let Some(builtin_runner) = runner_map.get(builtin) {
            stack.append(&mut builtin_runner.initial_stack());
        } else {
            stack.push(Felt252::ZERO.into())
        }
    }
}

fn load_program(
    vm: &mut VirtualMachine,
    program_base: Relocatable,
    bytecode: &[MaybeRelocatable],
) -> Result<(), RunnerError> {
    vm.load_data(program_base, bytecode)
        .map_err(RunnerError::MemoryInitializationError)?;
    for i in 0..bytecode.len() {
        vm.segments.memory.mark_as_accessed((program_base + i)?);
    }
    Ok(())
}

fn load_stack(
    vm: &mut VirtualMachine,
    execution_base: Relocatable,
    stack: &[MaybeRelocatable],
) -> Result<(), RunnerError> {
    vm.load_data(execution_base, stack)
        .map_err(RunnerError::MemoryInitializationError)?;
    Ok(())
}

fn add_builtin_validation_rules(
    memory: &mut Memory,
    runners: &mut [BuiltinRunner],
) -> Result<(), RunnerError> {
    for runner in runners {
        runner.add_validation_rule(memory)
    }
    memory
        .validate_existing_memory()
        .map_err(RunnerError::MemoryValidationError)?;
    Ok(())
}

fn get_hint_data(
    collection: &HintsCollection,
    references: &[HintReference],
    processor: &dyn HintProcessor,
) -> Result<Vec<Box<dyn Any>>, VirtualMachineError> {
    collection
        .iter_hints()
        .map(|hint| {
            processor
                .compile_hint(
                    &hint.code,
                    &hint.flow_tracking_data.ap_tracking,
                    &hint.flow_tracking_data.reference_ids,
                    references,
                )
                .map_err(|_| VirtualMachineError::CompileHintFail(hint.code.clone().into()))
        })
        .collect()
}
