#![cfg(feature = "cairo-runner-2")]

use core::any::Any;

use cairo_lang_casm::hints::Hint;
use cairo_lang_executable::executable::{EntryPointKind, Executable, ExecutableEntryPoint};

use crate::{
    hint_processor::hint_processor_definition::{HintProcessor, HintReference},
    serde::deserialize_program::{
        ApTracking, Attribute, FlowTrackingData, HintParams, Identifier, InstructionLocation,
    },
    stdlib::{
        collections::{BTreeMap, HashMap, HashSet},
        prelude::*,
    },
    types::{
        builtin_name::BuiltinName,
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
        vm_core::{VirtualMachine, VirtualMachineBuilder},
        vm_memory::memory_segments::MemorySegmentManager,
    },
    Felt252,
};

#[allow(dead_code)]
pub struct CairoRunner2 {
    vm: VirtualMachine,
    program_base: Relocatable,
    execution_base: Relocatable,
    final_pc: Relocatable,
    execution_scopes: ExecutionScopes,

    // Configuration
    executable: Executable,
    entrypoint_kind: EntryPointKind,
    layout: CairoLayout,
    trace_enabled: bool,
    constants: HashMap<String, Felt252>,
    error_message_attributes: Vec<Attribute>,
    instruction_locations: Option<HashMap<usize, InstructionLocation>>,
    identifiers: HashMap<String, Identifier>,
    reference_manager: Vec<HintReference>,

    // Preprocessed Data
    hint_collection: HintsCollection,
}

impl CairoRunner2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        executable: Executable,
        entrypoint_kind: EntryPointKind,
        layout: CairoLayout,
        trace_enabled: bool,
        constants: HashMap<String, Felt252>,
        error_message_attributes: Vec<Attribute>,
        instruction_locations: Option<HashMap<usize, InstructionLocation>>,
        identifiers: HashMap<String, Identifier>,
        reference_manager: Vec<HintReference>,
    ) -> Result<Self, RunnerError> {
        let entrypoint = find_entrypoint_of_kind(&executable.entrypoints, entrypoint_kind.clone());

        let builtins = get_entrypoint_builtins(entrypoint);

        check_builtin_order(&builtins)?;
        let mut builtin_runners = initialize_builtin_runners(&layout, &builtins, true, true)?;

        let mut segments = MemorySegmentManager::new();
        let program_base = segments.add();
        let execution_base = segments.add();

        initialize_builtin_runner_segments(&mut builtin_runners, &mut segments);

        let mut vm = VirtualMachineBuilder::default()
            .builtin_runners(builtin_runners)
            .segments(segments)
            .build();

        let mut stack = Vec::new();

        let initial_pc = (program_base + entrypoint.offset)?;

        let (initial_fp, final_pc) = match entrypoint_kind {
            EntryPointKind::Bootloader => {
                // On bootloader, we execute until control flow is returned.
                // The stack is arranged as if we are at the start of a function call.
                // Input arguments are set as input arguments to the the function.
                //
                //   --- ARGUMENTS ---   RETURN FP   RETURN PC
                // ┌────┬────┬────┬────┬───────────┬───────────┬ ─ ─ ─ ─ ┐
                // │    │    │    │    │           │           │ START FP
                // └────┴────┴────┴────┴───────────┴───────────┴ ─ ─ ─ ─ ┘
                // Note: The size of the cells is not relevant

                extend_stack_with_builtins(&mut stack, &builtins, &vm.builtin_runners);

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
                //   ZERO   ------ ARGUMENTS ------
                // ┌──────┬──────────┬────┬────┬────┐
                // │      │ START FP │    │    │    │
                // └──────┴──────────┴────┴────┴────┘
                // Note: The size of the cells is not relevant
                //
                // The zero element is necessary because the compiler asumes that `fp`
                // is not pointing to the start of a segment - it fails otherwise.

                let stack_prefix = &[MaybeRelocatable::Int(Felt252::ZERO)];
                stack.extend_from_slice(stack_prefix);
                extend_stack_with_builtins(&mut stack, &builtins, &vm.builtin_runners);

                let final_pc = (initial_pc + 4)?;
                let initial_fp = (execution_base + stack_prefix.len())?;

                (initial_fp, final_pc)
            }
        };

        let initial_ap = initial_fp;
        let run_context = RunContext::new(initial_pc, initial_ap.offset, initial_fp.offset);
        vm.set_run_context(run_context);

        let bytecode = executable
            .program
            .bytecode
            .iter()
            .map(Felt252::from)
            .map(MaybeRelocatable::from)
            .collect::<Vec<_>>();
        vm.load_data(program_base, &bytecode)
            .map_err(RunnerError::MemoryInitializationError)?;
        for i in 0..bytecode.len() {
            vm.segments.memory.mark_as_accessed((program_base + i)?);
        }

        vm.load_data(execution_base, &stack)
            .map_err(RunnerError::MemoryInitializationError)?;

        for builtin_runner in &mut vm.builtin_runners {
            builtin_runner.add_validation_rule(&mut vm.segments.memory)
        }
        vm.segments
            .memory
            .validate_existing_memory()
            .map_err(RunnerError::MemoryValidationError)?;

        let hint_collection = build_hint_collection(&executable.program.hints, bytecode.len());

        Ok(Self {
            executable,
            vm,
            program_base,
            execution_base,
            final_pc,
            execution_scopes: ExecutionScopes::new(),
            entrypoint_kind,
            layout,
            trace_enabled,
            constants,
            error_message_attributes,
            instruction_locations,
            identifiers,
            reference_manager,
            hint_collection,
        })
    }

    pub fn run(
        &mut self,
        hint_processor: &mut dyn HintProcessor,
    ) -> Result<(), VirtualMachineError> {
        #[cfg_attr(not(feature = "extensive_hints"), allow(unused_mut))]
        let mut hint_data = get_hint_data(
            &self.hint_collection,
            &self.reference_manager,
            hint_processor,
        )?;

        #[cfg(feature = "extensive_hints")]
        let mut hint_ranges = self.hint_collection.hints_ranges.clone();

        while self.vm.get_pc() != self.final_pc && !hint_processor.consumed() {
            #[cfg(feature = "extensive_hints")]
            let hint_data = &mut hint_data;
            #[cfg(not(feature = "extensive_hints"))]
            let hint_data = self
                .hint_collection
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
                &self.constants,
            )?;

            hint_processor.consume_step();
        }

        if self.vm.get_pc() != self.final_pc {
            return Err(VirtualMachineError::UnfinishedExecution);
        }

        Ok(())
    }
}

fn find_entrypoint_of_kind(
    entrypoints: &[ExecutableEntryPoint],
    entrypoint_kind: EntryPointKind,
) -> &ExecutableEntryPoint {
    entrypoints
        .iter()
        .find(|entrypoint| {
            // TODO: Use `Eq` once implemented on `EntryPointKind`.
            std::mem::discriminant(&entrypoint.kind) == std::mem::discriminant(&entrypoint_kind)
        })
        .expect("executable had no entrypoint of required kind")
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

/// TODO: Remove this once cyclic dependency is fixed.
/// It should not be necessary, but cargo treats executable BuiltinName as a separate type
/// which is why I had to create this adapter function.
pub fn get_entrypoint_builtins(entrypoint: &ExecutableEntryPoint) -> Vec<BuiltinName> {
    let mut builtins = Vec::with_capacity(entrypoint.builtins.len());

    for builtin in &entrypoint.builtins {
        let adapted_builtin = BuiltinName::from_str(builtin.to_str())
            .expect("should never fail under the same implementation");
        builtins.push(adapted_builtin);
    }

    builtins
}

/// TODO: Determine if we receive the hint collection or build it ourselves
/// This function was adapted from cairo-lang-runner
pub fn build_hint_collection(
    hints: &[(usize, Vec<Hint>)],
    program_length: usize,
) -> HintsCollection {
    let mut hint_map: BTreeMap<usize, Vec<HintParams>> = BTreeMap::new();

    for (offset, offset_hints) in hints {
        hint_map.insert(
            *offset,
            offset_hints
                .iter()
                .map(|_| HintParams {
                    code: format!("{offset}"),
                    accessible_scopes: vec![],
                    flow_tracking_data: FlowTrackingData {
                        ap_tracking: ApTracking::new(),
                        reference_ids: HashMap::new(),
                    },
                })
                .collect(),
        );
    }

    HintsCollection::new(&hint_map, program_length).expect("failed to build hint collection")
}
