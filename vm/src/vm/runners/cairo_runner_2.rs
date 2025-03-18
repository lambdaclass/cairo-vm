use std::collections::{HashMap, HashSet};

use cairo_lang_executable::executable::{EntryPointKind, Executable, ExecutableEntryPoint};

use crate::{
    hint_processor::hint_processor_definition::HintReference,
    serde::deserialize_program::{Attribute, Identifier, InstructionLocation},
    types::{builtin_name::BuiltinName, layout::CairoLayout, relocatable::Relocatable},
    utils::is_subsequence,
    vm::{
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
    virtual_machine: VirtualMachine,
    program_base: Relocatable,
    execution_base: Relocatable,

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
}

impl CairoRunner2 {
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
        let entrypoint = executable
            .entrypoints
            .iter()
            .find(|entrypoint| {
                // TODO: Use `Eq` once implemented on `EntryPointKind`.
                std::mem::discriminant(&entrypoint.kind) == std::mem::discriminant(&entrypoint_kind)
            })
            .expect("executable had no entrypoint of required kind");

        let builtins = get_entrypoint_builtins(entrypoint);

        check_builtin_order(&builtins)?;

        let builtins_set: HashSet<BuiltinName> = builtins.clone().into_iter().collect();
        let mut builtin_runners = initialize_builtin_runners(&layout, builtins_set, true, true)?;

        let mut memory_segment_manager = MemorySegmentManager::new();
        let program_base = memory_segment_manager.add();
        let execution_base = memory_segment_manager.add();

        for builtin_runner in &mut builtin_runners {
            builtin_runner.initialize_segments(&mut memory_segment_manager);
        }

        let virtual_machine = VirtualMachineBuilder::default()
            .builtin_runners(builtin_runners)
            .segments(memory_segment_manager)
            .build();

        Ok(Self {
            executable,
            virtual_machine,
            program_base,
            execution_base,
            entrypoint_kind,
            layout,
            trace_enabled,
            constants,
            error_message_attributes,
            instruction_locations,
            identifiers,
            reference_manager,
        })
    }

    pub fn run(&mut self) -> Result<(), VirtualMachineError> {
        Ok(())
    }
}

// TODO: Remove this once cyclic dependency is fixed.
// It should not be necessary, but cargo treats executable BuiltinName as a separate type
// which is why I had to create this adapter function.
pub fn get_entrypoint_builtins(entrypoint: &ExecutableEntryPoint) -> Vec<BuiltinName> {
    let mut builtins = Vec::with_capacity(entrypoint.builtins.len());

    for builtin in &entrypoint.builtins {
        let adapted_builtin = BuiltinName::from_str(builtin.to_str())
            .expect("should never fail under the same implementation");
        builtins.push(adapted_builtin);
    }

    builtins
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
    mut builtins: HashSet<BuiltinName>,
    allow_missing_builtins: bool,
    create_all_builtins: bool,
) -> Result<Vec<BuiltinRunner>, RunnerError> {
    let mut builtin_runners = Vec::new();

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

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_lang_compiler::diagnostics::DiagnosticsReporter;
    use cairo_lang_executable::{compile::compile_executable, executable::Executable};
    use std::path::Path;

    #[test]
    fn execute_program() {
        let program_path = Path::new("../cairo_programs/new_executable/empty.cairo");

        let reporter = DiagnosticsReporter::stderr();
        let executable = Executable::new(
            compile_executable(program_path, None, reporter).expect("failed to compile program"),
        );

        let layout = CairoLayout::all_cairo_instance();

        let mut runner = CairoRunner2::new(
            executable,
            EntryPointKind::Standalone,
            layout,
            false,
            HashMap::default(),
            Vec::default(),
            None,
            HashMap::default(),
            Vec::default(),
        )
        .expect("failed to create runner");

        runner.run().expect("failed to run program");
    }
}
