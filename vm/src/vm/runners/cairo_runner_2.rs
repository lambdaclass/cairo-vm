use std::collections::HashMap;

use cairo_lang_executable::executable::{EntryPointKind, Executable};

use crate::{
    hint_processor::hint_processor_definition::HintReference,
    serde::deserialize_program::{Attribute, Identifier, InstructionLocation},
    types::layout::CairoLayout,
    vm::errors::vm_errors::VirtualMachineError,
    Felt252,
};

#[allow(dead_code)]
pub struct CairoRunner2 {
    executable: Executable,
    entrypoint: EntryPointKind,
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
        entrypoint: EntryPointKind,
        layout: CairoLayout,
        trace_enabled: bool,
        constants: HashMap<String, Felt252>,
        error_message_attributes: Vec<Attribute>,
        instruction_locations: Option<HashMap<usize, InstructionLocation>>,
        identifiers: HashMap<String, Identifier>,
        reference_manager: Vec<HintReference>,
    ) -> Self {
        Self {
            executable,
            entrypoint,
            layout,
            trace_enabled,
            constants,
            error_message_attributes,
            instruction_locations,
            identifiers,
            reference_manager,
        }
    }

    pub fn run(&mut self) -> Result<(), VirtualMachineError> {
        Ok(())
    }
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
        );

        runner.run().expect("failed to run program");
    }
}
