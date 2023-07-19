use cairo_vm::{
    cairo_run::{cairo_run_parsed_program, CairoRunConfig},
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    types::program::Program,
};
use cairo_vm::{
    serde::deserialize_program::{
        Attribute, BuiltinName, HintParams, Identifier,
        InstructionLocation, ReferenceManager,
    },
    types::relocatable::MaybeRelocatable,
};
use honggfuzz::fuzz;
use std::collections::HashMap;

const STEPS_LIMIT: usize = 1000000;
fn main() {
    loop {
        fuzz!(|data: (
            CairoRunConfig,
            Vec<BuiltinName>, 
            Vec<MaybeRelocatable>, 
            Option<usize>, 
            HashMap<usize, 
            Vec<HintParams>>, 
            ReferenceManager, 
            HashMap<String, Identifier>, 
            Vec<Attribute>, 
            Option<HashMap<usize, InstructionLocation>>
            )| 
        {
            let (
                cairo_config,
                builtins, 
                mem,
                main,
                hints,
                reference_manager,
                identifiers,
                error_message_attributes,
                instruction_locations
            ) = data;
            match Program::new(builtins, mem, main, hints, reference_manager, identifiers, error_message_attributes, instruction_locations) {
                Ok(program) => {
                    let _ = cairo_run_parsed_program(
                        program.clone(),
                        &CairoRunConfig::default(),
                        &mut BuiltinHintProcessor::new_empty(),
                        STEPS_LIMIT,
                    );
                    let _ = cairo_run_parsed_program(
                        program,
                        &cairo_config,
                        &mut BuiltinHintProcessor::new_empty(),
                        STEPS_LIMIT,
                    );
                },
                Err(_) => {}
            }
        });
    }
}
