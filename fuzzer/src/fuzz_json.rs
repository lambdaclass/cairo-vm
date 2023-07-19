use honggfuzz::fuzz;
use cairo_vm::{
    cairo_run::{cairo_run_parsed_program, CairoRunConfig},
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    serde::deserialize_program::ProgramJson,
};

const STEPS_LIMIT: usize = 1000000;
fn main() {
    loop {
        fuzz!(|data: (CairoRunConfig, ProgramJson)| {
            let (cairo_run_config, program_json) = data;
            let _ = cairo_run_parsed_program(
                Some(program_json.clone()),
                None,
                &CairoRunConfig::default(),
                &mut BuiltinHintProcessor::new_empty(),
                STEPS_LIMIT,
            );
            let _ = cairo_run_parsed_program(
                Some(program_json),
                None,
                &cairo_run_config,
                &mut BuiltinHintProcessor::new_empty(),
                STEPS_LIMIT,
            );
        });
    }
}
