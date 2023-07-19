use honggfuzz::fuzz;
use cairo_vm::{
    cairo_run::{cairo_run_parsed_program, CairoRunConfig},
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    serde::deserialize_program::ProgramJson,
};

fn main() {
    loop {
        fuzz!(|data: ProgramJson| {
            let _ = cairo_run_parsed_program(
                Some(data),
                None,
                &CairoRunConfig::default(),
                &mut BuiltinHintProcessor::new_empty(),
                STEPS_LIMIT,
            );
        });
    }
}
