use honggfuzz::fuzz;
use cairo_vm::{
    cairo_run::{CairoRunConfig, cairo_run_parsed_program},
    types::program::Program,
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor
};

fn main() {
    loop {
        fuzz!(|data: (CairoRunConfig, Program)| {
            let (cairo_config, program) = data;
            let _ = cairo_run_parsed_program(program, &cairo_config, &mut BuiltinHintProcessor::new_empty());
        });
    }
}
