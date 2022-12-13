use cairo_rs::{
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    types::program::Program,
    vm::{runners::cairo_runner::CairoRunner, vm_core::VirtualMachine},
};

use std::path::Path;

#[test]
fn skip_next_instruction_test() {
    let program = Program::from_file(
        Path::new("cairo_programs/test_skip_next_instruction.json"),
        Some("main"),
    )
    .expect("Failed to deserialize program");

    let hint_processor = BuiltinHintProcessor::new_empty();

    let mut cairo_runner = CairoRunner::new(&program, "all", false).unwrap();
    let mut vm = VirtualMachine::new(program.prime, false, Vec::new());
    let end = cairo_runner.initialize(&mut vm).unwrap();
    assert_eq!(
        cairo_runner.run_until_pc(end, &mut vm, &hint_processor),
        Ok(())
    );
}
