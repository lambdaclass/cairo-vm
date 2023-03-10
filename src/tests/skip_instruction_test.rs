use crate::{
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    types::program::Program,
    vm::{runners::cairo_runner::CairoRunner, vm_core::VirtualMachine},
};

use assert_matches::assert_matches;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn skip_next_instruction_test() {
    let program = Program::from_bytes(
        include_bytes!(
            "../../cairo_programs/noretrocompat/test_skip_next_instruction.noretrocompat.json"
        ),
        Some("main"),
    )
    .unwrap();

    let mut hint_processor = BuiltinHintProcessor::new_empty();

    let mut cairo_runner = CairoRunner::new(&program, "all", false).unwrap();
    let mut vm = VirtualMachine::new(false);
    let end = cairo_runner.initialize(&mut vm).unwrap();
    assert_matches!(
        cairo_runner.run_until_pc(end, &mut vm, &mut hint_processor),
        Ok(())
    );
}
