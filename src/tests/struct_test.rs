use crate::{
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    types::program::Program, vm::vm_core::VirtualMachine,
};

use crate::vm::{runners::cairo_runner::CairoRunner, trace::trace_entry::RelocatedTraceEntry};

use assert_matches::assert_matches;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn struct_integration_test() {
    let program = Program::from_bytes(
        include_bytes!("../../cairo_programs/struct.json"),
        Some("main"),
    )
    .unwrap();
    let mut hint_processor = BuiltinHintProcessor::new_empty();
    let mut cairo_runner = CairoRunner::new(&program, "all", false).unwrap();
    let mut vm = VirtualMachine::new(true);
    let end = cairo_runner.initialize(&mut vm).unwrap();

    assert_matches!(
        cairo_runner.run_until_pc(end, &mut vm, &mut hint_processor),
        Ok(()),
        "Execution failed"
    );
    assert!(
        cairo_runner.relocate(&mut vm, true) == Ok(()),
        "Execution failed"
    );
    let relocated_entry = RelocatedTraceEntry {
        pc: 1,
        ap: 4,
        fp: 4,
    };

    assert_eq!(cairo_runner.relocated_trace, Some(vec![relocated_entry]));
}
