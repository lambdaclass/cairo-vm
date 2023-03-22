use crate::stdlib::prelude::*;

use crate::{
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    types::program::Program,
    vm::{
        runners::cairo_runner::CairoRunner, trace::trace_entry::TraceEntry, vm_core::VirtualMachine,
    },
};

use assert_matches::assert_matches;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn bitwise_integration_test() {
    let program = Program::from_bytes(
        include_bytes!("../../cairo_programs/bitwise_builtin_test.json"),
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
    assert_matches!(
        cairo_runner.relocate(&mut vm, true),
        Ok(()),
        "Execution failed"
    );

    let python_vm_relocated_trace: Vec<TraceEntry> = vec![
        TraceEntry {
            pc: 27,
            ap: 72,
            fp: 72,
        },
        TraceEntry {
            pc: 28,
            ap: 73,
            fp: 72,
        },
        TraceEntry {
            pc: 30,
            ap: 74,
            fp: 72,
        },
        TraceEntry {
            pc: 32,
            ap: 75,
            fp: 72,
        },
        TraceEntry {
            pc: 9,
            ap: 77,
            fp: 77,
        },
        TraceEntry {
            pc: 10,
            ap: 77,
            fp: 77,
        },
        TraceEntry {
            pc: 11,
            ap: 77,
            fp: 77,
        },
        TraceEntry {
            pc: 13,
            ap: 78,
            fp: 77,
        },
        TraceEntry {
            pc: 14,
            ap: 79,
            fp: 77,
        },
        TraceEntry {
            pc: 34,
            ap: 79,
            fp: 72,
        },
        TraceEntry {
            pc: 36,
            ap: 79,
            fp: 72,
        },
        TraceEntry {
            pc: 37,
            ap: 80,
            fp: 72,
        },
        TraceEntry {
            pc: 39,
            ap: 81,
            fp: 72,
        },
        TraceEntry {
            pc: 41,
            ap: 82,
            fp: 72,
        },
        TraceEntry {
            pc: 15,
            ap: 84,
            fp: 84,
        },
        TraceEntry {
            pc: 16,
            ap: 84,
            fp: 84,
        },
        TraceEntry {
            pc: 17,
            ap: 84,
            fp: 84,
        },
        TraceEntry {
            pc: 19,
            ap: 85,
            fp: 84,
        },
        TraceEntry {
            pc: 20,
            ap: 86,
            fp: 84,
        },
        TraceEntry {
            pc: 43,
            ap: 86,
            fp: 72,
        },
        TraceEntry {
            pc: 45,
            ap: 86,
            fp: 72,
        },
        TraceEntry {
            pc: 46,
            ap: 87,
            fp: 72,
        },
        TraceEntry {
            pc: 48,
            ap: 88,
            fp: 72,
        },
        TraceEntry {
            pc: 50,
            ap: 89,
            fp: 72,
        },
        TraceEntry {
            pc: 21,
            ap: 91,
            fp: 91,
        },
        TraceEntry {
            pc: 22,
            ap: 91,
            fp: 91,
        },
        TraceEntry {
            pc: 23,
            ap: 91,
            fp: 91,
        },
        TraceEntry {
            pc: 25,
            ap: 92,
            fp: 91,
        },
        TraceEntry {
            pc: 26,
            ap: 93,
            fp: 91,
        },
        TraceEntry {
            pc: 52,
            ap: 93,
            fp: 72,
        },
        TraceEntry {
            pc: 54,
            ap: 93,
            fp: 72,
        },
        TraceEntry {
            pc: 55,
            ap: 94,
            fp: 72,
        },
        TraceEntry {
            pc: 57,
            ap: 95,
            fp: 72,
        },
        TraceEntry {
            pc: 59,
            ap: 96,
            fp: 72,
        },
        TraceEntry {
            pc: 1,
            ap: 98,
            fp: 98,
        },
        TraceEntry {
            pc: 2,
            ap: 98,
            fp: 98,
        },
        TraceEntry {
            pc: 3,
            ap: 98,
            fp: 98,
        },
        TraceEntry {
            pc: 5,
            ap: 99,
            fp: 98,
        },
        TraceEntry {
            pc: 6,
            ap: 100,
            fp: 98,
        },
        TraceEntry {
            pc: 7,
            ap: 101,
            fp: 98,
        },
        TraceEntry {
            pc: 8,
            ap: 102,
            fp: 98,
        },
        TraceEntry {
            pc: 61,
            ap: 102,
            fp: 72,
        },
        TraceEntry {
            pc: 63,
            ap: 102,
            fp: 72,
        },
        TraceEntry {
            pc: 65,
            ap: 102,
            fp: 72,
        },
        TraceEntry {
            pc: 67,
            ap: 102,
            fp: 72,
        },
        TraceEntry {
            pc: 68,
            ap: 103,
            fp: 72,
        },
    ];
    for (i, entry) in python_vm_relocated_trace.iter().enumerate() {
        assert_eq!(&vm.get_relocated_trace().unwrap()[i], entry);
    }
}
