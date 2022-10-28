use cairo_rs::{
    hint_processor::{
        builtin_hint_processor::builtin_hint_processor_definition::{
            BuiltinHintProcessor, HintFunc,
        },
        hint_processor_definition::HintReference,
    },
    serde::deserialize_program::ApTracking,
    types::{exec_scope::ExecutionScopes, program::Program},
    vm::{
        errors::vm_errors::VirtualMachineError, runners::cairo_runner::CairoRunner,
        vm_core::VirtualMachine,
    },
};
use num_bigint::BigInt;
use std::rc::Rc;
use std::{collections::HashMap, path::Path};

#[test]
fn skip_next_instruction_test() {
    fn skip_hint(
        vm: &mut VirtualMachine,
        _exec_scopes: &mut ExecutionScopes,
        _ids_data: &HashMap<String, HintReference>,
        _ap_tracking: &ApTracking,
        _constants: &HashMap<String, BigInt>,
    ) -> Result<(), VirtualMachineError> {
        vm.skip_next_instruction_execution();
        Ok(())
    }
    let program = Program::from_file(
        Path::new("cairo_programs/test_skip_next_instruction.json"),
        Some("main"),
    )
    .expect("Failed to deserialize program");

    let hint = Rc::new(HintFunc(Box::new(skip_hint)));
    let mut hint_processor = BuiltinHintProcessor::new_empty();
    hint_processor.add_hint(String::from("skip_next_instruction()"), hint);

    let mut cairo_runner = CairoRunner::new(&program, "all", false).unwrap();
    let mut vm = VirtualMachine::new(program.prime, false, Vec::new());
    let end = cairo_runner.initialize(&mut vm).unwrap();
    assert_eq!(
        cairo_runner.run_until_pc(end, &mut vm, &hint_processor),
        Ok(())
    );
}
