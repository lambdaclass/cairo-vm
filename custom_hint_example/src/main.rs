use cairo_rs::cairo_run::cairo_run;
use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintFunc,
};
use cairo_rs::hint_processor::builtin_hint_processor::hint_utils::get_integer_from_var_name;
use cairo_rs::hint_processor::hint_processor_definition::HintReference;
use cairo_rs::hint_processor::proxies::{
    exec_scopes_proxy::ExecutionScopesProxy, vm_proxy::VMProxy,
};
use cairo_rs::serde::deserialize_program::ApTracking;
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use std::collections::HashMap;
use std::path::Path;


// Create the function that implements the custom hint
fn hint_func(
    vm_proxy: &mut VMProxy,
    _exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let a = get_integer_from_var_name("a", vm_proxy, ids_data, ap_tracking)?;
    println!("{}", a);
    Ok(())
}

fn main() {
    //Instantiate the hint processor
    let mut hint_processor = BuiltinHintProcessor::new_empty();

    //Add the custom hint, together with the Python code
    hint_processor.add_hint(String::from("print(ids.a)"), HintFunc(Box::new(hint_func)));

    //Run the cairo program
    cairo_run(
        Path::new("custom_hint.json"),
        "main",
        false,
        &hint_processor,
    )
    .expect("Couldn't run program");
}
