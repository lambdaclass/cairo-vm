use std::collections::HashMap;

use crate::{
    cairo_run::{cairo_run, CairoRunConfig},
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    vm::runners::{
        builtin_runner::{HASH_BUILTIN_NAME, OUTPUT_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME},
        cairo_pie::{BuiltinAdditionalData, OutputBuiltinAdditionalData, SegmentInfo},
        cairo_runner::ExecutionResources,
    },
};

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn pedersen_test() {
    // Run the program
    let program_content = include_bytes!("../../../cairo_programs/pedersen_test.json");
    let mut hint_processor = BuiltinHintProcessor::new_empty();
    let result = cairo_run(
        program_content,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_processor,
    );
    assert!(result.is_ok());
    let (runner, vm) = result.unwrap();
    // Obtain the pie
    let result = runner.get_cairo_pie(&vm);
    //assert!(result.is_ok());
    let cairo_pie = result.unwrap();
    // Check pie values
    // CairoPieMedatada
    let pie_metadata = cairo_pie.metadata;
    // ret_pc_segment
    assert_eq!(pie_metadata.ret_pc_segment, SegmentInfo::from((6, 0)));
    // builtin_segments
    //let expected_builtin_segments:


    // execution_resources
    let expected_execution_resources = ExecutionResources {
        n_steps: 14,
        n_memory_holes: 0,
        builtin_instance_counter: HashMap::from([
            (RANGE_CHECK_BUILTIN_NAME.to_string(), 0),
            (OUTPUT_BUILTIN_NAME.to_string(), 1),
            (HASH_BUILTIN_NAME.to_string(), 1),
        ]),
    };
    assert_eq!(cairo_pie.execution_resources, expected_execution_resources);
    // additional_data
    let expected_additional_data = HashMap::from([
        (
            OUTPUT_BUILTIN_NAME.to_string(),
            BuiltinAdditionalData::Output(OutputBuiltinAdditionalData {
                pages: HashMap::new(),
                attributes: HashMap::new(),
            }),
        ),
        (
            HASH_BUILTIN_NAME.to_string(),
            BuiltinAdditionalData::Hash(vec![3, 2]),
        ),
        (
            RANGE_CHECK_BUILTIN_NAME.to_string(),
            BuiltinAdditionalData::None,
        ),
    ]);
    assert_eq!(cairo_pie.additional_data, expected_additional_data)
}
