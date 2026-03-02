use crate::tests::run_program_with_trace;

#[test]
fn struct_integration_test() {
    let program_data = include_bytes!("../../../cairo_programs/struct.json");
    let expected_trace = [(1, 4, 4)];
    run_program_with_trace(program_data.as_slice(), expected_trace.as_slice());
}
