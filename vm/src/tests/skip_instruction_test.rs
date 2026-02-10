use crate::tests::run_program_simple;

#[test]
fn skip_next_instruction_test() {
    let program_data = include_bytes!(
        "../../../cairo_programs/noretrocompat/test_skip_next_instruction.noretrocompat.json"
    );
    run_program_simple(program_data.as_slice());
}
