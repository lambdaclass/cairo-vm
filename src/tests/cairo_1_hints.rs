use crate::tests::*;

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn linear_split() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/linear_split.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![1_usize.into()],
        &vec![0.into(), 1.into()],
    );
}
