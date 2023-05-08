#[cfg(feature = "cairo-1-hints")]
use crate::tests::*;

#[cfg(feature = "cairo-1-hints")]
#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn alloc_felt_252_dict() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/felt_252_dict.casm");
    run_cairo_1_entrypoint(program_data.as_slice(), 0, &vec![], &vec![1.into()]);
}
