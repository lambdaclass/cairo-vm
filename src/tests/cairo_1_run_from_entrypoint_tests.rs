use crate::tests::*;

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn fibonacci_1() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/fib.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &[1_usize.into(), 1_usize.into(), 1_usize.into()],
        &[1_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn fibonacci_3() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/fib.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &[3_usize.into(), 3_usize.into(), 3_usize.into()],
        &[9_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn random_ec_point() {
    let program_data =
        include_bytes!("../../cairo_programs/cairo-1-contracts/random_ec_point.casm");
    // No arguments needed or return value expected. It should just not panic, there is an assert in the contract.
    run_cairo_1_entrypoint(program_data.as_slice(), 0, &[], &[]);
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn divmod_hint_test() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/divmod.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &[16_usize.into(), 2_usize.into()],
        &[8_usize.into()],
    );
}
