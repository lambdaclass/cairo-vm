use crate::tests::*;

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn test_init_squash_data() {
    let program_data =
        include_bytes!("../../cairo_programs/cairo-1-contracts/init_squash_data.casm");

    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &[10_usize.into()],
        &[10_usize.into()],
    );
}

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
fn divmod_hint_test() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/divmod.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &[16_usize.into(), 2_usize.into()],
        &[8_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn linear_split() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/linear_split.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &[1_usize.into()],
        &[0.into(), 1.into()],
    );

    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &[100_usize.into()],
        &[0.into(), 100.into()],
    );

    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &[1000_usize.into()],
        &[0.into(), 1000.into()],
    );
}
