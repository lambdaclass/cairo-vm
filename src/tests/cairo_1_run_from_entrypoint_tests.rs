use crate::tests::*;

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn test_uint256_div_mod_hint() {
    let program_data =
        include_bytes!("../../cairo_programs/cairo-1-contracts/uint256_div_mod.casm");

    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &[8_usize.into(), 2_usize.into()],
        &[Felt252::from(4_usize).into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn test_less_than_or_equal() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/test_less_than.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &[8_usize.into()],
        &[1_u8.into()],
    );

    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &[290_usize.into()],
        &[0_u8.into()],
    );

    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &[250_usize.into()],
        &[1_u8.into()],
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
fn boxed_fibonacci() {
    let program_data =
        include_bytes!("../../cairo_programs/cairo-1-contracts/alloc_constant_size.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &[3_usize.into(), 3_usize.into(), 3_usize.into()],
        &[9_usize.into()],
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
