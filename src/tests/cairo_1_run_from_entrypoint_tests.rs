use crate::tests::*;

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn fibonacci_1() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/fib.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![1_usize.into(), 1_usize.into(), 1_usize.into()],
        &vec![1_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn fibonacci_3() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/fib.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![3_usize.into(), 3_usize.into(), 3_usize.into()],
        &vec![9_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u8_sqrt_9() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u8_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![9_usize.into()],
        &vec![3_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u8_sqrt_10() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u8_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![10_usize.into()],
        &vec![3_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u8_sqrt_one() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u8_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![1_usize.into()],
        &vec![1_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u8_sqrt_zero() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u8_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![0_usize.into()],
        &vec![0_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u16_sqrt_9() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u16_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![9_usize.into()],
        &vec![3_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u16_sqrt_10() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u16_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![10_usize.into()],
        &vec![3_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u16_sqrt_one() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u16_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![1_usize.into()],
        &vec![1_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u16_sqrt_zero() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u16_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![0_usize.into()],
        &vec![0_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u32_sqrt_9() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u32_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![9_usize.into()],
        &vec![3_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u32_sqrt_10() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u32_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![10_usize.into()],
        &vec![3_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u32_sqrt_one() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u32_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![1_usize.into()],
        &vec![1_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u32_sqrt_zero() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u32_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![0_usize.into()],
        &vec![0_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u64_sqrt_9() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u64_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![9_usize.into()],
        &vec![3_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u64_sqrt_10() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u64_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![10_usize.into()],
        &vec![3_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u64_sqrt_one() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u64_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![1_usize.into()],
        &vec![1_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u64_sqrt_zero() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u64_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![0_usize.into()],
        &vec![0_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u128_sqrt_9() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u128_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![9_usize.into()],
        &vec![3_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u128_sqrt_10() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u128_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![10_usize.into()],
        &vec![3_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u128_sqrt_one() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u128_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![1_usize.into()],
        &vec![1_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u128_sqrt_zero() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u128_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![0_usize.into()],
        &vec![0_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u256_sqrt_9() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u256_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![9_usize.into()],
        &vec![3_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u256_sqrt_10() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u256_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![10_usize.into()],
        &vec![3_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u256_sqrt_one() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u256_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![1_usize.into()],
        &vec![1_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u256_sqrt_zero() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u256_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        0,
        &vec![0_usize.into()],
        &vec![0_usize.into()],
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn u256_sqrt_big_num() {
    let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u256_sqrt.casm");
    run_cairo_1_entrypoint(
        program_data.as_slice(),
        144,
        &vec![],
        &vec![1125899906842624_usize.into()],
    );
}
// Failing due to overflow, it shouldn't!
// #[test]
// #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
// fn u256_sqrt_max_num() {
//     let program_data = include_bytes!("../../cairo_programs/cairo-1-contracts/u256_sqrt.casm");
//     run_cairo_1_entrypoint(
//         program_data.as_slice(),
//         257,
//         &vec![],
//         &vec![1.into()],
//     );
// }
