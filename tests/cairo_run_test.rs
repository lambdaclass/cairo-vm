use std::path::Path;

use cleopatra_cairo::cairo_run;

#[test]
fn cairo_run_test() {
    cairo_run::cairo_run(Path::new("cairo_programs/fibonacci.json")).expect("Couldn't run program");
}

#[test]
fn cairo_run_bitwise_output() {
    cairo_run::cairo_run(Path::new("cairo_programs/bitwise_output.json"))
        .expect("Couldn't run program");
}

#[test]
fn cairo_run_bitwise_recursion() {
    cairo_run::cairo_run(Path::new("cairo_programs/bitwise_recursion.json"))
        .expect("Couldn't run program");
}

#[test]
fn cairo_run_integration() {
    cairo_run::cairo_run(Path::new("cairo_programs/integration.json"))
        .expect("Couldn't run program");
}

#[test]
fn cairo_run_integration_with_alloc_locals() {
    cairo_run::cairo_run(Path::new(
        "cairo_programs/integration_with_alloc_locals.json",
    ))
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_compare_arrays() {
    cairo_run::cairo_run(Path::new("cairo_programs/compare_arrays.json"))
        .expect("Couldn't run program");
}

#[test]
fn cairo_run_compare_greater_array() {
    cairo_run::cairo_run(Path::new("cairo_programs/compare_greater_array.json"))
        .expect("Couldn't run program");
}

#[test]
fn cairo_run_compare_lesser_array() {
    cairo_run::cairo_run(Path::new("cairo_programs/compare_lesser_array.json"))
        .expect("Couldn't run program");
}

#[test]
fn cairo_run_assert_le_felt_hint() {
    cairo_run::cairo_run(Path::new("cairo_programs/assert_le_felt_hint.json"))
        .expect("Couldn't run program");
}

#[test]
fn cairo_run_assert_250_bit_element_array() {
    cairo_run::cairo_run(Path::new(
        "cairo_programs/assert_250_bit_element_array.json",
    ))
    .expect("Couldn't run program");
}

#[test]
fn cairo_abs_value() {
    cairo_run::cairo_run(Path::new("cairo_programs/abs_value_array.json"))
        .expect("Couldn't run program");
}

#[test]
fn cairo_run_compare_different_arrays() {
    cairo_run::cairo_run(Path::new("cairo_programs/compare_different_arrays.json"))
        .expect("Couldn't run program");
}

#[test]
fn cairo_run_assert_nn() {
    cairo_run::cairo_run(Path::new("cairo_programs/assert_nn.json")).expect("Couldn't run program");
}

#[test]
fn cairo_run_sqrt() {
    cairo_run::cairo_run(Path::new("cairo_programs/sqrt.json")).expect("Couldn't run program");
}

#[test]
fn cairo_run_assert_not_zero() {
    cairo_run::cairo_run(Path::new("cairo_programs/assert_not_zero.json"))
        .expect("Couldn't run program");
}

#[test]
fn cairo_run_split_int() {
    cairo_run::cairo_run(Path::new("cairo_programs/split_int.json")).expect("Couldn't run program");
}

#[test]
fn cairo_run_split_int_big() {
    cairo_run::cairo_run(Path::new("cairo_programs/split_int_big.json"))
        .expect("Couldn't run program");
}

#[test]
fn cairo_run_dict() {
    cairo_run::cairo_run(Path::new("cairo_programs/dict.json")).expect("Couldn't run program");
}

#[test]
fn cairo_run_split_felt() {
    cairo_run::cairo_run(Path::new("cairo_programs/split_felt.json"))
        .expect("Couldn't run program");
}

#[test]
fn cairo_run_is_le_felt() {
    cairo_run::cairo_run(Path::new("cairo_programs/math_cmp_is_le_felt.json"))
        .expect("Couldn't run program");
}

#[test]
fn cairo_run_unsigned_div_rem() {
    cairo_run::cairo_run(Path::new("cairo_programs/unsigned_div_rem.json"))
        .expect("Couldn't run program");
}

#[test]
fn cairo_run_assert_lt_felt() {
    cairo_run::cairo_run(Path::new("cairo_programs/assert_lt_felt.json"))
        .expect("Couldn't run program");
}
