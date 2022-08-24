use std::path::Path;

use cairo_rs::cairo_run;
use cairo_rs::vm::hints::execute_hint::BuiltinHintExecutor;

static HINT_EXECUTOR: BuiltinHintExecutor = BuiltinHintExecutor {};

#[test]
fn cairo_run_test() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/fibonacci.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_bitwise_output() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/bitwise_output.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_bitwise_recursion() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/bitwise_recursion.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_integration() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/integration.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_integration_with_alloc_locals() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/integration_with_alloc_locals.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_compare_arrays() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/compare_arrays.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_compare_greater_array() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/compare_greater_array.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_compare_lesser_array() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/compare_lesser_array.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_assert_le_felt_hint() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/assert_le_felt_hint.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_assert_250_bit_element_array() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/assert_250_bit_element_array.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_abs_value() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/abs_value_array.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_compare_different_arrays() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/compare_different_arrays.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_assert_nn() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/assert_nn.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_sqrt() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/sqrt.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_assert_not_zero() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/assert_not_zero.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_split_int() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/split_int.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_split_int_big() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/split_int_big.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_split_felt() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/split_felt.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_math_cmp() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/math_cmp.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_unsigned_div_rem() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/unsigned_div_rem.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_signed_div_rem() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/signed_div_rem.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_assert_lt_felt() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/assert_lt_felt.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_memcpy() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/memcpy_test.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_memset() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/memset.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_pow() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/pow.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_dict() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/dict.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_dict_update() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/dict_update.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_uint256() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/uint256.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_find_element() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/find_element.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_search_sorted_lower() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/search_sorted_lower.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_usort() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/usort.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_usort_bad() {
    let err = cairo_run::cairo_run(
        Path::new("cairo_programs/bad_programs/bad_usort.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    );
    assert!(err.is_err());
    assert_eq!(
        err.err().unwrap().to_string(),
        "VM failure: unexpected verify multiplicity fail: positions length != 0"
    );
}

#[test]
fn cairo_run_dict_write_bad() {
    assert!(cairo_run::cairo_run(
        Path::new("cairo_programs/bad_programs/bad_dict_new.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .is_err());
    let err = cairo_run::cairo_run(
        Path::new("cairo_programs/bad_programs/bad_dict_new.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .err();
    assert_eq!(
        err.unwrap().to_string(),
        "VM failure: Dict Error: Tried to create a dict whithout an initial dict"
    );
}

#[test]
fn cairo_run_dict_update_bad() {
    assert!(cairo_run::cairo_run(
        Path::new("cairo_programs/bad_programs/bad_dict_update.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .is_err());
    let err = cairo_run::cairo_run(
        Path::new("cairo_programs/bad_programs/bad_dict_update.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .err();
    assert_eq!(
        err.unwrap().to_string(),
        "VM failure: Dict Error: Got the wrong value for dict_update, expected value: 3, got: 5 for key: 2"
    );
}

#[test]
fn cairo_run_squash_dict() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/squash_dict.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_dict_squash() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/dict_squash.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_set_add() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/set_add.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_secp() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/secp.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_signature() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/signature.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_secp_ec() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/secp_ec.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_blake2s_hello_world_hash() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/blake2s_hello_world_hash.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_finalize_blake2s() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/finalize_blake2s.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}
#[test]
fn cairo_run_unsafe_keccak() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/unsafe_keccak.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_blake2s_felts() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/blake2s_felts.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_unsafe_keccak_finalize() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/unsafe_keccak_finalize.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_keccak_add_uint256() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/keccak_add_uint256.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_private_keccak() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/_keccak.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_keccak_copy_inputs() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/keccak_copy_inputs.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_finalize_keccak() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/cairo_finalize_keccak.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_operations_with_data() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/operations_with_data_structures.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_sha256() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/sha256.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_math_cmp_and_pow_integration() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/math_cmp_and_pow_integration_tests.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_uint256_integration() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/uint256_integration_tests.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_set_integration() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/set_integration_tests.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_memory_module_integration() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/memory_integration_tests.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_dict_integration() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/dict_integration_tests.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_secp_integration() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/secp_integration_tests.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_keccak_integration() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/keccak_integration_tests.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_blake2s_integration() {
    cairo_run::cairo_run(
        Path::new("cairo_programs/blake2s_integration_tests.json"),
        "main",
        false,
        &HINT_EXECUTOR,
    )
    .expect("Couldn't run program");
}
