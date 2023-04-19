use crate::tests::*;

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn fibonacci() {
    let program_data = include_bytes!("../../cairo_programs/fibonacci.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn array_sum() {
    let program_data = include_bytes!("../../cairo_programs/array_sum.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn big_struct() {
    let program_data = include_bytes!("../../cairo_programs/big_struct.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn call_function_assign_param_by_name() {
    let program_data =
        include_bytes!("../../cairo_programs/call_function_assign_param_by_name.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn function_return() {
    let program_data = include_bytes!("../../cairo_programs/function_return.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn function_return_if_print() {
    let program_data = include_bytes!("../../cairo_programs/function_return_if_print.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn function_return_to_variable() {
    let program_data = include_bytes!("../../cairo_programs/function_return_to_variable.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn if_and_prime() {
    let program_data = include_bytes!("../../cairo_programs/if_and_prime.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn if_in_function() {
    let program_data = include_bytes!("../../cairo_programs/if_in_function.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn if_list() {
    let program_data = include_bytes!("../../cairo_programs/if_list.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn jmp() {
    let program_data = include_bytes!("../../cairo_programs/jmp.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn jmp_if_condition() {
    let program_data = include_bytes!("../../cairo_programs/jmp_if_condition.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn pointers() {
    let program_data = include_bytes!("../../cairo_programs/pointers.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn print() {
    let program_data = include_bytes!("../../cairo_programs/print.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn program_return() {
    let program_data = include_bytes!("../../cairo_programs/return.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn reversed_register_instructions() {
    let program_data = include_bytes!("../../cairo_programs/reversed_register_instructions.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn simple_print() {
    let program_data = include_bytes!("../../cairo_programs/simple_print.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn test_addition_if() {
    let program_data = include_bytes!("../../cairo_programs/test_addition_if.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn test_reverse_if() {
    let program_data = include_bytes!("../../cairo_programs/test_reverse_if.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn test_subtraction_if() {
    let program_data = include_bytes!("../../cairo_programs/test_subtraction_if.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn use_imported_module() {
    let program_data = include_bytes!("../../cairo_programs/use_imported_module.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn bitwise_output() {
    let program_data = include_bytes!("../../cairo_programs/bitwise_output.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn bitwise_recursion() {
    let program_data = include_bytes!("../../cairo_programs/bitwise_recursion.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn integration() {
    let program_data = include_bytes!("../../cairo_programs/integration.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn integration_with_alloc_locals() {
    let program_data = include_bytes!("../../cairo_programs/integration_with_alloc_locals.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn compare_arrays() {
    let program_data = include_bytes!("../../cairo_programs/compare_arrays.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn compare_greater_array() {
    let program_data = include_bytes!("../../cairo_programs/compare_greater_array.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn compare_lesser_array() {
    let program_data = include_bytes!("../../cairo_programs/compare_lesser_array.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn assert_le_felt_hint() {
    let program_data = include_bytes!("../../cairo_programs/assert_le_felt_hint.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn assert_250_bit_element_array() {
    let program_data = include_bytes!("../../cairo_programs/assert_250_bit_element_array.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn abs_value_array() {
    let program_data = include_bytes!("../../cairo_programs/abs_value_array.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn compare_different_arrays() {
    let program_data = include_bytes!("../../cairo_programs/compare_different_arrays.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn assert_nn() {
    let program_data = include_bytes!("../../cairo_programs/assert_nn.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn sqrt() {
    let program_data = include_bytes!("../../cairo_programs/sqrt.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn assert_not_zero() {
    let program_data = include_bytes!("../../cairo_programs/assert_not_zero.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn split_int() {
    let program_data = include_bytes!("../../cairo_programs/split_int.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn split_int_big() {
    let program_data = include_bytes!("../../cairo_programs/split_int_big.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn split_felt() {
    let program_data = include_bytes!("../../cairo_programs/split_felt.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn math_cmp() {
    let program_data = include_bytes!("../../cairo_programs/math_cmp.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn unsigned_div_rem() {
    let program_data = include_bytes!("../../cairo_programs/unsigned_div_rem.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn signed_div_rem() {
    let program_data = include_bytes!("../../cairo_programs/signed_div_rem.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn assert_lt_felt() {
    let program_data = include_bytes!("../../cairo_programs/assert_lt_felt.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn memcpy_test() {
    let program_data = include_bytes!("../../cairo_programs/memcpy_test.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn memset() {
    let program_data = include_bytes!("../../cairo_programs/memset.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn pow() {
    let program_data = include_bytes!("../../cairo_programs/pow.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn dict() {
    let program_data = include_bytes!("../../cairo_programs/dict.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn dict_update() {
    let program_data = include_bytes!("../../cairo_programs/dict_update.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn uint256() {
    let program_data = include_bytes!("../../cairo_programs/uint256.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn find_element() {
    let program_data = include_bytes!("../../cairo_programs/find_element.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn search_sorted_lower() {
    let program_data = include_bytes!("../../cairo_programs/search_sorted_lower.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn usort() {
    let program_data = include_bytes!("../../cairo_programs/usort.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn squash_dict() {
    let program_data = include_bytes!("../../cairo_programs/squash_dict.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn dict_squash() {
    let program_data = include_bytes!("../../cairo_programs/dict_squash.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn set_add() {
    let program_data = include_bytes!("../../cairo_programs/set_add.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn secp() {
    let program_data = include_bytes!("../../cairo_programs/secp.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn signature() {
    let program_data = include_bytes!("../../cairo_programs/signature.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn secp_ec() {
    let program_data = include_bytes!("../../cairo_programs/secp_ec.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn blake2s_hello_world_hash() {
    let program_data = include_bytes!("../../cairo_programs/blake2s_hello_world_hash.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn finalize_blake2s() {
    let program_data = include_bytes!("../../cairo_programs/finalize_blake2s.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn unsafe_keccak() {
    let program_data = include_bytes!("../../cairo_programs/unsafe_keccak.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn blake2s_felts() {
    let program_data = include_bytes!("../../cairo_programs/blake2s_felts.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn unsafe_keccak_finalize() {
    let program_data = include_bytes!("../../cairo_programs/unsafe_keccak_finalize.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn keccak_add_uint256() {
    let program_data = include_bytes!("../../cairo_programs/keccak_add_uint256.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn keccak() {
    let program_data = include_bytes!("../../cairo_programs/_keccak.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn keccak_copy_inputs() {
    let program_data = include_bytes!("../../cairo_programs/keccak_copy_inputs.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_finalize_keccak() {
    let program_data = include_bytes!("../../cairo_programs/cairo_finalize_keccak.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn operations_with_data_structures() {
    let program_data = include_bytes!("../../cairo_programs/operations_with_data_structures.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn sha256() {
    let program_data = include_bytes!("../../cairo_programs/sha256.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn math_cmp_and_pow_integration_tests() {
    let program_data =
        include_bytes!("../../cairo_programs/math_cmp_and_pow_integration_tests.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn uint256_integration_tests() {
    let program_data = include_bytes!("../../cairo_programs/uint256_integration_tests.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn set_integration_tests() {
    let program_data = include_bytes!("../../cairo_programs/set_integration_tests.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn memory_integration_tests() {
    let program_data = include_bytes!("../../cairo_programs/memory_integration_tests.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn dict_integration_tests() {
    let program_data = include_bytes!("../../cairo_programs/dict_integration_tests.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn secp_integration_tests() {
    let program_data = include_bytes!("../../cairo_programs/secp_integration_tests.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn keccak_integration_tests() {
    let program_data = include_bytes!("../../cairo_programs/keccak_integration_tests.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn blake2s_integration_tests() {
    let program_data = include_bytes!("../../cairo_programs/blake2s_integration_tests.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn relocate_segments() {
    let program_data = include_bytes!("../../cairo_programs/relocate_segments.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn dict_store_cast_ptr() {
    let program_data = include_bytes!("../../cairo_programs/dict_store_cast_ptr.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn common_signature() {
    let program_data = include_bytes!("../../cairo_programs/common_signature.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn bad_usort() {
    let program_data = include_bytes!("../../cairo_programs/bad_programs/bad_usort.json");
    let error_msg = "unexpected verify multiplicity fail: positions length != 0";
    run_program_with_error(program_data.as_slice(), error_msg);
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn bad_dict_new() {
    let program_data = include_bytes!("../../cairo_programs/bad_programs/bad_dict_new.json");
    let error_msg = "Dict Error: Tried to create a dict whithout an initial dict";
    run_program_with_error(program_data.as_slice(), error_msg);
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn bad_dict_update() {
    let program_data = include_bytes!("../../cairo_programs/bad_programs/bad_dict_update.json");
    let error_msg =
        "Dict Error: Got the wrong value for dict_update, expected value: 3, got: 5 for key: 2";
    run_program_with_error(program_data.as_slice(), error_msg);
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn error_msg_attr() {
    let program_data = include_bytes!("../../cairo_programs/bad_programs/error_msg_attr.json");
    let error_msg = "SafeUint256: addition overflow";
    run_program_with_error(program_data.as_slice(), error_msg);
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn error_msg_attr_tempvar() {
    let program_data =
        include_bytes!("../../cairo_programs/bad_programs/error_msg_attr_tempvar.json");

    #[cfg(feature = "std")]
    let error_msg = "Error message: SafeUint256: addition overflow: {x} (Cannot evaluate ap-based or complex references: ['x'])\ncairo_programs/bad_programs/error_msg_attr_tempvar.cairo:4:9: Error at pc=0:2:\nAn ASSERT_EQ instruction failed: 3 != 2.\n        assert x = 2;\n        ^***********^\n";
    #[cfg(not(feature = "std"))]
    let error_msg = "Error message: SafeUint256: addition overflow: {x} (Cannot evaluate ap-based or complex references: ['x'])\ncairo_programs/bad_programs/error_msg_attr_tempvar.cairo:4:9: Error at pc=0:2:\nAn ASSERT_EQ instruction failed: 3 != 2.\n";
    run_program_with_error(program_data.as_slice(), error_msg);
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn error_msg_attr_struct() {
    let program_data =
        include_bytes!("../../cairo_programs/bad_programs/error_msg_attr_struct.json");
    let error_msg = "Error message: Cats cannot have more than nine lives: {cat} (Cannot evaluate ap-based or complex references: ['cat'])";
    run_program_with_error(program_data.as_slice(), error_msg);
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_test() {
    let program_data = include_bytes!("../../cairo_programs/fibonacci.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_array_sum() {
    let program_data = include_bytes!("../../cairo_programs/array_sum.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_big_struct() {
    let program_data = include_bytes!("../../cairo_programs/big_struct.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_call_function_assign_param_by_name() {
    let program_data =
        include_bytes!("../../cairo_programs/call_function_assign_param_by_name.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_function_return() {
    let program_data = include_bytes!("../../cairo_programs/function_return.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_function_return_if_print() {
    let program_data = include_bytes!("../../cairo_programs/function_return_if_print.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_function_return_to_variable() {
    let program_data = include_bytes!("../../cairo_programs/function_return_to_variable.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_if_and_prime() {
    let program_data = include_bytes!("../../cairo_programs/if_and_prime.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_if_in_function() {
    let program_data = include_bytes!("../../cairo_programs/if_in_function.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_if_list() {
    let program_data = include_bytes!("../../cairo_programs/if_list.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_jmp() {
    let program_data = include_bytes!("../../cairo_programs/jmp.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_jmp_if_condition() {
    let program_data = include_bytes!("../../cairo_programs/jmp_if_condition.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_pointers() {
    let program_data = include_bytes!("../../cairo_programs/pointers.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_print() {
    let program_data = include_bytes!("../../cairo_programs/print.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_return() {
    let program_data = include_bytes!("../../cairo_programs/return.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_reversed_register_instructions() {
    let program_data = include_bytes!("../../cairo_programs/reversed_register_instructions.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_simple_print() {
    let program_data = include_bytes!("../../cairo_programs/simple_print.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_test_addition_if() {
    let program_data = include_bytes!("../../cairo_programs/test_addition_if.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_test_reverse_if() {
    let program_data = include_bytes!("../../cairo_programs/test_reverse_if.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_test_subtraction_if() {
    let program_data = include_bytes!("../../cairo_programs/test_subtraction_if.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_use_imported_module() {
    let program_data = include_bytes!("../../cairo_programs/use_imported_module.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_bitwise_output() {
    let program_data = include_bytes!("../../cairo_programs/bitwise_output.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_bitwise_recursion() {
    let program_data = include_bytes!("../../cairo_programs/bitwise_recursion.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_integration() {
    let program_data = include_bytes!("../../cairo_programs/integration.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_integration_with_alloc_locals() {
    let program_data = include_bytes!("../../cairo_programs/integration_with_alloc_locals.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_compare_arrays() {
    let program_data = include_bytes!("../../cairo_programs/compare_arrays.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_compare_greater_array() {
    let program_data = include_bytes!("../../cairo_programs/compare_greater_array.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_compare_lesser_array() {
    let program_data = include_bytes!("../../cairo_programs/compare_lesser_array.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_assert_le_felt_hint() {
    let program_data = include_bytes!("../../cairo_programs/assert_le_felt_hint.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_assert_250_bit_element_array() {
    let program_data = include_bytes!("../../cairo_programs/assert_250_bit_element_array.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_abs_value() {
    let program_data = include_bytes!("../../cairo_programs/abs_value_array.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_compare_different_arrays() {
    let program_data = include_bytes!("../../cairo_programs/compare_different_arrays.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_assert_nn() {
    let program_data = include_bytes!("../../cairo_programs/assert_nn.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_sqrt() {
    let program_data = include_bytes!("../../cairo_programs/sqrt.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_assert_not_zero() {
    let program_data = include_bytes!("../../cairo_programs/assert_not_zero.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_split_int() {
    let program_data = include_bytes!("../../cairo_programs/split_int.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_split_int_big() {
    let program_data = include_bytes!("../../cairo_programs/split_int_big.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_split_felt() {
    let program_data = include_bytes!("../../cairo_programs/split_felt.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_math_cmp() {
    let program_data = include_bytes!("../../cairo_programs/math_cmp.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_unsigned_div_rem() {
    let program_data = include_bytes!("../../cairo_programs/unsigned_div_rem.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_signed_div_rem() {
    let program_data = include_bytes!("../../cairo_programs/signed_div_rem.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_assert_lt_felt() {
    let program_data = include_bytes!("../../cairo_programs/assert_lt_felt.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_memcpy() {
    let program_data = include_bytes!("../../cairo_programs/memcpy_test.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_memset() {
    let program_data = include_bytes!("../../cairo_programs/memset.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_pow() {
    let program_data = include_bytes!("../../cairo_programs/pow.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_dict() {
    let program_data = include_bytes!("../../cairo_programs/dict.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_dict_update() {
    let program_data = include_bytes!("../../cairo_programs/dict_update.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_uint256() {
    let program_data = include_bytes!("../../cairo_programs/uint256.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_find_element() {
    let program_data = include_bytes!("../../cairo_programs/find_element.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_search_sorted_lower() {
    let program_data = include_bytes!("../../cairo_programs/search_sorted_lower.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_usort() {
    let program_data = include_bytes!("../../cairo_programs/usort.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_usort_bad() {
    let program_data = include_bytes!("../../cairo_programs/bad_programs/bad_usort.json");
    let error_msg = "unexpected verify multiplicity fail: positions length != 0";
    run_program_with_error(program_data.as_slice(), error_msg);
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_dict_write_bad() {
    let program_data = include_bytes!("../../cairo_programs/bad_programs/bad_dict_new.json");
    let error_msg = "Dict Error: Tried to create a dict whithout an initial dict";
    run_program_with_error(program_data.as_slice(), error_msg);
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_dict_update_bad() {
    let program_data = include_bytes!("../../cairo_programs/bad_programs/bad_dict_update.json");
    let error_msg =
        "Dict Error: Got the wrong value for dict_update, expected value: 3, got: 5 for key: 2";
    run_program_with_error(program_data.as_slice(), error_msg);
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_squash_dict() {
    let program_data = include_bytes!("../../cairo_programs/squash_dict.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_dict_squash() {
    let program_data = include_bytes!("../../cairo_programs/dict_squash.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_set_add() {
    let program_data = include_bytes!("../../cairo_programs/set_add.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_secp() {
    let program_data = include_bytes!("../../cairo_programs/secp.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_signature() {
    let program_data = include_bytes!("../../cairo_programs/signature.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_secp_ec() {
    let program_data = include_bytes!("../../cairo_programs/secp_ec.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_blake2s_hello_world_hash() {
    let program_data = include_bytes!("../../cairo_programs/blake2s_hello_world_hash.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_finalize_blake2s() {
    let program_data = include_bytes!("../../cairo_programs/finalize_blake2s.json");
    run_program_simple(program_data.as_slice());
}
#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_unsafe_keccak() {
    let program_data = include_bytes!("../../cairo_programs/unsafe_keccak.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_blake2s_felts() {
    let program_data = include_bytes!("../../cairo_programs/blake2s_felts.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_unsafe_keccak_finalize() {
    let program_data = include_bytes!("../../cairo_programs/unsafe_keccak_finalize.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_keccak_add_uint256() {
    let program_data = include_bytes!("../../cairo_programs/keccak_add_uint256.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_private_keccak() {
    let program_data = include_bytes!("../../cairo_programs/_keccak.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_keccak_copy_inputs() {
    let program_data = include_bytes!("../../cairo_programs/keccak_copy_inputs.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_finalize_keccak() {
    let program_data = include_bytes!("../../cairo_programs/cairo_finalize_keccak.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_operations_with_data() {
    let program_data = include_bytes!("../../cairo_programs/operations_with_data_structures.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_sha256() {
    let program_data = include_bytes!("../../cairo_programs/sha256.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_math_cmp_and_pow_integration() {
    let program_data =
        include_bytes!("../../cairo_programs/math_cmp_and_pow_integration_tests.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_uint256_integration() {
    let program_data = include_bytes!("../../cairo_programs/uint256_integration_tests.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_set_integration() {
    let program_data = include_bytes!("../../cairo_programs/set_integration_tests.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_memory_module_integration() {
    let program_data = include_bytes!("../../cairo_programs/memory_integration_tests.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_dict_integration() {
    let program_data = include_bytes!("../../cairo_programs/dict_integration_tests.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_secp_integration() {
    let program_data = include_bytes!("../../cairo_programs/secp_integration_tests.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_keccak_integration() {
    let program_data = include_bytes!("../../cairo_programs/keccak_integration_tests.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_blake2s_integration() {
    let program_data = include_bytes!("../../cairo_programs/blake2s_integration_tests.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_relocate_segments() {
    let program_data = include_bytes!("../../cairo_programs/relocate_segments.json");
    run_program_small(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_error_msg_attr() {
    let program_data = include_bytes!("../../cairo_programs/bad_programs/error_msg_attr.json");
    let error_msg = "SafeUint256: addition overflow";
    run_program_with_error(program_data.as_slice(), error_msg);
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_error_msg_attr_ap_based_reference() {
    let program_data =
        include_bytes!("../../cairo_programs/bad_programs/error_msg_attr_tempvar.json");
    #[cfg(feature = "std")]
    let error_msg = "Error message: SafeUint256: addition overflow: {x} (Cannot evaluate ap-based or complex references: ['x'])\ncairo_programs/bad_programs/error_msg_attr_tempvar.cairo:4:9: Error at pc=0:2:\nAn ASSERT_EQ instruction failed: 3 != 2.\n        assert x = 2;\n        ^***********^\n";
    #[cfg(not(feature = "std"))]
    let error_msg = "Error message: SafeUint256: addition overflow: {x} (Cannot evaluate ap-based or complex references: ['x'])\ncairo_programs/bad_programs/error_msg_attr_tempvar.cairo:4:9: Error at pc=0:2:\nAn ASSERT_EQ instruction failed: 3 != 2.\n";
    run_program_with_error(program_data.as_slice(), error_msg);
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_error_msg_attr_complex_reference() {
    let program_data =
        include_bytes!("../../cairo_programs/bad_programs/error_msg_attr_struct.json");
    let error_msg = "Error message: Cats cannot have more than nine lives: {cat} (Cannot evaluate ap-based or complex references: ['cat'])";
    run_program_with_error(program_data.as_slice(), error_msg);
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_dict_store_cast_pointer() {
    let program_data = include_bytes!("../../cairo_programs/dict_store_cast_ptr.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_verify_signature_hint() {
    let program_data = include_bytes!("../../cairo_programs/common_signature.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_poseidon_builtin() {
    let program_data = include_bytes!("../../cairo_programs/poseidon_builtin.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_ec_op() {
    let program_data = include_bytes!("../../cairo_programs/ec_op.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_poseidon_hash() {
    let program_data = include_bytes!("../../cairo_programs/poseidon_hash.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_chained_run_ec_op() {
    let program_data = include_bytes!("../../cairo_programs/chained_ec_op.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_keccak_builtin() {
    let program_data = include_bytes!("../../cairo_programs/keccak_builtin.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_keccak_uint256() {
    let program_data = include_bytes!("../../cairo_programs/keccak_uint256.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_recover_y() {
    let program_data = include_bytes!("../../cairo_programs/recover_y.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_math_integration() {
    let program_data = include_bytes!("../../cairo_programs/math_integration_tests.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_is_quad_residue_test() {
    let program_data = include_bytes!("../../cairo_programs/is_quad_residue_test.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_mul_s_inv() {
    let program_data = include_bytes!("../../cairo_programs/mul_s_inv.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_keccak_alternative_hint() {
    let program_data = include_bytes!("../../cairo_programs/_keccak_alternative_hint.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_uint384() {
    let program_data = include_bytes!("../../cairo_programs/uint384.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_uint384_extension() {
    let program_data = include_bytes!("../../cairo_programs/uint384_extension.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_ed25519_field() {
    let program_data = include_bytes!("../../cairo_programs/ed25519_field.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_ed25519_ec() {
    let program_data = include_bytes!("../../cairo_programs/ed25519_ec.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_efficient_secp256r1_ec() {
    let program_data = include_bytes!("../../cairo_programs/efficient_secp256r1_ec.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_div_mod_n() {
    let program_data = include_bytes!("../../cairo_programs/div_mod_n.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_is_zero() {
    let program_data = include_bytes!("../../cairo_programs/is_zero.json");
    run_program_simple(program_data.as_slice());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_run_uint256_improvements() {
    let program_data = include_bytes!("../../cairo_programs/uint256_improvements.json");
    run_program_simple(program_data.as_slice());
}
