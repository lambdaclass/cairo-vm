use cairo_vm::cairo_run;
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use std::path::Path;

#[test]
fn cairo_run_test() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/fibonacci.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_array_sum() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/array_sum.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_big_struct() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/big_struct.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_call_function_assign_param_by_name() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/call_function_assign_param_by_name.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_function_return() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/function_return.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_function_return_if_print() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/function_return_if_print.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_function_return_to_variable() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/function_return_to_variable.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_if_and_prime() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/if_and_prime.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_if_in_function() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/if_in_function.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_if_list() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/if_list.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_jmp() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/jmp.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_jmp_if_condition() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/jmp_if_condition.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_pointers() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/pointers.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_print() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/print.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_return() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/return.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_reversed_register_instructions() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/reversed_register_instructions.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_simple_print() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/simple_print.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_test_addition_if() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/test_addition_if.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_test_reverse_if() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/test_reverse_if.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_test_subtraction_if() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/test_subtraction_if.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_use_imported_module() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/use_imported_module.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_bitwise_output() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/bitwise_output.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_bitwise_recursion() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/bitwise_recursion.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_integration() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/integration.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_integration_with_alloc_locals() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/integration_with_alloc_locals.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_compare_arrays() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/compare_arrays.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_compare_greater_array() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/compare_greater_array.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_compare_lesser_array() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/compare_lesser_array.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_assert_le_felt_hint() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/assert_le_felt_hint.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_assert_250_bit_element_array() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/assert_250_bit_element_array.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_abs_value() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/abs_value_array.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_compare_different_arrays() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/compare_different_arrays.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_assert_nn() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/assert_nn.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_sqrt() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/sqrt.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_assert_not_zero() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/assert_not_zero.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_split_int() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/split_int.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_split_int_big() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/split_int_big.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_split_felt() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/split_felt.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_math_cmp() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/math_cmp.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_unsigned_div_rem() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/unsigned_div_rem.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_signed_div_rem() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/signed_div_rem.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_assert_lt_felt() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/assert_lt_felt.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_memcpy() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/memcpy_test.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_memset() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/memset.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_pow() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/pow.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_dict() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/dict.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_dict_update() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/dict_update.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_uint256() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/uint256.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_find_element() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/find_element.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_search_sorted_lower() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/search_sorted_lower.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_usort() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/usort.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_usort_bad() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    let err = cairo_run::cairo_run(
        Path::new("cairo_programs/bad_programs/bad_usort.json"),
        &cairo_run_config,
        &mut hint_executor,
    );
    assert!(err.is_err());
    assert!(err
        .err()
        .unwrap()
        .to_string()
        .contains("unexpected verify multiplicity fail: positions length != 0"));
}

#[test]
fn cairo_run_dict_write_bad() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    assert!(cairo_run::cairo_run(
        Path::new("cairo_programs/bad_programs/bad_dict_new.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .is_err());

    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    let err = cairo_run::cairo_run(
        Path::new("cairo_programs/bad_programs/bad_dict_new.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .err();
    assert!(err
        .unwrap()
        .to_string()
        .contains("Dict Error: Tried to create a dict whithout an initial dict"));
}

#[test]
fn cairo_run_dict_update_bad() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    assert!(cairo_run::cairo_run(
        Path::new("cairo_programs/bad_programs/bad_dict_update.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .is_err());

    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    let err = cairo_run::cairo_run(
        Path::new("cairo_programs/bad_programs/bad_dict_update.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .err();
    assert!(err.unwrap().to_string().contains(
        "Dict Error: Got the wrong value for dict_update, expected value: 3, got: 5 for key: 2"
    ));
}

#[test]
fn cairo_run_squash_dict() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/squash_dict.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_dict_squash() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/dict_squash.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_set_add() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/set_add.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_secp() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/secp.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_signature() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/signature.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_secp_ec() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/secp_ec.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_blake2s_hello_world_hash() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/blake2s_hello_world_hash.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_finalize_blake2s() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/finalize_blake2s.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}
#[test]
fn cairo_run_unsafe_keccak() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/unsafe_keccak.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_blake2s_felts() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/blake2s_felts.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_unsafe_keccak_finalize() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/unsafe_keccak_finalize.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_keccak_add_uint256() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/keccak_add_uint256.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_private_keccak() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/_keccak.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_keccak_copy_inputs() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/keccak_copy_inputs.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_finalize_keccak() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/cairo_finalize_keccak.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_operations_with_data() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/operations_with_data_structures.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_sha256() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/sha256.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_math_cmp_and_pow_integration() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/math_cmp_and_pow_integration_tests.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_uint256_integration() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/uint256_integration_tests.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_set_integration() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/set_integration_tests.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_memory_module_integration() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/memory_integration_tests.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_dict_integration() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/dict_integration_tests.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_secp_integration() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/secp_integration_tests.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_keccak_integration() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/keccak_integration_tests.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_blake2s_integration() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/blake2s_integration_tests.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_relocate_segments() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/relocate_segments.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_error_msg_attr() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    let err = cairo_run::cairo_run(
        Path::new("cairo_programs/bad_programs/error_msg_attr.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .err()
    .unwrap();

    assert!(err.to_string().contains("SafeUint256: addition overflow"));
}

#[test]
fn cairo_run_error_msg_attr_ap_based_reference() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    let err = cairo_run::cairo_run(
        Path::new("cairo_programs/bad_programs/error_msg_attr_tempvar.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .err()
    .unwrap();

    assert_eq!(err.to_string(), String::from("Error message: SafeUint256: addition overflow: {x} (Cannot evaluate ap-based or complex references: ['x'])\ncairo_programs/bad_programs/error_msg_attr_tempvar.cairo:4:9: Error at pc=0:2:\nAn ASSERT_EQ instruction failed: 3 != 2.\n        assert x = 2;\n        ^***********^\n"));
}

#[test]
fn cairo_run_error_msg_attr_complex_reference() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    let err = cairo_run::cairo_run(
        Path::new("cairo_programs/bad_programs/error_msg_attr_struct.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .err()
    .unwrap();
    assert!(err.to_string().contains("Error message: Cats cannot have more than nine lives: {cat} (Cannot evaluate ap-based or complex references: ['cat'])"))
}

#[test]
fn cairo_run_dict_store_cast_pointer() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "small",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/dict_store_cast_ptr.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
fn cairo_run_verify_signature_hint() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    cairo_run::cairo_run(
        Path::new("cairo_programs/common_signature.json"),
        &cairo_run_config,
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}
