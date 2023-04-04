use crate::stdlib::prelude::*;

use crate::cairo_run::{self, CairoRunConfig};
use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn fibonacci() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/fibonacci.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn array_sum() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/array_sum.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn big_struct() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/big_struct.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn call_function_assign_param_by_name() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/call_function_assign_param_by_name.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn function_return() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/function_return.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn function_return_if_print() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/function_return_if_print.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn function_return_to_variable() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/function_return_to_variable.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn if_and_prime() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/if_and_prime.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn if_in_function() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/if_in_function.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn if_list() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/if_list.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn jmp() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/jmp.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn jmp_if_condition() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/jmp_if_condition.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn pointers() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/pointers.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn print() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/print.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn program_return() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/return.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn reversed_register_instructions() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/reversed_register_instructions.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn simple_print() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/simple_print.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn test_addition_if() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/test_addition_if.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn test_reverse_if() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/test_reverse_if.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn test_subtraction_if() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/test_subtraction_if.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn use_imported_module() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/use_imported_module.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn bitwise_output() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/bitwise_output.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn bitwise_recursion() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/bitwise_recursion.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn integration() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/integration.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn integration_with_alloc_locals() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/integration_with_alloc_locals.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn compare_arrays() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/compare_arrays.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn compare_greater_array() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/compare_greater_array.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn compare_lesser_array() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/compare_lesser_array.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn assert_le_felt_hint() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/assert_le_felt_hint.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn assert_250_bit_element_array() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/assert_250_bit_element_array.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn abs_value_array() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/abs_value_array.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn compare_different_arrays() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/compare_different_arrays.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn assert_nn() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/assert_nn.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn sqrt() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/sqrt.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn assert_not_zero() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/assert_not_zero.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn split_int() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/split_int.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn split_int_big() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/split_int_big.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn split_felt() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/split_felt.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn math_cmp() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/math_cmp.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn unsigned_div_rem() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/unsigned_div_rem.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn signed_div_rem() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/signed_div_rem.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn assert_lt_felt() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/assert_lt_felt.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn memcpy_test() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/memcpy_test.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn memset() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/memset.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn pow() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/pow.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn dict() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/dict.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn dict_update() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/dict_update.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn uint256() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/uint256.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn find_element() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/find_element.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn search_sorted_lower() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/search_sorted_lower.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn usort() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/usort.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn squash_dict() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/squash_dict.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn dict_squash() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/dict_squash.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn set_add() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/set_add.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn secp() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/secp.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn signature() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/signature.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn secp_ec() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/secp_ec.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn blake2s_hello_world_hash() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/blake2s_hello_world_hash.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn finalize_blake2s() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/finalize_blake2s.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn unsafe_keccak() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/unsafe_keccak.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn blake2s_felts() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/blake2s_felts.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn unsafe_keccak_finalize() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/unsafe_keccak_finalize.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn keccak_add_uint256() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/keccak_add_uint256.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn keccak() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/_keccak.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn keccak_copy_inputs() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/keccak_copy_inputs.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn cairo_finalize_keccak() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/cairo_finalize_keccak.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn operations_with_data_structures() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/operations_with_data_structures.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn sha256() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/sha256.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn math_cmp_and_pow_integration_tests() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/math_cmp_and_pow_integration_tests.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn uint256_integration_tests() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/uint256_integration_tests.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn set_integration_tests() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/set_integration_tests.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn memory_integration_tests() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/memory_integration_tests.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn dict_integration_tests() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/dict_integration_tests.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn secp_integration_tests() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/secp_integration_tests.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn keccak_integration_tests() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/keccak_integration_tests.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn blake2s_integration_tests() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/blake2s_integration_tests.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn relocate_segments() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/relocate_segments.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn dict_store_cast_ptr() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/dict_store_cast_ptr.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn common_signature() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/common_signature.json");
    cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    )
    .expect("Couldn't run program");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn bad_usort() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/bad_programs/bad_usort.json");
    let expected_error_message = "unexpected verify multiplicity fail: positions length != 0";
    let res = cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    );
    assert!(&res
        .err()
        .unwrap()
        .to_string()
        .contains(expected_error_message));
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn bad_dict_new() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/bad_programs/bad_dict_new.json");
    let expected_error_message = "Dict Error: Tried to create a dict whithout an initial dict";
    let res = cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    );
    assert!(&res
        .err()
        .unwrap()
        .to_string()
        .contains(expected_error_message));
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn bad_dict_update() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/bad_programs/bad_dict_update.json");
    let expected_error_message =
        "Dict Error: Got the wrong value for dict_update, expected value: 3, got: 5 for key: 2";
    let res = cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    );
    assert!(&res
        .err()
        .unwrap()
        .to_string()
        .contains(expected_error_message));
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn error_msg_attr() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/bad_programs/error_msg_attr.json");
    let expected_error_message = "SafeUint256: addition overflow";
    let res = cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    );
    assert!(&res
        .err()
        .unwrap()
        .to_string()
        .contains(expected_error_message));
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn error_msg_attr_tempvar() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/bad_programs/error_msg_attr_tempvar.json");

    #[cfg(feature = "std")]
    let expected_error_message = "Error message: SafeUint256: addition overflow: {x} (Cannot evaluate ap-based or complex references: ['x'])\ncairo_programs/bad_programs/error_msg_attr_tempvar.cairo:4:9: Error at pc=0:2:\nAn ASSERT_EQ instruction failed: 3 != 2.\n        assert x = 2;\n        ^***********^\n";
    #[cfg(not(feature = "std"))]
    let expected_error_message = "Error message: SafeUint256: addition overflow: {x} (Cannot evaluate ap-based or complex references: ['x'])\ncairo_programs/bad_programs/error_msg_attr_tempvar.cairo:4:9: Error at pc=0:2:\nAn ASSERT_EQ instruction failed: 3 != 2.\n";
    let res = cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    );
    assert!(&res
        .err()
        .unwrap()
        .to_string()
        .contains(expected_error_message));
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn error_msg_attr_struct() {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let file = include_bytes!("../../cairo_programs/bad_programs/error_msg_attr_struct.json");
    let expected_error_message = "Error message: Cats cannot have more than nine lives: {cat} (Cannot evaluate ap-based or complex references: ['cat'])";
    let res = cairo_run::cairo_run(
        file,
        &CairoRunConfig {
            layout: "all_cairo",
            ..Default::default()
        },
        &mut hint_executor,
    );
    assert!(&res
        .err()
        .unwrap()
        .to_string()
        .contains(expected_error_message));
}
