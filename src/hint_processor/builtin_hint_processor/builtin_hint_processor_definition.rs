use crate::any_box;
use crate::hint_processor::builtin_hint_processor::blake2s_utils::{
    blake2s_add_uint256, blake2s_add_uint256_bigend, compute_blake2s, finalize_blake2s,
};
use crate::hint_processor::builtin_hint_processor::dict_hint_utils::{
    default_dict_new, dict_new, dict_read, dict_squash_copy_dict, dict_squash_update_ptr,
    dict_update, dict_write,
};
use crate::hint_processor::builtin_hint_processor::find_element_hint::{
    find_element, search_sorted_lower,
};
use crate::hint_processor::builtin_hint_processor::hint_code;
use crate::hint_processor::builtin_hint_processor::keccak_utils::{
    unsafe_keccak, unsafe_keccak_finalize,
};
use crate::hint_processor::builtin_hint_processor::math_utils::*;
use crate::hint_processor::builtin_hint_processor::memcpy_hint_utils::{
    add_segment, enter_scope, exit_scope, memcpy_continue_copying, memcpy_enter_scope,
};
use crate::hint_processor::builtin_hint_processor::memset_utils::{
    memset_continue_loop, memset_enter_scope,
};
use crate::hint_processor::builtin_hint_processor::pow_utils::pow;
use crate::hint_processor::builtin_hint_processor::set::set_add;
use crate::hint_processor::builtin_hint_processor::squash_dict_utils::{
    squash_dict, squash_dict_inner_assert_len_keys, squash_dict_inner_check_access_index,
    squash_dict_inner_continue_loop, squash_dict_inner_first_iteration,
    squash_dict_inner_len_assert, squash_dict_inner_next_key, squash_dict_inner_skip_loop,
    squash_dict_inner_used_accesses_assert,
};
use crate::hint_processor::builtin_hint_processor::uint256_utils::{
    split_64, uint256_add, uint256_signed_nn, uint256_sqrt, uint256_unsigned_div_rem,
};
use crate::hint_processor::hint_processor_definition::{HintProcessor, HintReference};
use crate::hint_processor::proxies::exec_scopes_proxy::ExecutionScopesProxy;
use crate::serde::deserialize_program::ApTracking;
use crate::vm::errors::vm_errors::VirtualMachineError;
use std::any::Any;
use std::collections::HashMap;

use crate::hint_processor::builtin_hint_processor::cairo_keccak::keccak_hints::{
    block_permutation, cairo_keccak_finalize, compare_bytes_in_word_nondet,
    compare_keccak_full_rate_in_bytes_nondet, keccak_write_args,
};
use crate::hint_processor::builtin_hint_processor::secp::{
    bigint_utils::{bigint_to_uint256, nondet_bigint3},
    ec_utils::{
        compute_doubling_slope, compute_slope, ec_double_assign_new_x, ec_double_assign_new_y,
        ec_mul_inner, ec_negate, fast_ec_add_assign_new_x, fast_ec_add_assign_new_y,
    },
    field_utils::{
        is_zero_assign_scope_variables, is_zero_nondet, is_zero_pack, reduce, verify_zero,
    },
    signature::{div_mod_n_packed_divmod, div_mod_n_safe_div, get_point_from_x},
};
use crate::hint_processor::builtin_hint_processor::sha256_utils::{
    sha256_finalize, sha256_input, sha256_main,
};
use crate::hint_processor::builtin_hint_processor::usort::{
    usort_body, usort_enter_scope, verify_multiplicity_assert, verify_multiplicity_body,
    verify_usort,
};
use crate::hint_processor::proxies::vm_proxy::VMProxy;

pub struct HintProcessorData {
    pub code: String,
    pub ap_tracking: ApTracking,
    pub ids_data: HashMap<String, HintReference>,
}

impl HintProcessorData {
    pub fn new_default(code: String, ids_data: HashMap<String, HintReference>) -> Self {
        HintProcessorData {
            code,
            ap_tracking: ApTracking::default(),
            ids_data,
        }
    }
}
pub struct BuiltinHintProcessor {}

impl HintProcessor for BuiltinHintProcessor {
    fn execute_hint(
        &self,
        vm_proxy: &mut VMProxy,
        exec_scopes_proxy: &mut ExecutionScopesProxy,
        hint_data: &Box<dyn Any>,
    ) -> Result<(), VirtualMachineError> {
        let hint_data = hint_data
            .downcast_ref::<HintProcessorData>()
            .ok_or(VirtualMachineError::WrongHintData)?;
        match &*hint_data.code {
            hint_code::ADD_SEGMENT => add_segment(vm_proxy),
            hint_code::IS_NN => is_nn(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking),
            hint_code::IS_NN_OUT_OF_RANGE => {
                is_nn_out_of_range(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::IS_LE_FELT => {
                is_le_felt(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::ASSERT_LE_FELT => {
                assert_le_felt(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::ASSERT_250_BITS => {
                assert_250_bit(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::IS_POSITIVE => {
                is_positive(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::SPLIT_INT_ASSERT_RANGE => {
                split_int_assert_range(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::SPLIT_INT => {
                split_int(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::ASSERT_NOT_EQUAL => {
                assert_not_equal(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::ASSERT_NN => {
                assert_nn(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::SQRT => sqrt(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking),
            hint_code::ASSERT_NOT_ZERO => {
                assert_not_zero(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::VM_EXIT_SCOPE => exit_scope(exec_scopes_proxy),
            hint_code::MEMCPY_ENTER_SCOPE => memcpy_enter_scope(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::MEMSET_ENTER_SCOPE => memset_enter_scope(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::MEMCPY_CONTINUE_COPYING => memcpy_continue_copying(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::MEMSET_CONTINUE_LOOP => memset_continue_loop(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::SPLIT_FELT => {
                split_felt(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::UNSIGNED_DIV_REM => {
                unsigned_div_rem(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::SIGNED_DIV_REM => {
                signed_div_rem(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::ASSERT_LT_FELT => {
                assert_lt_felt(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::FIND_ELEMENT => find_element(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::SEARCH_SORTED_LOWER => search_sorted_lower(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::POW => pow(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking),
            hint_code::SET_ADD => set_add(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking),
            hint_code::DICT_NEW => dict_new(vm_proxy, exec_scopes_proxy),
            hint_code::DICT_READ => dict_read(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::DICT_WRITE => dict_write(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::DEFAULT_DICT_NEW => default_dict_new(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::SQUASH_DICT_INNER_FIRST_ITERATION => squash_dict_inner_first_iteration(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::USORT_ENTER_SCOPE => usort_enter_scope(exec_scopes_proxy),
            hint_code::USORT_BODY => usort_body(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::USORT_VERIFY => verify_usort(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::USORT_VERIFY_MULTIPLICITY_ASSERT => {
                verify_multiplicity_assert(exec_scopes_proxy)
            }
            hint_code::USORT_VERIFY_MULTIPLICITY_BODY => verify_multiplicity_body(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::BLAKE2S_COMPUTE => {
                compute_blake2s(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::VERIFY_ZERO => {
                verify_zero(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::NONDET_BIGINT3 => nondet_bigint3(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::REDUCE => reduce(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::BLAKE2S_FINALIZE => {
                finalize_blake2s(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::BLAKE2S_ADD_UINT256 => {
                blake2s_add_uint256(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::BLAKE2S_ADD_UINT256_BIGEND => {
                blake2s_add_uint256_bigend(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::UNSAFE_KECCAK => unsafe_keccak(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::UNSAFE_KECCAK_FINALIZE => {
                unsafe_keccak_finalize(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::SQUASH_DICT_INNER_SKIP_LOOP => squash_dict_inner_skip_loop(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::SQUASH_DICT_INNER_CHECK_ACCESS_INDEX => {
                squash_dict_inner_check_access_index(
                    vm_proxy,
                    exec_scopes_proxy,
                    &hint_data.ids_data,
                    &hint_data.ap_tracking,
                )
            }
            hint_code::SQUASH_DICT_INNER_CONTINUE_LOOP => squash_dict_inner_continue_loop(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::SQUASH_DICT_INNER_ASSERT_LEN_KEYS => {
                squash_dict_inner_assert_len_keys(exec_scopes_proxy)
            }
            hint_code::SQUASH_DICT_INNER_LEN_ASSERT => {
                squash_dict_inner_len_assert(exec_scopes_proxy)
            }
            hint_code::SQUASH_DICT_INNER_USED_ACCESSES_ASSERT => {
                squash_dict_inner_used_accesses_assert(
                    vm_proxy,
                    exec_scopes_proxy,
                    &hint_data.ids_data,
                    &hint_data.ap_tracking,
                )
            }
            hint_code::SQUASH_DICT_INNER_NEXT_KEY => squash_dict_inner_next_key(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::SQUASH_DICT => squash_dict(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::VM_ENTER_SCOPE => enter_scope(exec_scopes_proxy),
            hint_code::DICT_UPDATE => dict_update(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::DICT_SQUASH_COPY_DICT => dict_squash_copy_dict(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::DICT_SQUASH_UPDATE_PTR => dict_squash_update_ptr(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::UINT256_ADD => {
                uint256_add(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::SPLIT_64 => split_64(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking),
            hint_code::UINT256_SQRT => {
                uint256_sqrt(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::UINT256_SIGNED_NN => {
                uint256_signed_nn(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::UINT256_UNSIGNED_DIV_REM => {
                uint256_unsigned_div_rem(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::BIGINT_TO_UINT256 => {
                bigint_to_uint256(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::IS_ZERO_PACK => is_zero_pack(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::IS_ZERO_NONDET => is_zero_nondet(vm_proxy, exec_scopes_proxy),
            hint_code::IS_ZERO_ASSIGN_SCOPE_VARS => {
                is_zero_assign_scope_variables(exec_scopes_proxy)
            }
            hint_code::DIV_MOD_N_PACKED_DIVMOD => div_mod_n_packed_divmod(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::DIV_MOD_N_SAFE_DIV => div_mod_n_safe_div(exec_scopes_proxy),
            hint_code::GET_POINT_FROM_X => get_point_from_x(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::EC_NEGATE => ec_negate(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::EC_DOUBLE_SCOPE => compute_doubling_slope(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::COMPUTE_SLOPE => compute_slope(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::EC_DOUBLE_ASSIGN_NEW_X => ec_double_assign_new_x(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::EC_DOUBLE_ASSIGN_NEW_Y => ec_double_assign_new_y(exec_scopes_proxy),
            hint_code::KECCAK_WRITE_ARGS => {
                keccak_write_args(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::COMPARE_BYTES_IN_WORD_NONDET => {
                compare_bytes_in_word_nondet(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::SHA256_MAIN => {
                sha256_main(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::SHA256_INPUT => {
                sha256_input(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::SHA256_FINALIZE => {
                sha256_finalize(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::COMPARE_KECCAK_FULL_RATE_IN_BYTES_NONDET => {
                compare_keccak_full_rate_in_bytes_nondet(
                    vm_proxy,
                    &hint_data.ids_data,
                    &hint_data.ap_tracking,
                )
            }
            hint_code::BLOCK_PERMUTATION => {
                block_permutation(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::CAIRO_KECCAK_FINALIZE => {
                cairo_keccak_finalize(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            hint_code::FAST_EC_ADD_ASSIGN_NEW_X => fast_ec_add_assign_new_x(
                vm_proxy,
                exec_scopes_proxy,
                &hint_data.ids_data,
                &hint_data.ap_tracking,
            ),
            hint_code::FAST_EC_ADD_ASSIGN_NEW_Y => fast_ec_add_assign_new_y(exec_scopes_proxy),
            hint_code::EC_MUL_INNER => {
                ec_mul_inner(vm_proxy, &hint_data.ids_data, &hint_data.ap_tracking)
            }
            code => Err(VirtualMachineError::UnknownHint(code.to_string())),
        }
    }

    fn compile_hint(
        &self,
        code: String,
        ap_tracking: &ApTracking,
        reference_ids: &HashMap<String, usize>,
        references: &HashMap<usize, HintReference>,
    ) -> Result<Box<dyn Any>, VirtualMachineError> {
        Ok(any_box!(HintProcessorData {
            code,
            ap_tracking: ap_tracking.clone(),
            ids_data: get_ids_data(reference_ids, references)?,
        }))
    }
}

fn get_ids_data(
    reference_ids: &HashMap<String, usize>,
    references: &HashMap<usize, HintReference>,
) -> Result<HashMap<String, HintReference>, VirtualMachineError> {
    let mut ids_data = HashMap::<String, HintReference>::new();
    for (path, ref_id) in reference_ids {
        let name = path
            .rsplit('.')
            .next()
            .ok_or(VirtualMachineError::FailedToGetIds)?;
        ids_data.insert(
            name.to_string(),
            references
                .get(ref_id)
                .ok_or(VirtualMachineError::FailedToGetIds)?
                .clone(),
        );
    }
    Ok(ids_data)
}

#[cfg(test)]
mod tests {
    use crate::hint_processor::proxies::exec_scopes_proxy::get_exec_scopes_proxy;
    use crate::hint_processor::proxies::vm_proxy::get_vm_proxy;
    use crate::types::exec_scope::ExecutionScopes;
    use crate::types::relocatable::MaybeRelocatable;
    use crate::utils::test_utils::*;
    use crate::vm::errors::{exec_scope_errors::ExecScopeError, memory_errors::MemoryError};
    use crate::vm::vm_core::VirtualMachine;
    use crate::{any_box, bigint};
    use num_bigint::{BigInt, Sign};
    use std::any::Any;

    use super::*;

    static HINT_EXECUTOR: BuiltinHintProcessor = BuiltinHintProcessor {};
    use crate::hint_processor::hint_processor_definition::HintProcessor;

    #[test]
    fn run_alloc_hint_empty_memory() {
        let hint_code = "memory[ap] = segments.add()";
        let mut vm = vm!();
        //ids and references are not needed for this test
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        HINT_EXECUTOR
            .execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data))
            .expect("Error while executing hint");
        //first new segment is added
        assert_eq!(vm.segments.num_segments, 1);
        //new segment base (0,0) is inserted into ap (0,0)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from((0, 0))))
        );
    }

    #[test]
    fn run_alloc_hint_preset_memory() {
        let hint_code = "memory[ap] = segments.add()";
        let mut vm = vm!();
        //Add 3 segments to the memory
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        vm.run_context.ap = MaybeRelocatable::from((2, 6));
        //ids and references are not needed for this test
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        HINT_EXECUTOR
            .execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data))
            .expect("Error while executing hint");
        //Segment N°4 is added
        assert_eq!(vm.segments.num_segments, 4);
        //new segment base (3,0) is inserted into ap (2,6)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((2, 6))),
            Ok(Some(&MaybeRelocatable::from((3, 0))))
        );
    }

    #[test]
    fn run_alloc_hint_ap_is_not_empty() {
        let hint_code = "memory[ap] = segments.add()";
        let mut vm = vm!();
        //Add 3 segments to the memory
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        vm.run_context.ap = MaybeRelocatable::from((2, 6));
        //Insert something into ap
        vm.memory
            .insert(
                &MaybeRelocatable::from((2, 6)),
                &MaybeRelocatable::from((2, 6)),
            )
            .unwrap();
        //ids and references are not needed for this test
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((2, 6)),
                    MaybeRelocatable::from((2, 6)),
                    MaybeRelocatable::from((3, 0))
                )
            ))
        );
    }

    #[test]
    fn run_unknown_hint() {
        let hint_code = "random_invalid_code";
        let mut vm = vm!();
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
            Err(VirtualMachineError::UnknownHint(hint_code.to_string())),
        );
    }

    #[test]
    fn memcpy_enter_scope_valid() {
        let hint_code = "vm_enter_scope({'n': ids.len})";
        let mut vm = vm!();

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));

        // insert ids.len into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();
        let ids_data = ids_data!["len"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert!(HINT_EXECUTOR
            .execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data))
            .is_ok());
    }

    #[test]
    fn memcpy_enter_scope_invalid() {
        let hint_code = "vm_enter_scope({'n': ids.len})";
        let mut vm = vm!();

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));

        // insert ids.len into memory
        // we insert a relocatable value in the address of ids.len so that it raises an error.
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((0, 0)),
            )
            .unwrap();

        let ids_data = ids_data!["len"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);

        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn memcpy_continue_copying_valid() {
        let hint_code = "n -= 1\nids.continue_copying = 1 if n > 0 else 0";
        let mut vm = vm!();

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));

        // initialize vm scope with variable `n`
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("n", any_box!(bigint!(1)));

        // initialize ids.continue_copying
        // we create a memory gap so that there is None in (0, 0), the actual addr of continue_copying
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();

        let ids_data = ids_data!["continue_copying"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert!(HINT_EXECUTOR
            .execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data))
            .is_ok());
    }

    #[test]
    fn memcpy_continue_copying_variable_not_in_scope_error() {
        let hint_code = "n -= 1\nids.continue_copying = 1 if n > 0 else 0";
        let mut vm = vm!();

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));

        // we don't initialize `n` now:
        /*  vm.exec_scopes
        .assign_or_update_variable("n",  bigint!(1)));  */

        // initialize ids.continue_copying
        // we create a memory gap so that there is None in (0, 1), the actual addr of continue_copying
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();

        let ids_data = ids_data!["continue_copying"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
            Err(VirtualMachineError::VariableNotInScopeError(
                "n".to_string()
            ))
        );
    }

    #[test]
    fn memcpy_continue_copying_insert_error() {
        let hint_code = "n -= 1\nids.continue_copying = 1 if n > 0 else 0";
        let mut vm = vm!();

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));

        // initialize with variable `n`
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("n", any_box!(bigint!(1)));

        // initialize ids.continue_copying
        // a value is written in the address so the hint cant insert value there
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();

        let ids_data = ids_data!["continue_copying"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((0, 0)),
                    MaybeRelocatable::from(bigint!(5)),
                    MaybeRelocatable::from(bigint!(0))
                )
            ))
        );
    }

    #[test]
    fn exit_scope_valid() {
        let hint_code = "vm_exit_scope()";
        let mut vm = vm!();

        // Create new vm scope with dummy variable
        let mut exec_scopes = ExecutionScopes::new();
        let a_value: Box<dyn Any> = Box::new(bigint!(1));
        exec_scopes.enter_scope(HashMap::from([(String::from("a"), a_value)]));
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        // Initialize memory segments
        vm.segments.add(&mut vm.memory, None);
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert!(HINT_EXECUTOR
            .execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data))
            .is_ok());
    }

    #[test]
    fn exit_scope_invalid() {
        let hint_code = "vm_exit_scope()";
        let mut vm = vm!();

        // new vm scope is not created so that the hint raises an error:
        //vm.exec_scopes.enter_scope(HashMap::from([(String::from("a"),  bigint!(1)))]));

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
            Err(VirtualMachineError::MainScopeError(
                ExecScopeError::ExitMainScopeError
            ))
        );
    }

    #[test]
    fn run_enter_scope() {
        let hint_code = "vm_enter_scope()";
        //Create vm
        let mut vm = vm!();
        let mut exec_scopes = ExecutionScopes::new();
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
        //Check exec_scopes
        assert_eq!(exec_scopes.data.len(), 2);
        assert!(exec_scopes.data[0].is_empty());
        assert!(exec_scopes.data[1].is_empty());
    }

    #[test]
    fn unsafe_keccak_valid() {
        let hint_code = "from eth_hash.auto import keccak\n\ndata, length = ids.data, ids.length\n\nif '__keccak_max_size' in globals():\n    assert length <= __keccak_max_size, \\\n        f'unsafe_keccak() can only be used with length<={__keccak_max_size}. ' \\\n        f'Got: length={length}.'\n\nkeccak_input = bytearray()\nfor word_i, byte_i in enumerate(range(0, length, 16)):\n    word = memory[data + word_i]\n    n_bytes = min(16, length - byte_i)\n    assert 0 <= word < 2 ** (8 * n_bytes)\n    keccak_input += word.to_bytes(n_bytes, 'big')\n\nhashed = keccak(keccak_input)\nids.high = int.from_bytes(hashed[:16], 'big')\nids.low = int.from_bytes(hashed[16:32], 'big')";
        let mut vm = vm!();

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 5));

        // insert ids.len into memory
        vm.memory
            // length
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(3)),
            )
            .unwrap();

        vm.memory
            // data
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        vm.memory
            // pointer to data
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();

        vm.memory
            // we create a memory gap in (0, 3) and (0, 4)
            .insert(
                &MaybeRelocatable::from((0, 5)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();

        let ids_data = ids_data!["length", "data", "high", "low"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);

        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("__keccak_max_size", any_box!(bigint!(500)));

        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert!(HINT_EXECUTOR
            .execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data))
            .is_ok());
    }

    #[test]
    fn unsafe_keccak_max_size() {
        let hint_code = "from eth_hash.auto import keccak\n\ndata, length = ids.data, ids.length\n\nif '__keccak_max_size' in globals():\n    assert length <= __keccak_max_size, \\\n        f'unsafe_keccak() can only be used with length<={__keccak_max_size}. ' \\\n        f'Got: length={length}.'\n\nkeccak_input = bytearray()\nfor word_i, byte_i in enumerate(range(0, length, 16)):\n    word = memory[data + word_i]\n    n_bytes = min(16, length - byte_i)\n    assert 0 <= word < 2 ** (8 * n_bytes)\n    keccak_input += word.to_bytes(n_bytes, 'big')\n\nhashed = keccak(keccak_input)\nids.high = int.from_bytes(hashed[:16], 'big')\nids.low = int.from_bytes(hashed[16:32], 'big')";
        let mut vm = vm!();

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 5));

        // insert ids.len into memory
        vm.memory
            // length
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();

        vm.memory
            // data
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        vm.memory
            // pointer to data
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();

        vm.memory
            // we create a memory gap in (0, 3) and (0, 4)
            .insert(
                &MaybeRelocatable::from((0, 5)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();

        let ids_data = ids_data!["length", "data", "high", "low"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("__keccak_max_size", any_box!(bigint!(2)));
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::KeccakMaxSize(bigint!(5), bigint!(2)))
        );
    }

    #[test]
    fn unsafe_keccak_invalid_input_length() {
        let hint_code = "from eth_hash.auto import keccak\n\ndata, length = ids.data, ids.length\n\nif '__keccak_max_size' in globals():\n    assert length <= __keccak_max_size, \\\n        f'unsafe_keccak() can only be used with length<={__keccak_max_size}. ' \\\n        f'Got: length={length}.'\n\nkeccak_input = bytearray()\nfor word_i, byte_i in enumerate(range(0, length, 16)):\n    word = memory[data + word_i]\n    n_bytes = min(16, length - byte_i)\n    assert 0 <= word < 2 ** (8 * n_bytes)\n    keccak_input += word.to_bytes(n_bytes, 'big')\n\nhashed = keccak(keccak_input)\nids.high = int.from_bytes(hashed[:16], 'big')\nids.low = int.from_bytes(hashed[16:32], 'big')";
        let mut vm = vm!();

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 5));

        // insert ids.len into memory
        vm.memory
            // length
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(18446744073709551616_i128)),
            )
            .unwrap();

        vm.memory
            // data
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        vm.memory
            // pointer to data
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();

        vm.memory
            // we create a memory gap in (0, 3) and (0, 4)
            .insert(
                &MaybeRelocatable::from((0, 5)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();

        let ids_data = ids_data!["length", "data", "high", "low"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);

        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert!(HINT_EXECUTOR
            .execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data))
            .is_err());
    }

    #[test]
    fn unsafe_keccak_invalid_word_size() {
        let hint_code = "from eth_hash.auto import keccak\n\ndata, length = ids.data, ids.length\n\nif '__keccak_max_size' in globals():\n    assert length <= __keccak_max_size, \\\n        f'unsafe_keccak() can only be used with length<={__keccak_max_size}. ' \\\n        f'Got: length={length}.'\n\nkeccak_input = bytearray()\nfor word_i, byte_i in enumerate(range(0, length, 16)):\n    word = memory[data + word_i]\n    n_bytes = min(16, length - byte_i)\n    assert 0 <= word < 2 ** (8 * n_bytes)\n    keccak_input += word.to_bytes(n_bytes, 'big')\n\nhashed = keccak(keccak_input)\nids.high = int.from_bytes(hashed[:16], 'big')\nids.low = int.from_bytes(hashed[16:32], 'big')";
        let mut vm = vm!();

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 5));

        // insert ids.len into memory
        vm.memory
            // length
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(3)),
            )
            .unwrap();

        vm.memory
            // data
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(bigint!(-1)),
            )
            .unwrap();

        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        vm.memory
            // pointer to data
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();

        vm.memory
            // we create a memory gap in (0, 3) and (0, 4)
            .insert(
                &MaybeRelocatable::from((0, 5)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();

        let ids_data = ids_data!["length", "data", "high", "low"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("__keccak_max_size", any_box!(bigint!(10)));

        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::InvalidWordSize(bigint!(-1)))
        );
    }

    #[test]
    fn unsafe_keccak_finalize_valid() {
        let hint_code = "from eth_hash.auto import keccak\nkeccak_input = bytearray()\nn_elms = ids.keccak_state.end_ptr - ids.keccak_state.start_ptr\nfor word in memory.get_range(ids.keccak_state.start_ptr, n_elms):\n    keccak_input += word.to_bytes(16, 'big')\nhashed = keccak(keccak_input)\nids.high = int.from_bytes(hashed[:16], 'big')\nids.low = int.from_bytes(hashed[16:32], 'big')";
        let mut vm = vm!();

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 9));

        vm.memory
            // pointer to keccak_state
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from((0, 2)),
            )
            .unwrap();

        vm.memory
            // field start_ptr of keccak_state
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from((0, 4)),
            )
            .unwrap();

        vm.memory
            // field end_ptr of keccak_state
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from((0, 5)),
            )
            .unwrap();

        vm.memory
            // the number that is pointed to by start_pointer
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        vm.memory
            // the number that is pointed to by end_pointer
            .insert(
                &MaybeRelocatable::from((0, 5)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();

        vm.memory
            // we create a memory gap in (0, 6) and (0, 7)
            // for high and low variables
            .insert(
                &MaybeRelocatable::from((0, 8)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();

        let ids_data = HashMap::from([
            ("keccak_state".to_string(), HintReference::new_simple(-7)),
            ("high".to_string(), HintReference::new_simple(-3)),
            ("low".to_string(), HintReference::new_simple(-2)),
        ]);
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);

        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert!(HINT_EXECUTOR
            .execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data))
            .is_ok());
    }

    #[test]
    fn unsafe_keccak_finalize_nones_in_range() {
        let hint_code = "from eth_hash.auto import keccak\nkeccak_input = bytearray()\nn_elms = ids.keccak_state.end_ptr - ids.keccak_state.start_ptr\nfor word in memory.get_range(ids.keccak_state.start_ptr, n_elms):\n    keccak_input += word.to_bytes(16, 'big')\nhashed = keccak(keccak_input)\nids.high = int.from_bytes(hashed[:16], 'big')\nids.low = int.from_bytes(hashed[16:32], 'big')";
        let mut vm = vm!();

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 9));

        vm.memory
            // pointer to keccak_state
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from((0, 2)),
            )
            .unwrap();

        vm.memory
            // field start_ptr of keccak_state
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from((0, 4)),
            )
            .unwrap();

        vm.memory
            // field end_ptr of keccak_state
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from((0, 5)),
            )
            .unwrap();

        vm.memory
            // the number that is pointed to by end_pointer
            // we create a gap in (0, 4)
            .insert(
                &MaybeRelocatable::from((0, 5)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();

        vm.memory
            // we create a memory gap in (0, 6) and (0, 7)
            // for high and low variables
            .insert(
                &MaybeRelocatable::from((0, 8)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();

        let ids_data = HashMap::from([
            ("keccak_state".to_string(), HintReference::new_simple(-7)),
            ("high".to_string(), HintReference::new_simple(-3)),
            ("low".to_string(), HintReference::new_simple(-2)),
        ]);
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);

        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
            Err(VirtualMachineError::NoneInMemoryRange)
        );
    }

    #[test]
    fn unsafe_keccak_finalize_expected_integer_at_range() {
        let hint_code = "from eth_hash.auto import keccak\nkeccak_input = bytearray()\nn_elms = ids.keccak_state.end_ptr - ids.keccak_state.start_ptr\nfor word in memory.get_range(ids.keccak_state.start_ptr, n_elms):\n    keccak_input += word.to_bytes(16, 'big')\nhashed = keccak(keccak_input)\nids.high = int.from_bytes(hashed[:16], 'big')\nids.low = int.from_bytes(hashed[16:32], 'big')";
        let mut vm = vm!();

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 9));

        vm.memory
            // pointer to keccak_state
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from((0, 2)),
            )
            .unwrap();

        vm.memory
            // field start_ptr of keccak_state
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from((0, 4)),
            )
            .unwrap();

        vm.memory
            // field end_ptr of keccak_state
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from((0, 5)),
            )
            .unwrap();

        vm.memory
            // this is the cell pointed by start_ptr and should be
            // a number, not a pointer. This causes the error
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from((0, 5)),
            )
            .unwrap();

        vm.memory
            // the number that is pointed to by end_pointer
            .insert(
                &MaybeRelocatable::from((0, 5)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();

        vm.memory
            // we create a memory gap in (0, 6) and (0, 7)
            // for high and low variables
            .insert(
                &MaybeRelocatable::from((0, 8)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();

        let ids_data = HashMap::from([
            ("keccak_state".to_string(), HintReference::new_simple(-7)),
            ("high".to_string(), HintReference::new_simple(-3)),
            ("low".to_string(), HintReference::new_simple(-2)),
        ]);
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);

        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert!(HINT_EXECUTOR
            .execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data))
            .is_err());
    }
}
