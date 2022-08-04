use std::collections::HashMap;

use num_bigint::BigInt;

use crate::serde::deserialize_program::ApTracking;
use crate::types::{hint_executor::HintExecutor, instruction::Register};
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::blake2s_utils::{
    blake2s_add_uint256, blake2s_add_uint256_bigend, compute_blake2s, finalize_blake2s,
};
use crate::vm::hints::dict_hint_utils::{
    default_dict_new, dict_new, dict_read, dict_squash_copy_dict, dict_squash_update_ptr,
    dict_update, dict_write,
};
use crate::vm::hints::find_element_hint::{find_element, search_sorted_lower};
use crate::vm::hints::hint_code;
use crate::vm::hints::hint_utils::{
    add_segment, assert_250_bit, assert_le_felt, assert_lt_felt, assert_nn, assert_not_equal,
    assert_not_zero, enter_scope, exit_scope, is_le_felt, is_nn, is_nn_out_of_range, is_positive,
    memcpy_continue_copying, memcpy_enter_scope, signed_div_rem, split_felt, split_int,
    split_int_assert_range, sqrt, unsigned_div_rem,
};
use crate::vm::hints::keccak_utils::{unsafe_keccak, unsafe_keccak_finalize};
use crate::vm::hints::memset_utils::{memset_continue_loop, memset_enter_scope};
use crate::vm::hints::pow_utils::pow;
use crate::vm::hints::set::set_add;
use crate::vm::hints::squash_dict_utils::{
    squash_dict, squash_dict_inner_assert_len_keys, squash_dict_inner_check_access_index,
    squash_dict_inner_continue_loop, squash_dict_inner_first_iteration,
    squash_dict_inner_len_assert, squash_dict_inner_next_key, squash_dict_inner_skip_loop,
    squash_dict_inner_used_accesses_assert,
};
use crate::vm::hints::uint256_utils::{
    split_64, uint256_add, uint256_signed_nn, uint256_sqrt, uint256_unsigned_div_rem,
};

use crate::vm::hints::secp::{
    bigint_utils::{bigint_to_uint256, nondet_bigint3},
    ec_utils::{compute_doubling_slope, ec_negate},
    field_utils::{
        is_zero_assign_scope_variables, is_zero_nondet, is_zero_pack, reduce, verify_zero,
    },
    signature::{div_mod_n_packed_divmod, div_mod_n_safe_div, get_point_from_x},
};
use crate::vm::hints::usort::{
    usort_body, usort_enter_scope, verify_multiplicity_assert, verify_multiplicity_body,
    verify_usort,
};
use crate::vm::vm_core::VirtualMachine;

#[derive(Debug, PartialEq, Clone)]
pub struct HintReference {
    pub register: Register,
    pub offset1: i32,
    pub offset2: i32,
    pub dereference: bool,
    pub inner_dereference: bool,
    pub ap_tracking_data: Option<ApTracking>,
    pub immediate: Option<BigInt>,
}

impl HintReference {
    pub fn new_simple(offset1: i32) -> Self {
        HintReference {
            register: Register::FP,
            offset1,
            offset2: 0,
            inner_dereference: false,
            ap_tracking_data: None,
            immediate: None,
            dereference: true,
        }
    }
}
pub struct BuiltinHintExecutor {}

impl HintExecutor for BuiltinHintExecutor {
    fn execute_hint(
        &self,
        vm: &mut VirtualMachine,
        code: &str,
        ids: &HashMap<String, BigInt>,
        ap_tracking: &ApTracking,
    ) -> Result<(), VirtualMachineError> {
        match code {
            hint_code::ADD_SEGMENT => add_segment(vm),
            hint_code::IS_NN => is_nn(vm, ids, None),
            hint_code::IS_NN_OUT_OF_RANGE => is_nn_out_of_range(vm, ids, None),
            hint_code::IS_LE_FELT => is_le_felt(vm, ids, None),
            hint_code::ASSERT_LE_FELT => assert_le_felt(vm, ids, None),
            hint_code::ASSERT_250_BITS => assert_250_bit(vm, ids, None),
            hint_code::IS_POSITIVE => is_positive(vm, ids, Some(ap_tracking)),
            hint_code::SPLIT_INT_ASSERT_RANGE => split_int_assert_range(vm, ids, None),
            hint_code::SPLIT_INT => split_int(vm, ids, None),
            hint_code::ASSERT_NOT_EQUAL => assert_not_equal(vm, ids, None),
            hint_code::ASSERT_NN => assert_nn(vm, ids, None),
            hint_code::SQRT => sqrt(vm, ids, None),
            hint_code::ASSERT_NOT_ZERO => assert_not_zero(vm, ids, None),
            hint_code::VM_EXIT_SCOPE => exit_scope(vm),
            hint_code::MEMCPY_ENTER_SCOPE => memcpy_enter_scope(vm, ids, Some(ap_tracking)),
            hint_code::MEMSET_ENTER_SCOPE => memset_enter_scope(vm, ids, Some(ap_tracking)),
            hint_code::MEMCPY_CONTINUE_COPYING => {
                memcpy_continue_copying(vm, ids, Some(ap_tracking))
            }
            hint_code::MEMSET_CONTINUE_LOOP => memset_continue_loop(vm, ids, Some(ap_tracking)),
            hint_code::SPLIT_FELT => split_felt(vm, ids, None),
            hint_code::UNSIGNED_DIV_REM => unsigned_div_rem(vm, ids, None),
            hint_code::SIGNED_DIV_REM => signed_div_rem(vm, ids, None),
            hint_code::ASSERT_LT_FELT => assert_lt_felt(vm, ids, None),
            hint_code::FIND_ELEMENT => find_element(vm, ids, None),
            hint_code::SEARCH_SORTED_LOWER => search_sorted_lower(vm, ids, None),
            hint_code::POW => pow(vm, ids, Some(ap_tracking)),
            hint_code::SET_ADD => set_add(vm, ids, None),
            hint_code::DICT_NEW => dict_new(vm),
            hint_code::DICT_READ => dict_read(vm, ids, None),
            hint_code::DICT_WRITE => dict_write(vm, ids, None),
            hint_code::DEFAULT_DICT_NEW => default_dict_new(vm, ids, Some(ap_tracking)),
            hint_code::SQUASH_DICT_INNER_FIRST_ITERATION => {
                squash_dict_inner_first_iteration(vm, ids, Some(ap_tracking))
            }
            hint_code::USORT_ENTER_SCOPE => usort_enter_scope(vm),
            hint_code::USORT_BODY => usort_body(vm, ids, None),
            hint_code::USORT_VERIFY => verify_usort(vm, ids, None),
            hint_code::USORT_VERIFY_MULTIPLICITY_ASSERT => verify_multiplicity_assert(vm),
            hint_code::USORT_VERIFY_MULTIPLICITY_BODY => verify_multiplicity_body(vm, ids, None),
            hint_code::BLAKE2S_COMPUTE => compute_blake2s(vm, ids, Some(ap_tracking)),
            hint_code::VERIFY_ZERO => verify_zero(vm, ids, Some(ap_tracking)),
            hint_code::NONDET_BIGINT3 => nondet_bigint3(vm, ids, Some(ap_tracking)),
            hint_code::REDUCE => reduce(vm, ids, None),
            hint_code::BLAKE2S_FINALIZE => finalize_blake2s(vm, ids, Some(ap_tracking)),
            hint_code::BLAKE2S_ADD_UINT256 => blake2s_add_uint256(vm, ids, Some(ap_tracking)),
            hint_code::BLAKE2S_ADD_UINT256_BIGEND => {
                blake2s_add_uint256_bigend(vm, ids, Some(ap_tracking))
            }
            hint_code::UNSAFE_KECCAK => unsafe_keccak(vm, ids, None),
            hint_code::UNSAFE_KECCAK_FINALIZE => unsafe_keccak_finalize(vm, ids, None),
            hint_code::SQUASH_DICT_INNER_SKIP_LOOP => {
                squash_dict_inner_skip_loop(vm, ids, Some(ap_tracking))
            }
            hint_code::SQUASH_DICT_INNER_CHECK_ACCESS_INDEX => {
                squash_dict_inner_check_access_index(vm, ids, Some(ap_tracking))
            }
            hint_code::SQUASH_DICT_INNER_CONTINUE_LOOP => {
                squash_dict_inner_continue_loop(vm, ids, Some(ap_tracking))
            }
            hint_code::SQUASH_DICT_INNER_ASSERT_LEN_KEYS => squash_dict_inner_assert_len_keys(vm),
            hint_code::SQUASH_DICT_INNER_LEN_ASSERT => squash_dict_inner_len_assert(vm),
            hint_code::SQUASH_DICT_INNER_USED_ACCESSES_ASSERT => {
                squash_dict_inner_used_accesses_assert(vm, ids, Some(ap_tracking))
            }
            hint_code::SQUASH_DICT_INNER_NEXT_KEY => {
                squash_dict_inner_next_key(vm, ids, Some(ap_tracking))
            }
            hint_code::SQUASH_DICT => squash_dict(vm, ids, Some(ap_tracking)),
            hint_code::VM_ENTER_SCOPE => enter_scope(vm),
            hint_code::DICT_UPDATE => dict_update(vm, ids, None),
            hint_code::DICT_SQUASH_COPY_DICT => dict_squash_copy_dict(vm, ids, Some(ap_tracking)),
            hint_code::DICT_SQUASH_UPDATE_PTR => dict_squash_update_ptr(vm, ids, Some(ap_tracking)),
            hint_code::UINT256_ADD => uint256_add(vm, ids, None),
            hint_code::SPLIT_64 => split_64(vm, ids, None),
            hint_code::UINT256_SQRT => uint256_sqrt(vm, ids, None),
            hint_code::UINT256_SIGNED_NN => uint256_signed_nn(vm, ids, None),
            hint_code::UINT256_UNSIGNED_DIV_REM => uint256_unsigned_div_rem(vm, ids, None),
            hint_code::BIGINT_TO_UINT256 => bigint_to_uint256(vm, ids, None),
            hint_code::IS_ZERO_PACK => is_zero_pack(vm, ids, None),
            hint_code::IS_ZERO_NONDET => is_zero_nondet(vm),
            hint_code::IS_ZERO_ASSIGN_SCOPE_VARS => is_zero_assign_scope_variables(vm),
            hint_code::DIV_MOD_N_PACKED_DIVMOD => div_mod_n_packed_divmod(vm, ids, None),
            hint_code::DIV_MOD_N_SAFE_DIV => div_mod_n_safe_div(vm),
            hint_code::GET_POINT_FROM_X => get_point_from_x(vm, ids, Some(ap_tracking)),
            hint_code::EC_NEGATE => ec_negate(vm, ids, None),
            hint_code::EC_DOUBLE_SCOPE => compute_doubling_slope(vm, ids, None),
            code => Err(VirtualMachineError::UnknownHint(code.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Shl;

    use crate::bigint_str;
    use crate::math_utils::as_int;
    use crate::relocatable;
    use crate::types::exec_scope::PyValueType;
    use crate::types::relocatable::MaybeRelocatable;
    use crate::types::relocatable::Relocatable;
    use crate::vm::errors::{exec_scope_errors::ExecScopeError, memory_errors::MemoryError};
    use crate::{bigint, vm::runners::builtin_runner::RangeCheckBuiltinRunner};
    use num_bigint::{BigInt, Sign};

    use super::*;

    static HINT_EXECUTOR: BuiltinHintExecutor = BuiltinHintExecutor {};

    #[test]
    fn run_alloc_hint_empty_memory() {
        let hint_code = "memory[ap] = segments.add()";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            //ap value is (0,0)
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        //ids and references are not needed for this test
        vm.hint_executor
            .execute_hint(&mut vm, hint_code, &HashMap::new(), &ApTracking::new())
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
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        //Add 3 segments to the memory
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        vm.run_context.ap = MaybeRelocatable::from((2, 6));
        //ids and references are not needed for this test
        vm.hint_executor
            .execute_hint(&mut vm, hint_code, &HashMap::new(), &ApTracking::new())
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
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
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
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &HashMap::new(), &ApTracking::new()),
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
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &HashMap::new(), &ApTracking::new()),
            Err(VirtualMachineError::UnknownHint(hint_code.to_string())),
        );
    }

    #[test]
    fn run_is_nn_hint_false() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(-1)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        vm.hint_executor
            .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new())
            .expect("Error while executing hint");
        //Check that ap now contains false (0)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1))))
        );
    }

    #[test]
    fn run_is_nn_hint_true() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        vm.hint_executor
            .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new())
            .expect("Error while executing hint");
        //Check that ap now contains true (1)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
    }

    #[test]
    //This test contemplates the case when the number itself is negative, but it is within the range (-prime, -range_check_bound)
    //Making the comparison return 1 (true)
    fn run_is_nn_hint_true_border_case() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                //(-prime) + 1
                &MaybeRelocatable::from(
                    BigInt::new(Sign::Minus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]) + bigint!(1),
                ),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        vm.hint_executor
            .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new())
            .expect("Error while executing hint");
        //Check that ap now contains true (1)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
    }

    #[test]
    fn run_is_nn_hint_no_range_check_builtin() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn run_is_nn_hint_incorrect_ids() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("b"), bigint!(0));
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::IncorrectIds(
                vec![String::from("a")],
                vec![String::from("b")]
            ))
        );
    }

    #[test]
    fn run_is_nn_hint_cant_get_ids_from_memory() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Dont insert ids into memory
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryGet(MaybeRelocatable::from((
                0, 0
            ))))
        );
    }

    #[test]
    fn run_is_nn_hint_ids_are_relocatable_values() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((2, 3)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn run_assert_le_felt_valid() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)"
            ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //ids.b
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //create memory gap, so ids.small_inputs contains None
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(4)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        ids.insert(String::from("small_inputs"), bigint!(2));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Ok(())
        );
        //Hint would return an error if the assertion fails
    }

    #[test]
    fn is_le_felt_hint_true() {
        let hint_code = "memory[ap] = 0 if (ids.a % PRIME) <= (ids.b % PRIME) else 1";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .expect("Unexpected memory insert fail");
        //ids.b
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert!(vm
            .hint_executor
            .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new())
            .is_ok());
    }

    #[test]
    fn run_is_le_felt_hint_no_range_check_builtin() {
        let hint_code = "memory[ap] = 0 if (ids.a % PRIME) <= (ids.b % PRIME) else 1";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }

        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));

        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .expect("Unexpected memroy insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .expect("Unexpected memroy insert fail");

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);

        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn run_is_le_felt_hint_inconsistent_memory() {
        let hint_code = "memory[ap] = 0 if (ids.a % PRIME) <= (ids.b % PRIME) else 1";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((0, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));

        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .expect("Unexpected memroy insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .expect("Unexpected memroy insert fail");

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((0, 0)),
                    MaybeRelocatable::Int(bigint!(1)),
                    MaybeRelocatable::Int(bigint!(0))
                )
            ))
        );
    }

    #[test]
    fn run_is_le_felt_hint_incorrect_ids() {
        let hint_code = "memory[ap] = 0 if (ids.a % PRIME) <= (ids.b % PRIME) else 1";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }

        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));

        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .expect("Unexpected memroy insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .expect("Unexpected memroy insert fail");

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("c"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);

        // Since the ids are a map, the order might not always match and so the error returned
        // sometimes might be different
        assert!(matches!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::IncorrectIds(_, _))
        ));
    }

    #[test]
    fn run_assert_nn_valid() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );

        vm.segments.add(&mut vm.memory, None);

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -4,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Ok(())
        );
        //Hint would return an error if the assertion fails
    }

    #[test]
    fn run_assert_nn_invalid() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(-1)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -4,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ValueOutOfRange(bigint!(-1)))
        );
    }

    #[test]
    fn run_assert_nn_incorrect_ids() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );

        vm.segments.add(&mut vm.memory, None);

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(-1)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("incorrect_id"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -4,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::IncorrectIds(
                vec![String::from("a")],
                vec![String::from("incorrect_id")],
            ))
        );
    }

    #[test]
    fn run_assert_nn_incorrect_reference() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );

        vm.segments.add(&mut vm.memory, None);

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(-1)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: 10,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_assert_nn_a_is_not_integer() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );

        vm.segments.add(&mut vm.memory, None);

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((10, 10)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -4,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn run_assert_nn_no_range_check_builtin() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![],
            false,
            &HINT_EXECUTOR,
        );

        vm.segments.add(&mut vm.memory, None);

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -4,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn run_assert_nn_reference_is_not_in_memory() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );

        vm.segments.add(&mut vm.memory, None);

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -4,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_is_assert_le_felt_invalid() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)"
            ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //ids.b
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //create memory gap, so ids.small_inputs contains None
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(4)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        ids.insert(String::from("small_inputs"), bigint!(2));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::NonLeFelt(bigint!(2), bigint!(1)))
        );
    }

    #[test]
    fn run_is_assert_le_felt_small_inputs_not_local() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)"
            ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //ids.b
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //ids.small_inputs (insert into memory, instead of leaving a gap for it (local var))
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(4)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        ids.insert(String::from("small_inputs"), bigint!(2));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_is_assert_le_felt_a_is_not_integer() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)"
            ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((0, 0)),
            )
            .unwrap();
        //ids.b
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //create memory gap, so ids.small_inputs contains None
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(4)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        ids.insert(String::from("small_inputs"), bigint!(2));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn run_is_assert_le_felt_b_is_not_integer() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)"
            ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //ids.b
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from((0, 0)),
            )
            .unwrap();
        //create memory gap, so ids.small_inputs contains None
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(4)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        ids.insert(String::from("small_inputs"), bigint!(2));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 1))
            ))
        );
    }

    #[test]
    fn run_is_nn_hint_out_of_range_false() {
        let hint_code =
            "memory[ap] = 0 if 0 <= ((-ids.a - 1) % PRIME) < range_check_builtin.bound else 1";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        vm.hint_executor
            .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new())
            .expect("Error while executing hint");
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1))))
        );
    }

    #[test]
    fn run_is_nn_hint_out_of_range_true() {
        let hint_code =
            "memory[ap] = 0 if 0 <= ((-ids.a - 1) % PRIME) < range_check_builtin.bound else 1";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(-1)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        vm.hint_executor
            .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new())
            .expect("Error while executing hint");
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
    }
    #[test]
    fn run_assert_not_equal_int_false() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'"
            ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::AssertNotEqualFail(
                MaybeRelocatable::from(bigint!(1)),
                MaybeRelocatable::from(bigint!(1))
            ))
        );
    }

    #[test]
    fn run_assert_not_equal_int_true() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'"
            ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(3)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Ok(())
        );
    }

    #[test]
    fn run_assert_not_equal_int_false_mod() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'"
            ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                //-1 % prime = prime -1
                &MaybeRelocatable::from(bigint!(-1)),
            )
            .unwrap();
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                //prime -1
                &MaybeRelocatable::from(bigint_str!(
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020480"
                )),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::AssertNotEqualFail(
                MaybeRelocatable::from(bigint!(-1)),
                MaybeRelocatable::from(bigint_str!(
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020480"
                ))
            ))
        );
    }

    #[test]
    fn run_assert_not_equal_relocatable_false() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((0, 0)),
            )
            .unwrap();
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from((0, 0)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::AssertNotEqualFail(
                MaybeRelocatable::from((0, 0)),
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn run_assert_not_equal_relocatable_true() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'"
            ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((0, 1)),
            )
            .unwrap();
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from((0, 0)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Ok(())
        );
    }

    #[test]
    fn run_assert_non_equal_relocatable_diff_index() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from((0, 0)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::DiffIndexComp(
                relocatable!(1, 0),
                relocatable!(0, 0)
            ))
        );
    }

    #[test]
    fn run_assert_not_equal_relocatable_and_integer() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'"
            ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::DiffTypeComparison(
                MaybeRelocatable::from((1, 0)),
                MaybeRelocatable::from(bigint!(1))
            ))
        );
    }

    #[test]
    fn run_assert_not_zero_true() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        vm.segments.add(&mut vm.memory, None);
        // }
        // //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Ok(())
        );
    }

    #[test]
    fn run_assert_not_zero_false() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        vm.segments.add(&mut vm.memory, None);
        // }
        // //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::AssertNotZero(bigint!(0), vm.prime))
        );
    }

    #[test]
    fn run_assert_not_zero_false_with_prime() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        vm.segments.add(&mut vm.memory, None);
        // }
        // //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(vm.prime.clone()),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::AssertNotZero(
                vm.prime.clone(),
                vm.prime
            ))
        );
    }

    #[test]
    fn run_assert_not_zero_failed_to_get_reference() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        vm.segments.add(&mut vm.memory, None);
        // }
        // //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();
        //Create invalid id value
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(10));

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetReference(bigint!(10)))
        );
    }

    #[test]
    fn run_assert_not_zero_incorrect_id() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        vm.segments.add(&mut vm.memory, None);
        // }
        // //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();
        //Create invalid id key
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("incorrect_id"), bigint!(0));

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::IncorrectIds(
                vec![String::from("value")],
                vec![String::from("incorrect_id")],
            ))
        );
    }

    #[test]
    fn run_assert_not_zero_expected_integer_error() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        vm.segments.add(&mut vm.memory, None);
        // }
        // //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((0, 0)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn run_split_int_assertion_invalid() {
        let hint_code = "assert ids.value == 0, 'split_int(): value is out of range.'";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::SplitIntNotZero)
        );
    }

    #[test]
    fn run_split_int_assertion_valid() {
        let hint_code = "assert ids.value == 0, 'split_int(): value is out of range.'";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Ok(())
        );
    }

    #[test]
    fn run_split_int_valid() {
        let hint_code = "memory[ids.output] = res = (int(ids.value) % PRIME) % ids.base\nassert res < ids.bound, f'split_int(): Limb {res} is out of range.'";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.output
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((2, 0)),
            )
            .unwrap();
        //ids.value
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //ids.base
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .unwrap();
        //ids.bound
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(100)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("output"), bigint!(0));
        ids.insert(String::from("value"), bigint!(1));
        ids.insert(String::from("base"), bigint!(2));
        ids.insert(String::from("bound"), bigint!(3));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Ok(())
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((2, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(2))))
        );
    }

    #[test]
    fn run_split_int_invalid() {
        let hint_code = "memory[ids.output] = res = (int(ids.value) % PRIME) % ids.base\nassert res < ids.bound, f'split_int(): Limb {res} is out of range.'";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.output
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((2, 0)),
            )
            .unwrap();
        //ids.value
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(100)),
            )
            .unwrap();
        //ids.base
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(10000)),
            )
            .unwrap();
        //ids.bound
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("output"), bigint!(0));
        ids.insert(String::from("value"), bigint!(1));
        ids.insert(String::from("base"), bigint!(2));
        ids.insert(String::from("bound"), bigint!(3));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::SplitIntLimbOutOfRange(bigint!(100)))
        );
    }

    #[test]
    fn run_is_positive_hint_true() {
        let hint_code =
        "from starkware.cairo.common.math_utils import is_positive\nids.is_positive = 1 if is_positive(\n    value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0"
        ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(250)),
            )
            .unwrap();
        //Dont insert ids.is_positive as we need to modify it inside the hint
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("is_positive"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        vm.hint_executor
            .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new())
            .expect("Error while executing hint");
        //Check that is_positive now contains 1 (true)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1))))
        );
    }

    #[test]
    fn run_is_positive_hint_false() {
        let hint_code =
        "from starkware.cairo.common.math_utils import is_positive\nids.is_positive = 1 if is_positive(\n    value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0"
        ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(-250)),
            )
            .unwrap();
        //Dont insert ids.is_positive as we need to modify it inside the hint
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("is_positive"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        vm.hint_executor
            .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new())
            .expect("Error while executing hint");
        //Check that is_positive now contains 0 (false)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
    }

    #[test]
    fn run_is_positive_hint_outside_valid_range() {
        let hint_code =
        "from starkware.cairo.common.math_utils import is_positive\nids.is_positive = 1 if is_positive(\n    value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0"
        ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(BigInt::new(
                    Sign::Plus,
                    vec![1, 0, 0, 0, 0, 0, 17, 134217727],
                )),
            )
            .unwrap();
        //Dont insert ids.is_positive as we need to modify it inside the hint
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("is_positive"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ValueOutsideValidRange(as_int(
                &BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217727]),
                &vm.prime
            )))
        );
    }

    #[test]
    fn run_is_positive_hint_is_positive_not_empty() {
        let hint_code ="from starkware.cairo.common.math_utils import is_positive\nids.is_positive = 1 if is_positive(\n    value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0"
        ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //Insert ids.is_positive into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(4)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("is_positive"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((0, 1)),
                    MaybeRelocatable::from(bigint!(4)),
                    MaybeRelocatable::from(bigint!(1))
                )
            ))
        );
    }

    #[test]
    fn run_sqrt_valid() {
        let hint_code = "from starkware.python.math_utils import isqrt\nvalue = ids.value % PRIME\nassert value < 2 ** 250, f\"value={value} is outside of the range [0, 2**250).\"\nassert 2 ** 250 < PRIME\nids.root = isqrt(value)"
            ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(81)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("root"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Ok(())
        );
        //Check that root (0,1) has the square root of 81
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(9))))
        );
    }

    #[test]
    fn run_sqrt_invalid_negative_number() {
        let hint_code = "from starkware.python.math_utils import isqrt\nvalue = ids.value % PRIME\nassert value < 2 ** 250, f\"value={value} is outside of the range [0, 2**250).\"\nassert 2 ** 250 < PRIME\nids.root = isqrt(value)"
            ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(-81)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("root"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ValueOutside250BitRange(bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020400"
            )))
        );
    }

    #[test]
    fn run_sqrt_invalid_mismatched_root() {
        let hint_code = "from starkware.python.math_utils import isqrt\nvalue = ids.value % PRIME\nassert value < 2 ** 250, f\"value={value} is outside of the range [0, 2**250).\"\nassert 2 ** 250 < PRIME\nids.root = isqrt(value)"
            ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(81)),
            )
            .unwrap();
        //Insert ids.root into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(7)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("root"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((0, 1)),
                    MaybeRelocatable::from(bigint!(7)),
                    MaybeRelocatable::from(bigint!(9))
                )
            ))
        );
    }

    #[test]
    fn unsigned_div_rem_success() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\nids.q, ids.r = divmod(ids.value, ids.div)";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(7)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("r"), bigint!(0));
        ids.insert(String::from("q"), bigint!(1));
        ids.insert(String::from("div"), bigint!(2));
        ids.insert(String::from("value"), bigint!(3));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert!(vm
            .hint_executor
            .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new())
            .is_ok());
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(2))))
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1))))
        );
    }

    #[test]
    fn unsigned_div_rem_out_of_range() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\nids.q, ids.r = divmod(ids.value, ids.div)";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(-5)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(7)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("r"), bigint!(0));
        ids.insert(String::from("q"), bigint!(1));
        ids.insert(String::from("div"), bigint!(2));
        ids.insert(String::from("value"), bigint!(3));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::OutOfValidRange(
                bigint!(-5),
                bigint_str!(b"10633823966279327296825105735305134080")
            ))
        )
    }

    #[test]
    fn unsigned_div_rem_no_range_check_builtin() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\nids.q, ids.r = divmod(ids.value, ids.div)";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(7)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("r"), bigint!(0));
        ids.insert(String::from("q"), bigint!(1));
        ids.insert(String::from("div"), bigint!(2));
        ids.insert(String::from("value"), bigint!(3));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn unsigned_div_rem_inconsitent_memory() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\nids.q, ids.r = divmod(ids.value, ids.div)";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .expect("unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .expect("unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(7)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("r"), bigint!(0));
        ids.insert(String::from("q"), bigint!(1));
        ids.insert(String::from("div"), bigint!(2));
        ids.insert(String::from("value"), bigint!(3));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((0, 0)),
                    MaybeRelocatable::Int(bigint!(5)),
                    MaybeRelocatable::Int(bigint!(2))
                )
            ))
        );
    }

    #[test]
    fn unsigned_div_rem_incorrect_ids() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\nids.q, ids.r = divmod(ids.value, ids.div)";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(7)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        ids.insert(String::from("iv"), bigint!(2));
        ids.insert(String::from("vlue"), bigint!(3));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert!(matches!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::IncorrectIds(_, _))
        ))
    }

    #[test]
    fn signed_div_rem_success() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..5 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 6));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 5)),
                &MaybeRelocatable::from(bigint!(29)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("r"), bigint!(0));
        ids.insert(String::from("biased_q"), bigint!(1));
        ids.insert(String::from("range_check_ptr"), bigint!(2));
        ids.insert(String::from("div"), bigint!(3));
        ids.insert(String::from("value"), bigint!(4));
        ids.insert(String::from("bound"), bigint!(5));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -6,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                4,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                5,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert!(vm
            .hint_executor
            .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new())
            .is_ok());
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(31))))
        );
    }

    #[test]
    fn signed_div_rem_negative_quotient() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..5 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 6));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(7)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(bigint!(-10)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 5)),
                &MaybeRelocatable::from(bigint!(29)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("r"), bigint!(0));
        ids.insert(String::from("biased_q"), bigint!(1));
        ids.insert(String::from("range_check_ptr"), bigint!(2));
        ids.insert(String::from("div"), bigint!(3));
        ids.insert(String::from("value"), bigint!(4));
        ids.insert(String::from("bound"), bigint!(5));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -6,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                4,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                5,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert!(vm
            .hint_executor
            .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new())
            .is_ok());
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(4))))
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(27))))
        );
    }

    #[test]
    fn signed_div_rem_out_of_range() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..5 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 6));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(-5)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 5)),
                &MaybeRelocatable::from(bigint!(29)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("r"), bigint!(0));
        ids.insert(String::from("biased_q"), bigint!(1));
        ids.insert(String::from("range_check_ptr"), bigint!(2));
        ids.insert(String::from("div"), bigint!(3));
        ids.insert(String::from("value"), bigint!(4));
        ids.insert(String::from("bound"), bigint!(5));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -6,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                4,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                5,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::OutOfValidRange(
                bigint!(-5),
                bigint_str!(b"10633823966279327296825105735305134080")
            ))
        )
    }

    #[test]
    fn signed_div_rem_no_range_check_builtin() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..5 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 6));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 5)),
                &MaybeRelocatable::from(bigint!(29)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("r"), bigint!(0));
        ids.insert(String::from("biased_q"), bigint!(1));
        ids.insert(String::from("range_check_ptr"), bigint!(2));
        ids.insert(String::from("div"), bigint!(3));
        ids.insert(String::from("value"), bigint!(4));
        ids.insert(String::from("bound"), bigint!(5));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -6,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                4,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                5,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn signed_div_rem_inconsitent_memory() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..5 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 6));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 5)),
                &MaybeRelocatable::from(bigint!(29)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("r"), bigint!(0));
        ids.insert(String::from("biased_q"), bigint!(1));
        ids.insert(String::from("range_check_ptr"), bigint!(2));
        ids.insert(String::from("div"), bigint!(3));
        ids.insert(String::from("value"), bigint!(4));
        ids.insert(String::from("bound"), bigint!(5));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -6,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                4,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                5,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((0, 1)),
                    MaybeRelocatable::Int(bigint!(10)),
                    MaybeRelocatable::Int(bigint!(31))
                )
            ))
        );
    }

    #[test]
    fn signed_div_rem_incorrect_ids() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..5 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 6));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 5)),
                &MaybeRelocatable::from(bigint!(29)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("r"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        ids.insert(String::from("r"), bigint!(2));
        ids.insert(String::from("d"), bigint!(3));
        ids.insert(String::from("v"), bigint!(4));
        ids.insert(String::from("b"), bigint!(5));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -6,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                4,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                5,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert!(matches!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::IncorrectIds(_, _))
        ))
    }
    #[test]
    fn run_assert_250_bit_valid() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int\n\n# Correctness check.\nvalue = as_int(ids.value, PRIME) % PRIME\nassert value < ids.UPPER_BOUND, f'{value} is outside of the range [0, 2**250).'\n\n# Calculation for the assertion.\nids.high, ids.low = divmod(ids.value, ids.SHIFT)"
             ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        //Insert ids into memory
        //ids.value
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("high"), bigint!(1));
        ids.insert(String::from("low"), bigint!(2));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Ok(())
        );
        //Hint would return an error if the assertion fails
        //Check ids.high and ids.low values
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 2))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1))))
        );
    }

    #[test]
    fn run_assert_250_bit_invalid() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int\n\n# Correctness check.\nvalue = as_int(ids.value, PRIME) % PRIME\nassert value < ids.UPPER_BOUND, f'{value} is outside of the range [0, 2**250).'\n\n# Calculation for the assertion.\nids.high, ids.low = divmod(ids.value, ids.SHIFT)"
             ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        //Insert ids into memory
        //ids.value
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1).shl(251i32)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("high"), bigint!(1));
        ids.insert(String::from("low"), bigint!(2));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ValueOutside250BitRange(
                bigint!(1).shl(251i32)
            ))
        );
    }

    #[test]
    fn run_split_felt_ok() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128"
        ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 7));

        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from(bigint_str!(b"7335438970432432812899076431678123043273")),
            )
            .unwrap();

        //Insert ids.low pointer into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from((2, 0)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("low"), bigint!(1));
        ids.insert(String::from("high"), bigint!(2));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: true,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 1,
                    inner_dereference: true,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Ok(())
        );

        //Check hint memory inserts
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((2, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint_str!(
                b"189509265092725080168209675610990602697"
            ))))
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((2, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(21))))
        );
    }

    #[test]
    fn run_split_felt_incorrect_ids() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128"
        ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 7));

        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from(bigint_str!(b"7335438970432432812899076431678123043273")),
            )
            .unwrap();

        //Insert ids.low pointer into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from((2, 0)),
            )
            .unwrap();

        //Create incomplete ids
        let mut incomplete_ids = HashMap::<String, BigInt>::new();
        incomplete_ids.insert(String::from("value"), bigint!(0));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: true,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 1,
                    inner_dereference: true,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &incomplete_ids, &ApTracking::new()),
            Err(VirtualMachineError::IncorrectIds(
                vec![
                    String::from("high"),
                    String::from("low"),
                    String::from("value"),
                ],
                vec![String::from("value"),],
            ))
        );
    }
    #[test]
    fn run_split_felt_failed_to_get_ids() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128"
        ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 7));

        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from(bigint_str!(b"7335438970432432812899076431678123043273")),
            )
            .unwrap();

        //Insert ids.low pointer into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from((2, 0)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("low"), bigint!(1));
        ids.insert(String::from("high"), bigint!(2));

        //Create incorrect references
        vm.references = HashMap::from([
            // Incorrect reference
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: true,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 1,
                    inner_dereference: true,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_split_felt_fails_first_insert() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128"
        ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 7));

        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from(bigint_str!(b"7335438970432432812899076431678123043273")),
            )
            .unwrap();

        //Insert ids.low pointer into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from((2, 0)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("low"), bigint!(1));
        ids.insert(String::from("high"), bigint!(2));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: true,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 1,
                    inner_dereference: true,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);

        // Override MaybeRelocatable::from((2, 0)) memory address so, the hint vm.memory.insert fails
        vm.memory
            .insert(
                &MaybeRelocatable::from((2, 0)),
                &MaybeRelocatable::from(bigint!(99)),
            )
            .unwrap();

        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((2, 0)),
                    MaybeRelocatable::from(bigint!(99)),
                    MaybeRelocatable::from(bigint_str!(b"189509265092725080168209675610990602697"))
                )
            ))
        );
    }

    #[test]
    fn run_split_felt_fails_second_insert() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128"
        ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 7));

        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from(bigint_str!(b"7335438970432432812899076431678123043273")),
            )
            .unwrap();

        //Insert ids.low pointer into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from((2, 0)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("low"), bigint!(1));
        ids.insert(String::from("high"), bigint!(2));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: true,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 1,
                    inner_dereference: true,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);

        // Override MaybeRelocatable::from((2, 1)) memory address so, the hint vm.memory.insert fails
        vm.memory
            .insert(
                &MaybeRelocatable::from((2, 1)),
                &MaybeRelocatable::from(bigint!(99)),
            )
            .unwrap();

        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((2, 1)),
                    MaybeRelocatable::from(bigint!(99)),
                    MaybeRelocatable::from(bigint!(21))
                )
            ))
        );
    }

    #[test]
    fn run_split_felt_value_is_not_integer() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128"
        ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 7));

        //Insert insert RelocatableValue in ids.value memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();

        //Insert ids.low pointer into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from((2, 0)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("low"), bigint!(1));
        ids.insert(String::from("high"), bigint!(2));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: true,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 1,
                    inner_dereference: true,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 3))
            ))
        );
    }

    #[test]
    fn run_assert_lt_felt_ok() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"
        ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        //Initialize memory segements
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 3));

        //Insert ids.a into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        //Insert ids.b into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Ok(())
        );
    }

    #[test]
    fn run_assert_lt_felt_assert_fails() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"
        ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        //Initialize memory segements
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 3));

        //Insert ids.a into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(3)),
            )
            .unwrap();

        //Insert ids.b into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::AssertLtFelt(bigint!(3), bigint!(2)))
        );
    }

    #[test]
    fn run_assert_lt_felt_incorrect_ids() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"
        ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        //Initialize memory segements
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 3));

        //Insert ids.a into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        //Insert ids.b into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();

        //Create Incorrects ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::IncorrectIds(
                vec![String::from("a"), String::from("b"),],
                vec![String::from("a"),],
            ))
        );
    }

    #[test]
    fn run_assert_lt_felt_incorrect_references() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"
        ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        //Initialize memory segements
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 3));

        //Insert ids.a into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        //Insert ids.b into memory
        // vm.memory
        //     .insert(
        //         &MaybeRelocatable::from((1, 2)),
        //         &MaybeRelocatable::from(bigint!(2)),
        //     )
        //     .unwrap();

        //Create incorrects ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));

        //Create incorrect references
        vm.references = HashMap::from([
            // Incorrect reference
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_assert_lt_felt_a_is_not_integer() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"
        ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        //Initialize memory segements
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 3));

        //Insert ids.a into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();

        //Insert ids.b into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 1))
            ))
        );
    }

    #[test]
    fn run_assert_lt_felt_b_is_not_integer() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"
        ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        //Initialize memory segements
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 3));

        //Insert ids.a into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        //Insert ids.b into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 2))
            ))
        );
    }

    #[test]
    fn run_assert_lt_felt_ok_failed_to_get_ids() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"
        ;
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );
        //Initialize memory segements
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 3));

        //Insert ids.a into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        //Skip insert ids.b into memory
        // vm.memory
        //     .insert(
        //         &MaybeRelocatable::from((1, 2)),
        //         &MaybeRelocatable::from(bigint!(2)),
        //     )
        //     .unwrap();

        //Create incorrects ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn memcpy_enter_scope_valid() {
        let hint_code = "vm_enter_scope({'n': ids.len})";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));

        // insert ids.len into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("len"), bigint!(0));

        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -2,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);

        assert!(vm
            .hint_executor
            .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new())
            .is_ok());
    }

    #[test]
    fn memcpy_enter_scope_invalid() {
        let hint_code = "vm_enter_scope({'n': ids.len})";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));

        // insert ids.len into memory
        // we insert a relocatable value in the address of ids.len so that it raises an error.
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from((0, 0)),
            )
            .unwrap();

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("len"), bigint!(0));

        // create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -2,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 1))
            ))
        );
    }

    #[test]
    fn memcpy_continue_copying_valid() {
        let hint_code = "n -= 1\nids.continue_copying = 1 if n > 0 else 0";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));

        // initialize vm scope with variable `n`
        vm.exec_scopes
            .assign_or_update_variable("n", PyValueType::BigInt(bigint!(1)));

        // initialize ids.continue_copying
        // we create a memory gap so that there is None in (0, 1), the actual addr of continue_copying
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("continue_copying"), bigint!(0));

        // create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -2,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);

        assert!(vm
            .hint_executor
            .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new())
            .is_ok());
    }

    #[test]
    fn memcpy_continue_copying_variable_not_in_scope_error() {
        let hint_code = "n -= 1\nids.continue_copying = 1 if n > 0 else 0";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));

        // we don't initialize `n` now:
        /*  vm.exec_scopes
        .assign_or_update_variable("n", PyValueType::BigInt(bigint!(1)));  */

        // initialize ids.continue_copying
        // we create a memory gap so that there is None in (0, 1), the actual addr of continue_copying
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("continue_copying"), bigint!(0));

        // create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -2,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::VariableNotInScopeError(
                "n".to_string()
            ))
        );
    }

    #[test]
    fn memcpy_continue_copying_insert_error() {
        let hint_code = "n -= 1\nids.continue_copying = 1 if n > 0 else 0";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));

        // initialize with variable `n`
        vm.exec_scopes
            .assign_or_update_variable("n", PyValueType::BigInt(bigint!(1)));

        // initialize ids.continue_copying
        // a value is written in the address so the hint cant insert value there
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("continue_copying"), bigint!(0));

        // create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -2,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((0, 1)),
                    MaybeRelocatable::from(bigint!(5)),
                    MaybeRelocatable::from(bigint!(0))
                )
            ))
        );
    }

    #[test]
    fn exit_scope_valid() {
        let hint_code = "vm_exit_scope()";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

        // create new vm scope with dummy variable
        vm.exec_scopes.enter_scope(HashMap::from([(
            String::from("a"),
            PyValueType::BigInt(bigint!(1)),
        )]));

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        assert!(vm
            .hint_executor
            .execute_hint(&mut vm, hint_code, &HashMap::new(), &ApTracking::new())
            .is_ok());
    }

    #[test]
    fn exit_scope_invalid() {
        let hint_code = "vm_exit_scope()";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

        // new vm scope is not created so that the hint raises an error:
        //vm.exec_scopes.enter_scope(HashMap::from([(String::from("a"), PyValueType::BigInt(bigint!(1)))]));

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &HashMap::new(), &ApTracking::new()),
            Err(VirtualMachineError::MainScopeError(
                ExecScopeError::ExitMainScopeError
            ))
        );
    }

    #[test]
    fn run_enter_scope() {
        let hint_code = "vm_enter_scope()";
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        //Execute the hint
        assert_eq!(
            vm.hint_executor.execute_hint(
                &mut vm,
                hint_code,
                &HashMap::new(),
                &ApTracking::default()
            ),
            Ok(())
        );
        //Check exec_scopes
        let expected_scope = vec![HashMap::new(), HashMap::new()];
        assert_eq!(vm.exec_scopes.data, expected_scope)
    }

    #[test]
    fn unsafe_keccak_valid() {
        let hint_code = "from eth_hash.auto import keccak\n\ndata, length = ids.data, ids.length\n\nif '__keccak_max_size' in globals():\n    assert length <= __keccak_max_size, \\\n        f'unsafe_keccak() can only be used with length<={__keccak_max_size}. ' \\\n        f'Got: length={length}.'\n\nkeccak_input = bytearray()\nfor word_i, byte_i in enumerate(range(0, length, 16)):\n    word = memory[data + word_i]\n    n_bytes = min(16, length - byte_i)\n    assert 0 <= word < 2 ** (8 * n_bytes)\n    keccak_input += word.to_bytes(n_bytes, 'big')\n\nhashed = keccak(keccak_input)\nids.high = int.from_bytes(hashed[:16], 'big')\nids.low = int.from_bytes(hashed[16:32], 'big')";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));

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

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("length"), bigint!(0));
        ids.insert(String::from("data"), bigint!(1));
        ids.insert(String::from("high"), bigint!(2));
        ids.insert(String::from("low"), bigint!(3));

        vm.exec_scopes
            .assign_or_update_variable("__keccak_max_size", PyValueType::BigInt(bigint!(500)));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);

        assert!(vm
            .hint_executor
            .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new())
            .is_ok());
    }

    #[test]
    fn unsafe_keccak_max_size() {
        let hint_code = "from eth_hash.auto import keccak\n\ndata, length = ids.data, ids.length\n\nif '__keccak_max_size' in globals():\n    assert length <= __keccak_max_size, \\\n        f'unsafe_keccak() can only be used with length<={__keccak_max_size}. ' \\\n        f'Got: length={length}.'\n\nkeccak_input = bytearray()\nfor word_i, byte_i in enumerate(range(0, length, 16)):\n    word = memory[data + word_i]\n    n_bytes = min(16, length - byte_i)\n    assert 0 <= word < 2 ** (8 * n_bytes)\n    keccak_input += word.to_bytes(n_bytes, 'big')\n\nhashed = keccak(keccak_input)\nids.high = int.from_bytes(hashed[:16], 'big')\nids.low = int.from_bytes(hashed[16:32], 'big')";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));

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

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("length"), bigint!(0));
        ids.insert(String::from("data"), bigint!(1));
        ids.insert(String::from("high"), bigint!(2));
        ids.insert(String::from("low"), bigint!(3));

        vm.exec_scopes
            .assign_or_update_variable("__keccak_max_size", PyValueType::BigInt(bigint!(2)));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::KeccakMaxSize(bigint!(5), bigint!(2)))
        );
    }

    #[test]
    fn unsafe_keccak_invalid_input_length() {
        let hint_code = "from eth_hash.auto import keccak\n\ndata, length = ids.data, ids.length\n\nif '__keccak_max_size' in globals():\n    assert length <= __keccak_max_size, \\\n        f'unsafe_keccak() can only be used with length<={__keccak_max_size}. ' \\\n        f'Got: length={length}.'\n\nkeccak_input = bytearray()\nfor word_i, byte_i in enumerate(range(0, length, 16)):\n    word = memory[data + word_i]\n    n_bytes = min(16, length - byte_i)\n    assert 0 <= word < 2 ** (8 * n_bytes)\n    keccak_input += word.to_bytes(n_bytes, 'big')\n\nhashed = keccak(keccak_input)\nids.high = int.from_bytes(hashed[:16], 'big')\nids.low = int.from_bytes(hashed[16:32], 'big')";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));

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

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("length"), bigint!(0));
        ids.insert(String::from("data"), bigint!(1));
        ids.insert(String::from("high"), bigint!(2));
        ids.insert(String::from("low"), bigint!(3));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);

        assert!(vm
            .hint_executor
            .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new())
            .is_err());
    }

    #[test]
    fn unsafe_keccak_invalid_word_size() {
        let hint_code = "from eth_hash.auto import keccak\n\ndata, length = ids.data, ids.length\n\nif '__keccak_max_size' in globals():\n    assert length <= __keccak_max_size, \\\n        f'unsafe_keccak() can only be used with length<={__keccak_max_size}. ' \\\n        f'Got: length={length}.'\n\nkeccak_input = bytearray()\nfor word_i, byte_i in enumerate(range(0, length, 16)):\n    word = memory[data + word_i]\n    n_bytes = min(16, length - byte_i)\n    assert 0 <= word < 2 ** (8 * n_bytes)\n    keccak_input += word.to_bytes(n_bytes, 'big')\n\nhashed = keccak(keccak_input)\nids.high = int.from_bytes(hashed[:16], 'big')\nids.low = int.from_bytes(hashed[16:32], 'big')";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));

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

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("length"), bigint!(0));
        ids.insert(String::from("data"), bigint!(1));
        ids.insert(String::from("high"), bigint!(2));
        ids.insert(String::from("low"), bigint!(3));

        vm.exec_scopes
            .assign_or_update_variable("__keccak_max_size", PyValueType::BigInt(bigint!(10)));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::InvalidWordSize(bigint!(-1)))
        );
    }

    #[test]
    fn unsafe_keccak_finalize_valid() {
        let hint_code = "from eth_hash.auto import keccak\nkeccak_input = bytearray()\nn_elms = ids.keccak_state.end_ptr - ids.keccak_state.start_ptr\nfor word in memory.get_range(ids.keccak_state.start_ptr, n_elms):\n    keccak_input += word.to_bytes(16, 'big')\nhashed = keccak(keccak_input)\nids.high = int.from_bytes(hashed[:16], 'big')\nids.low = int.from_bytes(hashed[16:32], 'big')";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

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

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("keccak_state"), bigint!(0));
        ids.insert(String::from("high"), bigint!(1));
        ids.insert(String::from("low"), bigint!(2));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -7,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);

        assert!(vm
            .hint_executor
            .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new())
            .is_ok());
    }

    #[test]
    fn unsafe_keccak_finalize_nones_in_range() {
        let hint_code = "from eth_hash.auto import keccak\nkeccak_input = bytearray()\nn_elms = ids.keccak_state.end_ptr - ids.keccak_state.start_ptr\nfor word in memory.get_range(ids.keccak_state.start_ptr, n_elms):\n    keccak_input += word.to_bytes(16, 'big')\nhashed = keccak(keccak_input)\nids.high = int.from_bytes(hashed[:16], 'big')\nids.low = int.from_bytes(hashed[16:32], 'big')";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

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

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("keccak_state"), bigint!(0));
        ids.insert(String::from("high"), bigint!(1));
        ids.insert(String::from("low"), bigint!(2));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -7,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::NoneInMemoryRange)
        );
    }

    #[test]
    fn unsafe_keccak_finalize_expected_integer_at_range() {
        let hint_code = "from eth_hash.auto import keccak\nkeccak_input = bytearray()\nn_elms = ids.keccak_state.end_ptr - ids.keccak_state.start_ptr\nfor word in memory.get_range(ids.keccak_state.start_ptr, n_elms):\n    keccak_input += word.to_bytes(16, 'big')\nhashed = keccak(keccak_input)\nids.high = int.from_bytes(hashed[:16], 'big')\nids.low = int.from_bytes(hashed[16:32], 'big')";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

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

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("keccak_state"), bigint!(0));
        ids.insert(String::from("high"), bigint!(1));
        ids.insert(String::from("low"), bigint!(2));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -7,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);

        assert!(vm
            .hint_executor
            .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new())
            .is_err());
    }
}
