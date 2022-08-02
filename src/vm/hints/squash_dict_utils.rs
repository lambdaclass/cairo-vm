use std::collections::HashMap;

use num_bigint::BigInt;
use num_traits::{FromPrimitive, ToPrimitive};

use crate::{
    bigint, bigintusize,
    serde::deserialize_program::ApTracking,
    types::{exec_scope::PyValueType, relocatable::MaybeRelocatable},
    vm::{errors::vm_errors::VirtualMachineError, vm_core::VirtualMachine},
};

use super::{
    dict_hint_utils::DICT_ACCESS_SIZE,
    hint_utils::{
        get_int_from_scope, get_integer_from_var_name, get_list_from_scope,
        get_list_ref_from_scope, get_mut_list_ref_from_scope, get_ptr_from_var_name,
        get_range_check_builtin, get_relocatable_from_var_name, insert_int_into_scope,
        insert_integer_from_var_name, insert_list_into_scope,
    },
};

fn get_access_indices(
    vm: &mut VirtualMachine,
) -> Result<&HashMap<BigInt, Vec<BigInt>>, VirtualMachineError> {
    let mut access_indices: Option<&HashMap<BigInt, Vec<BigInt>>> = None;
    if let Some(variables) = vm.exec_scopes.get_local_variables() {
        if let Some(PyValueType::KeyToListMap(py_access_indices)) = variables.get("access_indices")
        {
            access_indices = Some(py_access_indices);
        }
    }
    access_indices
        .ok_or_else(|| VirtualMachineError::VariableNotInScopeError("access_indices".to_string()))
}

/*Implements hint:
    current_access_indices = sorted(access_indices[key])[::-1]
    current_access_index = current_access_indices.pop()
    memory[ids.range_check_ptr] = current_access_index
*/
pub fn squash_dict_inner_first_iteration(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    //Check that access_indices and key are in scope
    let key = get_int_from_scope(&vm.exec_scopes, "key")?;
    let range_check_ptr = get_ptr_from_var_name("range_check_ptr", ids, vm, hint_ap_tracking)?;
    let access_indices = get_access_indices(vm)?;
    //Get current_indices from access_indices
    let mut current_access_indices = access_indices
        .get(&key)
        .ok_or_else(|| VirtualMachineError::NoKeyInAccessIndices(key.clone()))?
        .clone();
    current_access_indices.sort();
    current_access_indices.reverse();
    //Get current_access_index
    let first_val = current_access_indices
        .pop()
        .ok_or(VirtualMachineError::EmptyCurrentAccessIndices)?;
    //Store variables in scope
    insert_list_into_scope(
        &mut vm.exec_scopes,
        "current_access_indices",
        current_access_indices,
    );
    insert_int_into_scope(
        &mut vm.exec_scopes,
        "current_access_index",
        first_val.clone(),
    );
    //Insert current_accesss_index into range_check_ptr
    vm.memory.insert_integer(&range_check_ptr, first_val)
}

// Implements Hint: ids.should_skip_loop = 0 if current_access_indices else 1
pub fn squash_dict_inner_skip_loop(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    //Check that current_access_indices is in scope
    let current_access_indices = get_list_from_scope(&vm.exec_scopes, "current_access_indices")?;
    //Main Logic
    let should_skip_loop = if current_access_indices.is_empty() {
        bigint!(1)
    } else {
        bigint!(0)
    };
    insert_integer_from_var_name(
        "should_skip_loop",
        should_skip_loop,
        ids,
        vm,
        hint_ap_tracking,
    )
}

/*Implements Hint:
   new_access_index = current_access_indices.pop()
   ids.loop_temps.index_delta_minus1 = new_access_index - current_access_index - 1
   current_access_index = new_access_index
*/
pub fn squash_dict_inner_check_access_index(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    //Check that current_access_indices and current_access_index are in scope
    let current_access_index = get_int_from_scope(&vm.exec_scopes, "current_access_index")?;
    let current_access_indices =
        get_mut_list_ref_from_scope(&mut vm.exec_scopes, "current_access_indices")?;
    //Main Logic
    let new_access_index = current_access_indices
        .pop()
        .ok_or(VirtualMachineError::EmptyCurrentAccessIndices)?;
    let index_delta_minus1 = new_access_index.clone() - current_access_index - bigint!(1);
    //loop_temps.delta_minus1 = loop_temps + 0 as it is the first field of the struct
    //Insert loop_temps.delta_minus1 into memory
    insert_integer_from_var_name("loop_temps", index_delta_minus1, ids, vm, hint_ap_tracking)?;
    insert_int_into_scope(
        &mut vm.exec_scopes,
        "new_access_index",
        new_access_index.clone(),
    );
    insert_int_into_scope(
        &mut vm.exec_scopes,
        "current_access_index",
        new_access_index,
    );
    Ok(())
}

// Implements Hint: ids.loop_temps.should_continue = 1 if current_access_indices else 0
pub fn squash_dict_inner_continue_loop(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    //Check that ids contains the reference id for each variable used by the hint
    //Get addr for ids variables
    let loop_temps_addr = get_relocatable_from_var_name("loop_temps", ids, vm, hint_ap_tracking)?;
    //Check that current_access_indices is in scope
    let current_access_indices =
        get_list_ref_from_scope(&vm.exec_scopes, "current_access_indices")?;
    //Main Logic
    let should_continue = if current_access_indices.is_empty() {
        bigint!(0)
    } else {
        bigint!(1)
    };
    //loop_temps.delta_minus1 = loop_temps + 3 as it is the fourth field of the struct
    //Insert loop_temps.delta_minus1 into memory
    let should_continue_addr = loop_temps_addr + 3;
    vm.memory
        .insert_integer(&should_continue_addr, should_continue)
}

// Implements Hint: assert len(current_access_indices) == 0
pub fn squash_dict_inner_len_assert(vm: &mut VirtualMachine) -> Result<(), VirtualMachineError> {
    //Check that current_access_indices is in scope
    let current_access_indices =
        get_list_ref_from_scope(&vm.exec_scopes, "current_access_indices")?;
    if !current_access_indices.is_empty() {
        return Err(VirtualMachineError::CurrentAccessIndicesNotEmpty);
    }
    Ok(())
}

//Implements hint: assert ids.n_used_accesses == len(access_indices[key]
pub fn squash_dict_inner_used_accesses_assert(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let key = get_int_from_scope(&vm.exec_scopes, "key")?;
    let n_used_accesses =
        get_integer_from_var_name("n_used_accesses", ids, vm, hint_ap_tracking)?.clone();
    let access_indices = get_access_indices(vm)?;
    //Main Logic
    let access_indices_at_key = access_indices
        .get(&key)
        .ok_or_else(|| VirtualMachineError::NoKeyInAccessIndices(key.clone()))?;

    if n_used_accesses != bigintusize!(access_indices_at_key.len()) {
        return Err(VirtualMachineError::NumUsedAccessesAssertFail(
            n_used_accesses,
            access_indices_at_key.len(),
            key,
        ));
    }
    Ok(())
}

// Implements Hint: assert len(keys) == 0
pub fn squash_dict_inner_assert_len_keys(
    vm: &mut VirtualMachine,
) -> Result<(), VirtualMachineError> {
    //Check that current_access_indices is in scope
    let keys = get_list_ref_from_scope(&vm.exec_scopes, "keys")?;
    if !keys.is_empty() {
        return Err(VirtualMachineError::KeysNotEmpty);
    };
    Ok(())
}

// Implements Hint:
//  assert len(keys) > 0, 'No keys left but remaining_accesses > 0.'
//  ids.next_key = key = keys.pop()
pub fn squash_dict_inner_next_key(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    //Check that current_access_indices is in scope
    let keys = get_mut_list_ref_from_scope(&mut vm.exec_scopes, "keys")?;
    let next_key = keys.pop().ok_or(VirtualMachineError::EmptyKeys)?;
    //Insert next_key into ids.next_keys
    insert_integer_from_var_name("next_key", next_key.clone(), ids, vm, hint_ap_tracking)?;
    //Update local variables
    insert_int_into_scope(&mut vm.exec_scopes, "key", next_key);
    Ok(())
}

/*Implements hint:
    dict_access_size = ids.DictAccess.SIZE
    address = ids.dict_accesses.address_
    assert ids.ptr_diff % dict_access_size == 0, \
        'Accesses array size must be divisible by DictAccess.SIZE'
    n_accesses = ids.n_accesses
    if '__squash_dict_max_size' in globals():
        assert n_accesses <= __squash_dict_max_size, \
            f'squash_dict() can only be used with n_accesses<={__squash_dict_max_size}. ' \
            f'Got: n_accesses={n_accesses}.'
    # A map from key to the list of indices accessing it.
    access_indices = {}
    for i in range(n_accesses):
        key = memory[address + dict_access_size * i]
        access_indices.setdefault(key, []).append(i)
    # Descending list of keys.
    keys = sorted(access_indices.keys(), reverse=True)
    # Are the keys used bigger than range_check bound.
    ids.big_keys = 1 if keys[0] >= range_check_builtin.bound else 0
    ids.first_key = key = keys.pop()
*/
pub fn squash_dict(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    //Get necessary variables addresses from ids
    let address = get_ptr_from_var_name("dict_accesses", ids, vm, hint_ap_tracking)?;
    let ptr_diff = get_integer_from_var_name("ptr_diff", ids, vm, hint_ap_tracking)?;
    let n_accesses = get_integer_from_var_name("n_accesses", ids, vm, hint_ap_tracking)?.clone();
    //Get range_check_builtin
    let range_check_builtin = get_range_check_builtin(vm)?;
    let range_check_bound = range_check_builtin._bound.clone();
    //Main Logic
    if ptr_diff % DICT_ACCESS_SIZE != bigint!(0) {
        return Err(VirtualMachineError::PtrDiffNotDivisibleByDictAccessSize);
    }
    let squash_dict_max_size = get_int_from_scope(&vm.exec_scopes, "__squash_dict_max_size");
    if let Ok(max_size) = squash_dict_max_size {
        if n_accesses > max_size {
            return Err(VirtualMachineError::SquashDictMaxSizeExceeded(
                max_size, n_accesses,
            ));
        };
    };
    let n_accesses_usize = n_accesses
        .to_usize()
        .ok_or_else(|| VirtualMachineError::NAccessesTooBig(n_accesses.clone()))?;
    //A map from key to the list of indices accessing it.
    let mut access_indices = HashMap::<BigInt, Vec<BigInt>>::new();
    for i in 0..n_accesses_usize {
        let key_addr = address.clone() + DICT_ACCESS_SIZE * i;
        let key = vm
            .memory
            .get_integer(&key_addr)
            .map_err(|_| VirtualMachineError::ExpectedInteger(MaybeRelocatable::from(key_addr)))?;
        access_indices
            .entry(key.clone())
            .or_insert(vec![])
            .push(bigintusize!(i));
    }
    //Descending list of keys.
    let mut keys: Vec<BigInt> = access_indices.keys().cloned().collect();
    keys.sort();
    keys.reverse();
    //Are the keys used bigger than the range_check bound.
    let big_keys = if keys[0] >= range_check_bound {
        bigint!(1)
    } else {
        bigint!(0)
    };
    insert_integer_from_var_name("big_keys", big_keys, ids, vm, hint_ap_tracking)?;
    let key = keys.pop().ok_or(VirtualMachineError::EmptyKeys)?;
    insert_integer_from_var_name("first_key", key.clone(), ids, vm, hint_ap_tracking)?;
    //Insert local variables into scope
    vm.exec_scopes
        .assign_or_update_variable("access_indices", PyValueType::KeyToListMap(access_indices));
    insert_list_into_scope(&mut vm.exec_scopes, "keys", keys);
    insert_int_into_scope(&mut vm.exec_scopes, "key", key);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::bigint;
    use crate::serde::deserialize_program::ApTracking;
    use crate::types::exec_scope::PyValueType;
    use crate::types::instruction::Register;
    use crate::vm::hints::execute_hint::{execute_hint, HintReference};
    use crate::vm::runners::builtin_runner::RangeCheckBuiltinRunner;
    use num_bigint::Sign;
    use num_traits::FromPrimitive;

    use super::*;
    //Hint code as consts
    const SQUASH_DICT_INNER_FIRST_ITERATION : &str = "current_access_indices = sorted(access_indices[key])[::-1]\ncurrent_access_index = current_access_indices.pop()\nmemory[ids.range_check_ptr] = current_access_index";
    const SQUASH_DICT_INNER_SKIP_LOOP: &str =
        "ids.should_skip_loop = 0 if current_access_indices else 1";
    const SQUASH_DICT_INNER_CHECK_ACCESS_INDEX: &str = "new_access_index = current_access_indices.pop()\nids.loop_temps.index_delta_minus1 = new_access_index - current_access_index - 1\ncurrent_access_index = new_access_index";
    const SQUASH_DICT_INNER_CONTINUE_LOOP: &str =
        "ids.loop_temps.should_continue = 1 if current_access_indices else 0";
    const SQUASH_DICT_INNER_ASSERT_LEN: &str = "assert len(current_access_indices) == 0";
    const SQUASH_DICT_INNER_USED_ACCESSES_ASSERT: &str =
        "assert ids.n_used_accesses == len(access_indices[key])";
    const SQUASH_DICT_INNER_LEN_KEYS: &str = "assert len(keys) == 0";
    const SQUASH_DICT_INNER_NEXT_KEY: &str = "assert len(keys) > 0, 'No keys left but remaining_accesses > 0.'\nids.next_key = key = keys.pop()";
    const SQUASH_DICT: &str ="dict_access_size = ids.DictAccess.SIZE\naddress = ids.dict_accesses.address_\nassert ids.ptr_diff % dict_access_size == 0, \\\n    'Accesses array size must be divisible by DictAccess.SIZE'\nn_accesses = ids.n_accesses\nif '__squash_dict_max_size' in globals():\n    assert n_accesses <= __squash_dict_max_size, \\\n        f'squash_dict() can only be used with n_accesses<={__squash_dict_max_size}. ' \\\n        f'Got: n_accesses={n_accesses}.'\n# A map from key to the list of indices accessing it.\naccess_indices = {}\nfor i in range(n_accesses):\n    key = memory[address + dict_access_size * i]\n    access_indices.setdefault(key, []).append(i)\n# Descending list of keys.\nkeys = sorted(access_indices.keys(), reverse=True)\n# Are the keys used bigger than range_check bound.\nids.big_keys = 1 if keys[0] >= range_check_builtin.bound else 0\nids.first_key = key = keys.pop()";
    #[test]
    fn squash_dict_inner_first_iteration_valid() {
        let hint_code = SQUASH_DICT_INNER_FIRST_ITERATION.as_bytes();
        //Prepare scope variables
        let mut access_indices = HashMap::<BigInt, Vec<BigInt>>::new();
        let current_accessed_indices = vec![bigint!(9), bigint!(3), bigint!(10), bigint!(7)];
        access_indices.insert(bigint!(5), current_accessed_indices);
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        vm.exec_scopes
            .assign_or_update_variable("access_indices", PyValueType::KeyToListMap(access_indices));
        vm.exec_scopes
            .assign_or_update_variable("key", PyValueType::BigInt(bigint!(5)));
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory (range_check_ptr)
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("range_check_ptr"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Ok(())
        );
        //Check scope variables
        //Prepare expected data
        let variables = vm.exec_scopes.get_local_variables().unwrap();
        let current_access_indices_scope = variables.get("current_access_indices").unwrap();
        assert_eq!(
            current_access_indices_scope,
            &PyValueType::List(vec![bigint!(10), bigint!(9), bigint!(7)])
        );
        let current_access_index = variables.get("current_access_index").unwrap();
        assert_eq!(current_access_index, &PyValueType::BigInt(bigint!(3)));
        //Check that current_access_index is now at range_check_ptr
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(3))))
        );
    }

    #[test]
    fn squash_dict_inner_first_iteration_empty_accessed_indices() {
        let hint_code = SQUASH_DICT_INNER_FIRST_ITERATION.as_bytes();
        //Prepare scope variables
        let mut access_indices = HashMap::<BigInt, Vec<BigInt>>::new();
        //Leave current_accessed_indices empty
        let current_accessed_indices = vec![];
        access_indices.insert(bigint!(5), current_accessed_indices);
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        vm.exec_scopes
            .assign_or_update_variable("access_indices", PyValueType::KeyToListMap(access_indices));
        vm.exec_scopes
            .assign_or_update_variable("key", PyValueType::BigInt(bigint!(5)));
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory (range_check_ptr)
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("range_check_ptr"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Err(VirtualMachineError::EmptyCurrentAccessIndices)
        );
    }

    #[test]
    fn squash_dict_inner_first_iteration_no_local_variables() {
        let hint_code = SQUASH_DICT_INNER_FIRST_ITERATION.as_bytes();
        //No scope variables
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory (range_check_ptr)
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("range_check_ptr"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Err(VirtualMachineError::VariableNotInScopeError(String::from(
                "key"
            )))
        );
    }

    #[test]
    fn should_skip_loop_valid_empty_current_access_indices() {
        let hint_code = SQUASH_DICT_INNER_SKIP_LOOP.as_bytes();
        //Prepare scope variables
        let current_access_indices = vec![];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        for _ in 0..1 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        vm.exec_scopes.assign_or_update_variable(
            "current_access_indices",
            PyValueType::List(current_access_indices),
        );
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("should_skip_loop"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Ok(())
        );
        //Check the value of ids.should_skip_loop
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1))))
        );
    }

    #[test]
    fn should_skip_loop_valid_non_empty_current_access_indices() {
        let hint_code = SQUASH_DICT_INNER_SKIP_LOOP.as_bytes();
        //Prepare scope variables
        let current_access_indices = vec![bigint!(4), bigint!(7)];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        for _ in 0..1 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        vm.exec_scopes.assign_or_update_variable(
            "current_access_indices",
            PyValueType::List(current_access_indices),
        );
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("should_skip_loop"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Ok(())
        );
        //Check the value of ids.should_skip_loop
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
    }

    #[test]
    fn squash_dict_inner_check_access_index_valid() {
        let hint_code = SQUASH_DICT_INNER_CHECK_ACCESS_INDEX.as_bytes();
        //Prepare scope variables
        let current_access_indices = vec![bigint!(10), bigint!(9), bigint!(7), bigint!(5)];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        vm.exec_scopes.assign_or_update_variable(
            "current_access_indices",
            PyValueType::List(current_access_indices),
        );
        vm.exec_scopes
            .assign_or_update_variable("current_access_index", PyValueType::BigInt(bigint!(1)));
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("loop_temps"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Ok(())
        );
        //Check scope variables
        let variables = vm.exec_scopes.get_local_variables().unwrap();
        let current_access_indices_scope = variables.get("current_access_indices").unwrap();
        let new_access_index = variables.get("new_access_index").unwrap();
        let current_access_index = variables.get("current_access_index").unwrap();
        assert_eq!(
            current_access_indices_scope,
            &PyValueType::List(vec![bigint!(10), bigint!(9), bigint!(7)])
        );
        assert_eq!(current_access_index, &PyValueType::BigInt(bigint!(5)));
        assert_eq!(new_access_index, &PyValueType::BigInt(bigint!(5)));
        //Check the value of loop_temps.index_delta_minus_1
        //new_index - current_index -1
        //5 - 1 - 1 = 3
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(3))))
        );
    }

    #[test]
    fn squash_dict_inner_check_access_current_access_addr_empty() {
        let hint_code = SQUASH_DICT_INNER_CHECK_ACCESS_INDEX.as_bytes();
        //Prepare scope variables
        let current_access_indices = vec![];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        vm.exec_scopes.assign_or_update_variable(
            "current_access_indices",
            PyValueType::List(current_access_indices),
        );
        vm.exec_scopes
            .assign_or_update_variable("current_access_index", PyValueType::BigInt(bigint!(1)));
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory (loop_temps)
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("loop_temps"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Err(VirtualMachineError::EmptyCurrentAccessIndices)
        );
    }

    #[test]
    fn should_continue_loop_valid_non_empty_current_access_indices() {
        let hint_code = SQUASH_DICT_INNER_CONTINUE_LOOP.as_bytes();
        //Prepare scope variables
        let current_access_indices = vec![bigint!(4), bigint!(7)];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        vm.exec_scopes.assign_or_update_variable(
            "current_access_indices",
            PyValueType::List(current_access_indices),
        );
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("loop_temps"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Ok(())
        );
        //Check the value of ids.loop_temps.should_continue (loop_temps + 3)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 3))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1))))
        );
    }

    #[test]
    fn should_continue_loop_valid_empty_current_access_indices() {
        let hint_code = SQUASH_DICT_INNER_CONTINUE_LOOP.as_bytes();
        //Prepare scope variables
        let current_access_indices = vec![];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        vm.exec_scopes.assign_or_update_variable(
            "current_access_indices",
            PyValueType::List(current_access_indices),
        );
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("loop_temps"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Ok(())
        );
        //Check the value of ids.loop_temps.should_continue (loop_temps + 3)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 3))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
    }

    #[test]
    fn assert_current_indices_len_is_empty() {
        let hint_code = SQUASH_DICT_INNER_ASSERT_LEN.as_bytes();
        //Prepare scope variables
        let current_access_indices = vec![];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        //Store scope variables
        vm.exec_scopes.assign_or_update_variable(
            "current_access_indices",
            PyValueType::List(current_access_indices),
        );
        //Execute the hint
        //Hint should produce an error if assertion fails
        assert_eq!(
            execute_hint(&mut vm, hint_code, HashMap::new(), &ApTracking::default()),
            Ok(())
        );
    }

    #[test]
    fn assert_current_indices_len_is_empty_not() {
        let hint_code = SQUASH_DICT_INNER_ASSERT_LEN.as_bytes();
        //Prepare scope variables
        let current_access_indices = vec![bigint!(29)];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        //Store scope variables
        vm.exec_scopes.assign_or_update_variable(
            "current_access_indices",
            PyValueType::List(current_access_indices),
        );
        //Execute the hint
        //Hint should produce an error if assertion fails
        assert_eq!(
            execute_hint(&mut vm, hint_code, HashMap::new(), &ApTracking::default()),
            Err(VirtualMachineError::CurrentAccessIndicesNotEmpty)
        );
    }

    #[test]
    fn squash_dict_inner_uses_accesses_assert_valid() {
        let hint_code = SQUASH_DICT_INNER_USED_ACCESSES_ASSERT.as_bytes();
        //Prepare scope variables
        let mut access_indices = HashMap::<BigInt, Vec<BigInt>>::new();
        let current_accessed_indices = vec![bigint!(9), bigint!(3), bigint!(10), bigint!(7)];
        access_indices.insert(bigint!(5), current_accessed_indices);
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        vm.exec_scopes
            .assign_or_update_variable("access_indices", PyValueType::KeyToListMap(access_indices));
        vm.exec_scopes
            .assign_or_update_variable("key", PyValueType::BigInt(bigint!(5)));
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory (n_used_accesses)
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(4)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("n_used_accesses"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        //Hint would fail is assertion fails
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Ok(())
        );
    }

    #[test]
    fn squash_dict_inner_uses_accesses_assert_wrong_used_access_number() {
        let hint_code = SQUASH_DICT_INNER_USED_ACCESSES_ASSERT.as_bytes();
        //Prepare scope variables
        let mut access_indices = HashMap::<BigInt, Vec<BigInt>>::new();
        let current_accessed_indices = vec![bigint!(9), bigint!(3), bigint!(10), bigint!(7)];
        access_indices.insert(bigint!(5), current_accessed_indices);
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        vm.exec_scopes
            .assign_or_update_variable("access_indices", PyValueType::KeyToListMap(access_indices));
        vm.exec_scopes
            .assign_or_update_variable("key", PyValueType::BigInt(bigint!(5)));
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory (n_used_accesses)
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("n_used_accesses"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Err(VirtualMachineError::NumUsedAccessesAssertFail(
                bigint!(5),
                4,
                bigint!(5)
            ))
        );
    }

    #[test]
    fn squash_dict_inner_uses_accesses_assert_used_access_number_relocatable() {
        let hint_code = SQUASH_DICT_INNER_USED_ACCESSES_ASSERT.as_bytes();
        //Prepare scope variables
        let mut access_indices = HashMap::<BigInt, Vec<BigInt>>::new();
        let current_accessed_indices = vec![bigint!(9), bigint!(3), bigint!(10), bigint!(7)];
        access_indices.insert(bigint!(5), current_accessed_indices);
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        vm.exec_scopes
            .assign_or_update_variable("access_indices", PyValueType::KeyToListMap(access_indices));
        vm.exec_scopes
            .assign_or_update_variable("key", PyValueType::BigInt(bigint!(5)));
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory (n_used_accesses)
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((0, 2)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("n_used_accesses"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn squash_dict_assert_len_keys_empty() {
        let hint_code = SQUASH_DICT_INNER_LEN_KEYS.as_bytes();
        //Prepare scope variables
        let keys = vec![];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        //Store scope variables
        vm.exec_scopes
            .assign_or_update_variable("keys", PyValueType::List(keys));
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, HashMap::new(), &ApTracking::default()),
            Ok(())
        );
    }

    #[test]
    fn squash_dict_assert_len_keys_not_empty() {
        let hint_code = SQUASH_DICT_INNER_LEN_KEYS.as_bytes();
        //Prepare scope variables
        let keys = vec![bigint!(3)];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        //Store scope variables
        vm.exec_scopes
            .assign_or_update_variable("keys", PyValueType::List(keys));
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, HashMap::new(), &ApTracking::default()),
            Err(VirtualMachineError::KeysNotEmpty)
        );
    }

    #[test]
    fn squash_dict_assert_len_keys_no_keys() {
        let hint_code = SQUASH_DICT_INNER_LEN_KEYS.as_bytes();
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, HashMap::new(), &ApTracking::default()),
            Err(VirtualMachineError::VariableNotInScopeError(String::from(
                "keys"
            )))
        );
    }

    #[test]
    fn squash_dict_inner_next_key_keys_non_empty() {
        let hint_code = SQUASH_DICT_INNER_NEXT_KEY.as_bytes();
        //Prepare scope variables
        let keys = vec![bigint!(1), bigint!(3)];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        for _ in 0..1 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        vm.exec_scopes
            .assign_or_update_variable("keys", PyValueType::List(keys));
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("next_key"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Ok(())
        );
        //Check the value of ids.next_key
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(3))))
        );
        //Check local variables
        let variables = vm.exec_scopes.get_local_variables().unwrap();
        let keys = variables.get("keys").unwrap();
        let key = variables.get("key").unwrap();
        assert_eq!(key, &PyValueType::BigInt(bigint!(3)));
        assert_eq!(keys, &PyValueType::List(vec![bigint!(1)]));
    }

    #[test]
    fn squash_dict_inner_next_key_keys_empty() {
        let hint_code = SQUASH_DICT_INNER_NEXT_KEY.as_bytes();
        //Prepare scope variables
        let keys = vec![];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        for _ in 0..1 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        vm.exec_scopes
            .assign_or_update_variable("keys", PyValueType::List(keys));
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("next_key"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Err(VirtualMachineError::EmptyKeys)
        );
    }

    #[test]
    fn squash_dict_valid_one_key_dict_no_max_size() {
        //Dict = {1: (1,1), 1: (1,2)}
        let hint_code = SQUASH_DICT.as_bytes();
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 5));
        //Insert ids into memory
        //ids.n_accesses
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //ids.n_ptr_diff
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(6)),
            )
            .unwrap();
        //Leave gaps for ids.big_keys (0,1) and ids.first_key (0,2)
        //ids.dict_accesses
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Points to the first dict_access
        //dict_accesses[0].key
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[0].prev_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[0].next_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[1].key
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[1].prev_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[1].next_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 5)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("dict_accesses"), bigint!(0));
        ids.insert(String::from("big_keys"), bigint!(1));
        ids.insert(String::from("first_key"), bigint!(2));
        ids.insert(String::from("ptr_diff"), bigint!(3));
        ids.insert(String::from("n_accesses"), bigint!(4));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                4,
                HintReference {
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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Ok(())
        );
        //Check scope variables
        let access_indices = get_access_indices(&mut vm).unwrap();
        assert_eq!(
            access_indices,
            &HashMap::from([(bigint!(1), vec![bigint!(0), bigint!(1)])])
        );
        let keys = get_list_from_scope(&vm.exec_scopes, "keys").unwrap();
        assert_eq!(keys, vec![]);
        let key = get_int_from_scope(&vm.exec_scopes, "key").unwrap();
        assert_eq!(key, bigint!(1));
        //Check ids variables
        let big_keys = vm
            .memory
            .get(&MaybeRelocatable::from((0, 1)))
            .unwrap()
            .unwrap();
        assert_eq!(big_keys, &MaybeRelocatable::from(bigint!(0)));
        let first_key = vm
            .memory
            .get(&MaybeRelocatable::from((0, 2)))
            .unwrap()
            .unwrap();
        assert_eq!(first_key, &MaybeRelocatable::from(bigint!(1)));
    }

    #[test]
    fn squash_dict_valid_two_key_dict_no_max_size() {
        //Dict = {1: (1,1), 1: (1,2), 2: (10,10), 2: (10,20)}
        let hint_code = SQUASH_DICT.as_bytes();
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 5));
        //Insert ids into memory
        //ids.n_accesses
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(bigint!(4)),
            )
            .unwrap();
        //ids.n_ptr_diff
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(6)),
            )
            .unwrap();
        //Leave gaps for ids.big_keys (0,1) and ids.first_key (0,2)
        //ids.dict_accesses
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Points to the first dict_access
        //dict_accesses[0].key
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[0].prev_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[0].next_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[1].key
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[1].prev_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[1].next_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 5)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //dict_accesses[2].key
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 6)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //dict_accesses[2].prev_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 7)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .unwrap();
        //dict_accesses[2].next_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 8)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .unwrap();
        //dict_accesses[3].key
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 9)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //dict_accesses[3].prev_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 10)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .unwrap();
        //dict_accesses[3].next_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 11)),
                &MaybeRelocatable::from(bigint!(20)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("dict_accesses"), bigint!(0));
        ids.insert(String::from("big_keys"), bigint!(1));
        ids.insert(String::from("first_key"), bigint!(2));
        ids.insert(String::from("ptr_diff"), bigint!(3));
        ids.insert(String::from("n_accesses"), bigint!(4));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                4,
                HintReference {
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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Ok(())
        );
        //Check scope variables
        let access_indices = get_access_indices(&mut vm).unwrap();
        assert_eq!(
            access_indices,
            &HashMap::from([
                (bigint!(1), vec![bigint!(0), bigint!(1)]),
                (bigint!(2), vec![bigint!(2), bigint!(3)])
            ])
        );
        let keys = get_list_from_scope(&vm.exec_scopes, "keys").unwrap();
        assert_eq!(keys, vec![bigint!(2)]);
        let key = get_int_from_scope(&vm.exec_scopes, "key").unwrap();
        assert_eq!(key, bigint!(1));
        //Check ids variables
        let big_keys = vm
            .memory
            .get(&MaybeRelocatable::from((0, 1)))
            .unwrap()
            .unwrap();
        assert_eq!(big_keys, &MaybeRelocatable::from(bigint!(0)));
        let first_key = vm
            .memory
            .get(&MaybeRelocatable::from((0, 2)))
            .unwrap()
            .unwrap();
        assert_eq!(first_key, &MaybeRelocatable::from(bigint!(1)));
    }

    #[test]
    fn squash_dict_valid_one_key_dict_with_max_size() {
        //Dict = {1: (1,1), 1: (1,2)}
        let hint_code = SQUASH_DICT.as_bytes();
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Create scope variables
        vm.exec_scopes
            .assign_or_update_variable("__squash_dict_max_size", PyValueType::BigInt(bigint!(12)));
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 5));
        //Insert ids into memory
        //ids.n_accesses
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //ids.n_ptr_diff
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(6)),
            )
            .unwrap();
        //Leave gaps for ids.big_keys (0,1) and ids.first_key (0,2)
        //ids.dict_accesses
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Points to the first dict_access
        //dict_accesses[0].key
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[0].prev_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[0].next_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[1].key
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[1].prev_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[1].next_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 5)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("dict_accesses"), bigint!(0));
        ids.insert(String::from("big_keys"), bigint!(1));
        ids.insert(String::from("first_key"), bigint!(2));
        ids.insert(String::from("ptr_diff"), bigint!(3));
        ids.insert(String::from("n_accesses"), bigint!(4));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                4,
                HintReference {
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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Ok(())
        );
        //Check scope variables
        let access_indices = get_access_indices(&mut vm).unwrap();
        assert_eq!(
            access_indices,
            &HashMap::from([(bigint!(1), vec![bigint!(0), bigint!(1)])])
        );
        let keys = get_list_from_scope(&vm.exec_scopes, "keys").unwrap();
        assert_eq!(keys, vec![]);
        let key = get_int_from_scope(&vm.exec_scopes, "key").unwrap();
        assert_eq!(key, bigint!(1));
        //Check ids variables
        let big_keys = vm
            .memory
            .get(&MaybeRelocatable::from((0, 1)))
            .unwrap()
            .unwrap();
        assert_eq!(big_keys, &MaybeRelocatable::from(bigint!(0)));
        let first_key = vm
            .memory
            .get(&MaybeRelocatable::from((0, 2)))
            .unwrap()
            .unwrap();
        assert_eq!(first_key, &MaybeRelocatable::from(bigint!(1)));
    }

    #[test]
    fn squash_dict_invalid_one_key_dict_with_max_size_exceeded() {
        //Dict = {1: (1,1), 1: (1,2)}
        let hint_code = SQUASH_DICT.as_bytes();
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Create scope variables
        vm.exec_scopes
            .assign_or_update_variable("__squash_dict_max_size", PyValueType::BigInt(bigint!(1)));
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 5));
        //Insert ids into memory
        //ids.n_accesses
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //ids.n_ptr_diff
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(6)),
            )
            .unwrap();
        //Leave gaps for ids.big_keys (0,1) and ids.first_key (0,2)
        //ids.dict_accesses
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Points to the first dict_access
        //dict_accesses[0].key
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[0].prev_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[0].next_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[1].key
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[1].prev_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[1].next_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 5)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("dict_accesses"), bigint!(0));
        ids.insert(String::from("big_keys"), bigint!(1));
        ids.insert(String::from("first_key"), bigint!(2));
        ids.insert(String::from("ptr_diff"), bigint!(3));
        ids.insert(String::from("n_accesses"), bigint!(4));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                4,
                HintReference {
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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Err(VirtualMachineError::SquashDictMaxSizeExceeded(
                bigint!(1),
                bigint!(2)
            ))
        );
    }

    #[test]
    fn squash_dict_invalid_one_key_dict_bad_ptr_diff() {
        //Dict = {1: (1,1), 1: (1,2)}
        let hint_code = SQUASH_DICT.as_bytes();
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 5));
        //Insert ids into memory
        //ids.n_accesses
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //ids.n_ptr_diff
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(7)),
            )
            .unwrap();
        //Leave gaps for ids.big_keys (0,1) and ids.first_key (0,2)
        //ids.dict_accesses
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Points to the first dict_access
        //dict_accesses[0].key
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[0].prev_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[0].next_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[1].key
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[1].prev_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[1].next_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 5)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("dict_accesses"), bigint!(0));
        ids.insert(String::from("big_keys"), bigint!(1));
        ids.insert(String::from("first_key"), bigint!(2));
        ids.insert(String::from("ptr_diff"), bigint!(3));
        ids.insert(String::from("n_accesses"), bigint!(4));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                4,
                HintReference {
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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Err(VirtualMachineError::PtrDiffNotDivisibleByDictAccessSize)
        );
    }
    #[test]
    fn squash_dict_invalid_one_key_dict_with_n_access_too_big() {
        //Dict = {1: (1,1), 1: (1,2)}
        let hint_code = SQUASH_DICT.as_bytes();
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 5));
        //Insert ids into memory
        //ids.n_accesses
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(BigInt::new(
                    Sign::Plus,
                    vec![1, 0, 0, 0, 0, 0, 17, 134217728],
                )),
            )
            .unwrap();
        //ids.n_ptr_diff
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(6)),
            )
            .unwrap();
        //Leave gaps for ids.big_keys (0,1) and ids.first_key (0,2)
        //ids.dict_accesses
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Points to the first dict_access
        //dict_accesses[0].key
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[0].prev_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[0].next_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[1].key
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[1].prev_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[1].next_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 5)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("dict_accesses"), bigint!(0));
        ids.insert(String::from("big_keys"), bigint!(1));
        ids.insert(String::from("first_key"), bigint!(2));
        ids.insert(String::from("ptr_diff"), bigint!(3));
        ids.insert(String::from("n_accesses"), bigint!(4));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                4,
                HintReference {
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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Err(VirtualMachineError::NAccessesTooBig(BigInt::new(
                Sign::Plus,
                vec![1, 0, 0, 0, 0, 0, 17, 134217728]
            ),))
        );
    }

    #[test]
    fn squash_dict_valid_one_key_dict_no_max_size_big_keys() {
        //Dict = {(prime - 1): (1,1), (prime - 1): (1,2)}
        let hint_code = SQUASH_DICT.as_bytes();
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 5));
        //Insert ids into memory
        //ids.n_accesses
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //ids.n_ptr_diff
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(6)),
            )
            .unwrap();
        //Leave gaps for ids.big_keys (0,1) and ids.first_key (0,2)
        //ids.dict_accesses
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Points to the first dict_access
        //dict_accesses[0].key
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(BigInt::new(
                    Sign::Plus,
                    vec![1, 0, 0, 0, 0, 0, 17, 134217727],
                )),
            )
            .unwrap();
        //dict_accesses[0].prev_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[0].next_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[1].key
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from(BigInt::new(
                    Sign::Plus,
                    vec![1, 0, 0, 0, 0, 0, 17, 134217727],
                )),
            )
            .unwrap();
        //dict_accesses[1].prev_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //dict_accesses[1].next_value
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 5)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("dict_accesses"), bigint!(0));
        ids.insert(String::from("big_keys"), bigint!(1));
        ids.insert(String::from("first_key"), bigint!(2));
        ids.insert(String::from("ptr_diff"), bigint!(3));
        ids.insert(String::from("n_accesses"), bigint!(4));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                4,
                HintReference {
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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Ok(())
        );
        //Check scope variables
        let access_indices = get_access_indices(&mut vm).unwrap();
        assert_eq!(
            access_indices,
            &HashMap::from([(
                BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217727]),
                vec![bigint!(0), bigint!(1)]
            )])
        );
        let keys = get_list_from_scope(&vm.exec_scopes, "keys").unwrap();
        assert_eq!(keys, vec![]);
        let key = get_int_from_scope(&vm.exec_scopes, "key").unwrap();
        assert_eq!(
            key,
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217727])
        );
        //Check ids variables
        let big_keys = vm
            .memory
            .get(&MaybeRelocatable::from((0, 1)))
            .unwrap()
            .unwrap();
        assert_eq!(big_keys, &MaybeRelocatable::from(bigint!(1)));
        let first_key = vm
            .memory
            .get(&MaybeRelocatable::from((0, 2)))
            .unwrap()
            .unwrap();
        assert_eq!(
            first_key,
            &MaybeRelocatable::from(BigInt::new(
                Sign::Plus,
                vec![1, 0, 0, 0, 0, 0, 17, 134217727]
            ))
        );
    }
}
