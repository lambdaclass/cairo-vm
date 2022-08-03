use std::collections::HashMap;

use num_bigint::BigInt;
use num_traits::ToPrimitive;

use crate::{
    bigint,
    serde::deserialize_program::ApTracking,
    types::{exec_scope::PyValueType, relocatable::MaybeRelocatable},
    vm::{errors::vm_errors::VirtualMachineError, vm_core::VirtualMachine},
};

use super::{
    dict_hint_utils::DICT_ACCESS_SIZE,
    hint_utils::{
        get_address_from_var_name, get_int_from_scope, get_list_from_scope, get_range_check_builtin,
    },
};

fn get_access_indices(vm: &mut VirtualMachine) -> Option<HashMap<BigInt, Vec<BigInt>>> {
    let mut access_indices: Option<HashMap<BigInt, Vec<BigInt>>> = None;
    if let Some(variables) = vm.exec_scopes.get_local_variables() {
        if let Some(PyValueType::KeyToListMap(py_access_indices)) = variables.get("access_indices")
        {
            access_indices = Some(py_access_indices.clone());
        }
    }
    access_indices
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
    let access_indices = get_access_indices(vm)
        .ok_or_else(|| VirtualMachineError::NoLocalVariable(String::from("access_indices")))?;
    let key = get_int_from_scope(vm, "key")
        .ok_or_else(|| VirtualMachineError::NoLocalVariable(String::from("key")))?;
    //Get addr for ids variables
    let range_check_ptr_addr =
        get_address_from_var_name("range_check_ptr", ids, vm, hint_ap_tracking)?;
    //Get ids from memory
    let range_check_ptr = vm
        .memory
        .get(&range_check_ptr_addr)
        .map_err(VirtualMachineError::MemoryError)?
        .ok_or(VirtualMachineError::MemoryGet(range_check_ptr_addr))?;
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
    vm.exec_scopes.assign_or_update_variable(
        "current_access_indices",
        PyValueType::List(current_access_indices),
    );
    vm.exec_scopes.assign_or_update_variable(
        "current_access_index",
        PyValueType::BigInt(first_val.clone()),
    );
    //Insert current_accesss_index into range_check_ptr
    let range_check_ptr_copy = range_check_ptr.clone();
    vm.memory
        .insert(&range_check_ptr_copy, &MaybeRelocatable::from(first_val))
        .map_err(VirtualMachineError::MemoryError)
}

// Implements Hint: ids.should_skip_loop = 0 if current_access_indices else 1
pub fn squash_dict_inner_skip_loop(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    //Check that current_access_indices is in scope
    let current_access_indices =
        get_list_from_scope(vm, "current_access_indices").ok_or_else(|| {
            VirtualMachineError::NoLocalVariable(String::from("current_access_indices"))
        })?;
    //Get addr for ids variables
    let should_skip_loop_addr =
        get_address_from_var_name("should_skip_loop", ids, vm, hint_ap_tracking)?;
    //Main Logic
    let should_skip_loop = if current_access_indices.is_empty() {
        bigint!(1)
    } else {
        bigint!(0)
    };
    vm.memory
        .insert(
            &should_skip_loop_addr,
            &MaybeRelocatable::from(should_skip_loop),
        )
        .map_err(VirtualMachineError::MemoryError)
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
    let mut current_access_indices =
        get_list_from_scope(vm, "current_access_indices").ok_or_else(|| {
            VirtualMachineError::NoLocalVariable(String::from("current_access_indices"))
        })?;
    let current_access_index = get_int_from_scope(vm, "current_access_index").ok_or_else(|| {
        VirtualMachineError::NoLocalVariable(String::from("current_access_index"))
    })?;
    //Get addr for ids variables
    let loop_temps_addr = get_address_from_var_name("loop_temps", ids, vm, hint_ap_tracking)?;
    //Main Logic
    let new_access_index = current_access_indices
        .pop()
        .ok_or(VirtualMachineError::EmptyCurrentAccessIndices)?;
    vm.exec_scopes.assign_or_update_variable(
        "new_access_index",
        PyValueType::BigInt(new_access_index.clone()),
    );
    vm.exec_scopes.assign_or_update_variable(
        "current_access_indices",
        PyValueType::List(current_access_indices),
    );
    let index_delta_minus1 = new_access_index.clone() - current_access_index - bigint!(1);
    //loop_temps.delta_minus1 = loop_temps + 0 as it is the first field of the struct
    //Insert loop_temps.delta_minus1 into memory
    vm.memory
        .insert(
            &loop_temps_addr,
            &MaybeRelocatable::from(index_delta_minus1),
        )
        .map_err(VirtualMachineError::MemoryError)?;
    vm.exec_scopes.assign_or_update_variable(
        "current_access_index",
        PyValueType::BigInt(new_access_index),
    );
    Ok(())
}

// Implements Hint: ids.loop_temps.should_continue = 1 if current_access_indices else 0
pub fn squash_dict_inner_continue_loop(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    //Check that current_access_indices is in scope
    let current_access_indices =
        get_list_from_scope(vm, "current_access_indices").ok_or_else(|| {
            VirtualMachineError::NoLocalVariable(String::from("current_access_indices"))
        })?;
    //Check that ids contains the reference id for each variable used by the hint
    //Get addr for ids variables
    let loop_temps_addr = get_address_from_var_name("loop_temps", ids, vm, hint_ap_tracking)?;
    //Main Logic
    let should_continue = if current_access_indices.is_empty() {
        bigint!(0)
    } else {
        bigint!(1)
    };
    //loop_temps.delta_minus1 = loop_temps + 3 as it is the fourth field of the struct
    //Insert loop_temps.delta_minus1 into memory
    let should_continue_addr = loop_temps_addr.add_usize_mod(3, None);
    vm.memory
        .insert(
            &should_continue_addr,
            &MaybeRelocatable::from(should_continue),
        )
        .map_err(VirtualMachineError::MemoryError)
}

// Implements Hint: assert len(current_access_indices) == 0
pub fn squash_dict_inner_len_assert(vm: &mut VirtualMachine) -> Result<(), VirtualMachineError> {
    //Check that current_access_indices is in scope
    let current_access_indices =
        get_list_from_scope(vm, "current_access_indices").ok_or_else(|| {
            VirtualMachineError::NoLocalVariable(String::from("current_access_indices"))
        })?;
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
    //Check that access_indices and key are in scope
    let access_indices = get_access_indices(vm)
        .ok_or_else(|| VirtualMachineError::NoLocalVariable(String::from("access_indices")))?;
    let key = get_int_from_scope(vm, "key")
        .ok_or_else(|| VirtualMachineError::NoLocalVariable(String::from("key")))?;
    //Get addr for ids variables
    let n_used_accesses_addr =
        get_address_from_var_name("n_used_accesses", ids, vm, hint_ap_tracking)?;
    //Get n_used_accesses from memory
    let maybe_rel_n_used_accesses = vm
        .memory
        .get(&n_used_accesses_addr)
        .map_err(VirtualMachineError::MemoryError)?
        .ok_or_else(|| VirtualMachineError::MemoryGet(n_used_accesses_addr.clone()))?;
    //Check that n_used_accesses is an int value
    let n_used_accesses = if let MaybeRelocatable::Int(n_used_accesses) = maybe_rel_n_used_accesses
    {
        n_used_accesses
    } else {
        return Err(VirtualMachineError::ExpectedInteger(n_used_accesses_addr));
    };
    //Main Logic
    let access_indices_at_key = access_indices
        .get(&key)
        .ok_or_else(|| VirtualMachineError::NoKeyInAccessIndices(key.clone()))?;

    if *n_used_accesses != bigint!(access_indices_at_key.len()) {
        return Err(VirtualMachineError::NumUsedAccessesAssertFail(
            n_used_accesses.clone(),
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
    let keys = get_list_from_scope(vm, "keys")
        .ok_or_else(|| VirtualMachineError::NoLocalVariable(String::from("keys")))?;
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
    let mut keys = get_list_from_scope(vm, "keys")
        .ok_or_else(|| VirtualMachineError::NoLocalVariable(String::from("keys")))?;
    //Get addr for ids variables
    let next_key_addr = get_address_from_var_name("next_key", ids, vm, hint_ap_tracking)?;
    let next_key = keys.pop().ok_or(VirtualMachineError::EmptyKeys)?;
    //Insert next_key into ids.next_keys
    vm.memory
        .insert(&next_key_addr, &MaybeRelocatable::from(next_key.clone()))
        .map_err(VirtualMachineError::MemoryError)?;
    //Update local variables
    vm.exec_scopes
        .assign_or_update_variable("keys", PyValueType::List(keys));
    vm.exec_scopes
        .assign_or_update_variable("key", PyValueType::BigInt(next_key));
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
    let dict_accesses_addr = get_address_from_var_name("dict_accesses", ids, vm, hint_ap_tracking)?;
    let ptr_diff_addr = get_address_from_var_name("ptr_diff", ids, vm, hint_ap_tracking)?;
    let n_accesses_addr = get_address_from_var_name("n_accesses", ids, vm, hint_ap_tracking)?;
    let big_keys_addr = get_address_from_var_name("big_keys", ids, vm, hint_ap_tracking)?;
    let first_key_addr = get_address_from_var_name("first_key", ids, vm, hint_ap_tracking)?;
    //Get ids variables from memory
    let ptr_diff = if let MaybeRelocatable::Int(ptr_diff) = vm
        .memory
        .get(&ptr_diff_addr)
        .map_err(VirtualMachineError::MemoryError)?
        .ok_or_else(|| VirtualMachineError::MemoryGet(ptr_diff_addr.clone()))?
    {
        ptr_diff
    } else {
        return Err(VirtualMachineError::ExpectedInteger(ptr_diff_addr));
    };
    let n_accesses = if let MaybeRelocatable::Int(n_accesses) = vm
        .memory
        .get(&n_accesses_addr)
        .map_err(VirtualMachineError::MemoryError)?
        .ok_or_else(|| VirtualMachineError::MemoryGet(n_accesses_addr.clone()))?
    {
        n_accesses.clone()
    } else {
        return Err(VirtualMachineError::ExpectedInteger(n_accesses_addr));
    };
    let address = vm
        .memory
        .get(&dict_accesses_addr)
        .map_err(VirtualMachineError::MemoryError)?
        .ok_or_else(|| VirtualMachineError::MemoryGet(n_accesses_addr.clone()))?
        .clone();
    //Get range_check_builtin
    let range_check_builtin = get_range_check_builtin(vm)?;
    let range_check_bound = range_check_builtin._bound.clone();
    //Main Logic
    if ptr_diff % DICT_ACCESS_SIZE != bigint!(0) {
        return Err(VirtualMachineError::PtrDiffNotDivisibleByDictAccessSize);
    }
    let squash_dict_max_size = get_int_from_scope(vm, "__squash_dict_max_size");
    if let Some(max_size) = squash_dict_max_size {
        if n_accesses > max_size {
            return Err(VirtualMachineError::SquashDictMaxSizeExceeded(
                max_size, n_accesses,
            ));
        };
    };
    let n_accesses_usize = n_accesses
        .to_usize()
        .ok_or(VirtualMachineError::NAccessesTooBig(n_accesses))?;
    //A map from key to the list of indices accessing it.
    let mut access_indices = HashMap::<BigInt, Vec<BigInt>>::new();
    for i in 0..n_accesses_usize {
        let key_addr = address.add_int_mod(&(DICT_ACCESS_SIZE * bigint!(i)), &vm.prime)?;
        let key = if let MaybeRelocatable::Int(key) = vm
            .memory
            .get(&key_addr)
            .map_err(VirtualMachineError::MemoryError)?
            .ok_or_else(|| VirtualMachineError::MemoryGet(key_addr.clone()))?
        {
            key
        } else {
            return Err(VirtualMachineError::ExpectedInteger(key_addr));
        };
        access_indices
            .entry(key.clone())
            .or_insert(vec![])
            .push(bigint!(i));
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
    vm.memory
        .insert(&big_keys_addr, &MaybeRelocatable::from(big_keys))
        .map_err(VirtualMachineError::MemoryError)?;
    let key = keys.pop().ok_or(VirtualMachineError::EmptyKeys)?;
    vm.memory
        .insert(&first_key_addr, &MaybeRelocatable::from(key.clone()))
        .map_err(VirtualMachineError::MemoryError)?;
    //Insert local variables into scope
    vm.exec_scopes
        .assign_or_update_variable("access_indices", PyValueType::KeyToListMap(access_indices));
    vm.exec_scopes
        .assign_or_update_variable("keys", PyValueType::List(keys));
    vm.exec_scopes
        .assign_or_update_variable("key", PyValueType::BigInt(key));
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::bigint;
    use crate::serde::deserialize_program::ApTracking;
    use crate::types::exec_scope::PyValueType;
    use crate::types::instruction::Register;
    use crate::vm::hints::{
        execute_hint::{BuiltinHintExecutor, HintReference},
        hint_code,
    };
    use crate::vm::runners::builtin_runner::RangeCheckBuiltinRunner;
    use num_bigint::Sign;

    use super::*;

    static HINT_EXECUTOR: BuiltinHintExecutor = BuiltinHintExecutor {};

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
        let hint_code = SQUASH_DICT_INNER_FIRST_ITERATION;
        //Prepare scope variables
        let mut access_indices = HashMap::<BigInt, Vec<BigInt>>::new();
        let current_accessed_indices = vec![bigint!(9), bigint!(3), bigint!(10), bigint!(7)];
        access_indices.insert(bigint!(5), current_accessed_indices);
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
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
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
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
        let hint_code = SQUASH_DICT_INNER_FIRST_ITERATION;
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
            &HINT_EXECUTOR,
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
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
            Err(VirtualMachineError::EmptyCurrentAccessIndices)
        );
    }

    #[test]
    fn squash_dict_inner_first_iteration_no_local_variables() {
        let hint_code = SQUASH_DICT_INNER_FIRST_ITERATION;
        //No scope variables
        //Create vm
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
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
            Err(VirtualMachineError::NoLocalVariable(String::from(
                "access_indices"
            )))
        );
    }

    #[test]
    fn should_skip_loop_valid_empty_current_access_indices() {
        let hint_code = SQUASH_DICT_INNER_SKIP_LOOP;
        //Prepare scope variables
        let current_access_indices = vec![];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
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
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
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
        let hint_code = SQUASH_DICT_INNER_SKIP_LOOP;
        //Prepare scope variables
        let current_access_indices = vec![bigint!(4), bigint!(7)];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
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
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
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
        let hint_code = SQUASH_DICT_INNER_CHECK_ACCESS_INDEX;
        //Prepare scope variables
        let current_access_indices = vec![bigint!(10), bigint!(9), bigint!(7), bigint!(5)];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
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
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
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
        let hint_code = SQUASH_DICT_INNER_CHECK_ACCESS_INDEX;
        //Prepare scope variables
        let current_access_indices = vec![];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
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
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
            Err(VirtualMachineError::EmptyCurrentAccessIndices)
        );
    }

    #[test]
    fn should_continue_loop_valid_non_empty_current_access_indices() {
        let hint_code = SQUASH_DICT_INNER_CONTINUE_LOOP;
        //Prepare scope variables
        let current_access_indices = vec![bigint!(4), bigint!(7)];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
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
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
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
        let hint_code = SQUASH_DICT_INNER_CONTINUE_LOOP;
        //Prepare scope variables
        let current_access_indices = vec![];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
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
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
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
        let hint_code = SQUASH_DICT_INNER_ASSERT_LEN;
        //Prepare scope variables
        let current_access_indices = vec![];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        //Store scope variables
        vm.exec_scopes.assign_or_update_variable(
            "current_access_indices",
            PyValueType::List(current_access_indices),
        );
        //Execute the hint
        //Hint should produce an error if assertion fails
        assert_eq!(
            vm.hint_executor.execute_hint(
                &mut vm,
                hint_code,
                &HashMap::new(),
                &ApTracking::default()
            ),
            Ok(())
        );
    }

    #[test]
    fn assert_current_indices_len_is_empty_not() {
        let hint_code = SQUASH_DICT_INNER_ASSERT_LEN;
        //Prepare scope variables
        let current_access_indices = vec![bigint!(29)];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        //Store scope variables
        vm.exec_scopes.assign_or_update_variable(
            "current_access_indices",
            PyValueType::List(current_access_indices),
        );
        //Execute the hint
        //Hint should produce an error if assertion fails
        assert_eq!(
            vm.hint_executor.execute_hint(
                &mut vm,
                hint_code,
                &HashMap::new(),
                &ApTracking::default()
            ),
            Err(VirtualMachineError::CurrentAccessIndicesNotEmpty)
        );
    }

    #[test]
    fn squash_dict_inner_uses_accesses_assert_valid() {
        let hint_code = SQUASH_DICT_INNER_USED_ACCESSES_ASSERT;
        //Prepare scope variables
        let mut access_indices = HashMap::<BigInt, Vec<BigInt>>::new();
        let current_accessed_indices = vec![bigint!(9), bigint!(3), bigint!(10), bigint!(7)];
        access_indices.insert(bigint!(5), current_accessed_indices);
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
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
        //Hint would fail is assertion fails
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
            Ok(())
        );
    }

    #[test]
    fn squash_dict_inner_uses_accesses_assert_wrong_used_access_number() {
        let hint_code = SQUASH_DICT_INNER_USED_ACCESSES_ASSERT;
        //Prepare scope variables
        let mut access_indices = HashMap::<BigInt, Vec<BigInt>>::new();
        let current_accessed_indices = vec![bigint!(9), bigint!(3), bigint!(10), bigint!(7)];
        access_indices.insert(bigint!(5), current_accessed_indices);
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
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
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
            Err(VirtualMachineError::NumUsedAccessesAssertFail(
                bigint!(5),
                4,
                bigint!(5)
            ))
        );
    }

    #[test]
    fn squash_dict_inner_uses_accesses_assert_used_access_number_relocatable() {
        let hint_code = SQUASH_DICT_INNER_USED_ACCESSES_ASSERT;
        //Prepare scope variables
        let mut access_indices = HashMap::<BigInt, Vec<BigInt>>::new();
        let current_accessed_indices = vec![bigint!(9), bigint!(3), bigint!(10), bigint!(7)];
        access_indices.insert(bigint!(5), current_accessed_indices);
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
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
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn squash_dict_assert_len_keys_empty() {
        let hint_code = SQUASH_DICT_INNER_LEN_KEYS;
        //Prepare scope variables
        let keys = vec![];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        //Store scope variables
        vm.exec_scopes
            .assign_or_update_variable("keys", PyValueType::List(keys));
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
    }

    #[test]
    fn squash_dict_assert_len_keys_not_empty() {
        let hint_code = SQUASH_DICT_INNER_LEN_KEYS;
        //Prepare scope variables
        let keys = vec![bigint!(3)];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );
        //Store scope variables
        vm.exec_scopes
            .assign_or_update_variable("keys", PyValueType::List(keys));
        //Execute the hint
        assert_eq!(
            vm.hint_executor.execute_hint(
                &mut vm,
                hint_code,
                &HashMap::new(),
                &ApTracking::default()
            ),
            Err(VirtualMachineError::KeysNotEmpty)
        );
    }

    #[test]
    fn squash_dict_assert_len_keys_no_keys() {
        let hint_code = SQUASH_DICT_INNER_LEN_KEYS;
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
            Err(VirtualMachineError::NoLocalVariable(String::from("keys")))
        );
    }

    #[test]
    fn squash_dict_inner_next_key_keys_non_empty() {
        let hint_code = SQUASH_DICT_INNER_NEXT_KEY;
        //Prepare scope variables
        let keys = vec![bigint!(1), bigint!(3)];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
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
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
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
        let hint_code = SQUASH_DICT_INNER_NEXT_KEY;
        //Prepare scope variables
        let keys = vec![];
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
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
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
            Err(VirtualMachineError::EmptyKeys)
        );
    }

    #[test]
    fn squash_dict_valid_one_key_dict_no_max_size() {
        //Dict = {1: (1,1), 1: (1,2)}
        let hint_code = SQUASH_DICT;
        //Create vm
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
                1,
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
                2,
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
                3,
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
                4,
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
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
            Ok(())
        );
        //Check scope variables
        let access_indices = get_access_indices(&mut vm).unwrap();
        assert_eq!(
            access_indices,
            HashMap::from([(bigint!(1), vec![bigint!(0), bigint!(1)])])
        );
        let keys = get_list_from_scope(&mut vm, "keys").unwrap();
        assert_eq!(keys, vec![]);
        let key = get_int_from_scope(&mut vm, "key").unwrap();
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
        let hint_code = SQUASH_DICT;
        assert_eq!(SQUASH_DICT, hint_code::SQUASH_DICT);
        //Create vm
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
                1,
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
                2,
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
                3,
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
                4,
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
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
            Ok(())
        );
        //Check scope variables
        let access_indices = get_access_indices(&mut vm).unwrap();
        assert_eq!(
            access_indices,
            HashMap::from([
                (bigint!(1), vec![bigint!(0), bigint!(1)]),
                (bigint!(2), vec![bigint!(2), bigint!(3)])
            ])
        );
        let keys = get_list_from_scope(&mut vm, "keys").unwrap();
        assert_eq!(keys, vec![bigint!(2)]);
        let key = get_int_from_scope(&mut vm, "key").unwrap();
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
        let hint_code = SQUASH_DICT;
        //Create vm
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
                1,
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
                2,
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
                3,
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
                4,
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
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
            Ok(())
        );
        //Check scope variables
        let access_indices = get_access_indices(&mut vm).unwrap();
        assert_eq!(
            access_indices,
            HashMap::from([(bigint!(1), vec![bigint!(0), bigint!(1)])])
        );
        let keys = get_list_from_scope(&mut vm, "keys").unwrap();
        assert_eq!(keys, vec![]);
        let key = get_int_from_scope(&mut vm, "key").unwrap();
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
        let hint_code = SQUASH_DICT;
        //Create vm
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
                1,
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
                2,
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
                3,
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
                4,
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
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
            Err(VirtualMachineError::SquashDictMaxSizeExceeded(
                bigint!(1),
                bigint!(2)
            ))
        );
    }

    #[test]
    fn squash_dict_invalid_one_key_dict_bad_ptr_diff() {
        //Dict = {1: (1,1), 1: (1,2)}
        let hint_code = SQUASH_DICT;
        //Create vm
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
                1,
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
                2,
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
                3,
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
                4,
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
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
            Err(VirtualMachineError::PtrDiffNotDivisibleByDictAccessSize)
        );
    }
    #[test]
    fn squash_dict_invalid_one_key_dict_with_n_access_too_big() {
        //Dict = {1: (1,1), 1: (1,2)}
        let hint_code = SQUASH_DICT;
        //Create vm
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
                1,
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
                2,
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
                3,
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
                4,
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
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
            Err(VirtualMachineError::NAccessesTooBig(BigInt::new(
                Sign::Plus,
                vec![1, 0, 0, 0, 0, 0, 17, 134217728]
            ),))
        );
    }

    #[test]
    fn squash_dict_valid_one_key_dict_no_max_size_big_keys() {
        //Dict = {(prime - 1): (1,1), (prime - 1): (1,2)}
        let hint_code = SQUASH_DICT;
        //Create vm
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
                1,
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
                2,
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
                3,
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
                4,
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
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::default()),
            Ok(())
        );
        //Check scope variables
        let access_indices = get_access_indices(&mut vm).unwrap();
        assert_eq!(
            access_indices,
            HashMap::from([(
                BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217727]),
                vec![bigint!(0), bigint!(1)]
            )])
        );
        let keys = get_list_from_scope(&mut vm, "keys").unwrap();
        assert_eq!(keys, vec![]);
        let key = get_int_from_scope(&mut vm, "key").unwrap();
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
