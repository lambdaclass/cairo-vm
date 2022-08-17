use num_bigint::BigInt;
use num_traits::ToPrimitive;
use std::collections::HashMap;

use crate::{
    bigint,
    serde::deserialize_program::ApTracking,
    types::{exec_scope::ExecutionScopesProxy, relocatable::MaybeRelocatable},
    vm::{errors::vm_errors::VirtualMachineError, vm_core::VMProxy},
};

use super::{
    dict_hint_utils::DICT_ACCESS_SIZE,
    execute_hint::HintReference,
    hint_utils::{
        get_integer_from_var_name, get_ptr_from_var_name, get_range_check_builtin,
        get_relocatable_from_var_name, insert_value_from_var_name,
    },
};

fn get_access_indices<'a>(
    exec_scopes_proxy: &'a mut ExecutionScopesProxy,
) -> Result<&'a HashMap<BigInt, Vec<BigInt>>, VirtualMachineError> {
    let mut access_indices: Option<&HashMap<BigInt, Vec<BigInt>>> = None;
    if let Some(variable) = exec_scopes_proxy
        .get_local_variables_mut()?
        .get_mut("access_indices")
    {
        if let Some(py_access_indices) = variable.downcast_mut::<HashMap<BigInt, Vec<BigInt>>>() {
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
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    //Check that access_indices and key are in scope
    let key = exec_scopes_proxy.get_int("key")?;
    let range_check_ptr =
        get_ptr_from_var_name("range_check_ptr", &vm_proxy, ids_data, ap_tracking)?;
    let access_indices = get_access_indices(exec_scopes_proxy)?;
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
    exec_scopes_proxy.insert_value("current_access_indices", current_access_indices);
    exec_scopes_proxy.insert_value("current_access_index", first_val.clone());
    //Insert current_accesss_index into range_check_ptr
    vm_proxy.memory.insert_value(&range_check_ptr, first_val)
}

// Implements Hint: ids.should_skip_loop = 0 if current_access_indices else 1
pub fn squash_dict_inner_skip_loop(
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    //Check that current_access_indices is in scope
    let current_access_indices = exec_scopes_proxy.get_list("current_access_indices")?;
    //Main Logic
    let should_skip_loop = if current_access_indices.is_empty() {
        bigint!(1)
    } else {
        bigint!(0)
    };
    insert_value_from_var_name(
        "should_skip_loop",
        should_skip_loop,
        vm_proxy,
        ids_data,
        ap_tracking,
    )
}

/*Implements Hint:
   new_access_index = current_access_indices.pop()
   ids.loop_temps.index_delta_minus1 = new_access_index - current_access_index - 1
   current_access_index = new_access_index
*/
pub fn squash_dict_inner_check_access_index(
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    //Check that current_access_indices and current_access_index are in scope
    let current_access_index = exec_scopes_proxy.get_int("current_access_index")?;
    let current_access_indices = exec_scopes_proxy.get_mut_list_ref("current_access_indices")?;
    //Main Logic
    let new_access_index = current_access_indices
        .pop()
        .ok_or(VirtualMachineError::EmptyCurrentAccessIndices)?;
    let index_delta_minus1 = new_access_index.clone() - current_access_index - bigint!(1);
    //loop_temps.delta_minus1 = loop_temps + 0 as it is the first field of the struct
    //Insert loop_temps.delta_minus1 into memory
    insert_value_from_var_name(
        "loop_temps",
        index_delta_minus1,
        vm_proxy,
        ids_data,
        ap_tracking,
    )?;
    exec_scopes_proxy.insert_value("new_access_index", new_access_index.clone());
    exec_scopes_proxy.insert_value("current_access_index", new_access_index);
    Ok(())
}

// Implements Hint: ids.loop_temps.should_continue = 1 if current_access_indices else 0
pub fn squash_dict_inner_continue_loop(
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    //Check that ids contains the reference id for each variable used by the hint
    //Get addr for ids variables
    let loop_temps_addr =
        get_relocatable_from_var_name("loop_temps", &vm_proxy, ids_data, ap_tracking)?;
    //Check that current_access_indices is in scope
    let current_access_indices = exec_scopes_proxy.get_list_ref("current_access_indices")?;
    //Main Logic
    let should_continue = if current_access_indices.is_empty() {
        bigint!(0)
    } else {
        bigint!(1)
    };
    //loop_temps.delta_minus1 = loop_temps + 3 as it is the fourth field of the struct
    //Insert loop_temps.delta_minus1 into memory
    let should_continue_addr = loop_temps_addr + 3;
    vm_proxy
        .memory
        .insert_value(&should_continue_addr, should_continue)
}

// Implements Hint: assert len(current_access_indices) == 0
pub fn squash_dict_inner_len_assert(
    exec_scopes_proxy: &mut ExecutionScopesProxy,
) -> Result<(), VirtualMachineError> {
    //Check that current_access_indices is in scope
    let current_access_indices = exec_scopes_proxy.get_list_ref("current_access_indices")?;
    if !current_access_indices.is_empty() {
        return Err(VirtualMachineError::CurrentAccessIndicesNotEmpty);
    }
    Ok(())
}

//Implements hint: assert ids.n_used_accesses == len(access_indices[key]
pub fn squash_dict_inner_used_accesses_assert(
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let key = exec_scopes_proxy.get_int("key")?;
    let n_used_accesses =
        get_integer_from_var_name("n_used_accesses", &vm_proxy, ids_data, ap_tracking)?;
    let access_indices = get_access_indices(exec_scopes_proxy)?;
    //Main Logic
    let access_indices_at_key = access_indices
        .get(&key)
        .ok_or_else(|| VirtualMachineError::NoKeyInAccessIndices(key.clone()))?;

    if n_used_accesses != &bigint!(access_indices_at_key.len()) {
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
    exec_scopes_proxy: &mut ExecutionScopesProxy,
) -> Result<(), VirtualMachineError> {
    //Check that current_access_indices is in scope
    let keys = exec_scopes_proxy.get_list_ref("keys")?;
    if !keys.is_empty() {
        return Err(VirtualMachineError::KeysNotEmpty);
    };
    Ok(())
}

// Implements Hint:
//  assert len(keys) > 0, 'No keys left but remaining_accesses > 0.'
//  ids.next_key = key = keys.pop()
pub fn squash_dict_inner_next_key(
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    //Check that current_access_indices is in scope
    let keys = exec_scopes_proxy.get_mut_list_ref("keys")?;
    let next_key = keys.pop().ok_or(VirtualMachineError::EmptyKeys)?;
    //Insert next_key into ids.next_keys
    insert_value_from_var_name(
        "next_key",
        next_key.clone(),
        vm_proxy,
        ids_data,
        ap_tracking,
    )?;
    //Update local variables
    exec_scopes_proxy.insert_value("key", next_key);
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
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    //Get necessary variables addresses from ids
    let address = get_ptr_from_var_name("dict_accesses", &vm_proxy, ids_data, ap_tracking)?;
    let ptr_diff = get_integer_from_var_name("ptr_diff", &vm_proxy, ids_data, ap_tracking)?;
    let n_accesses = get_integer_from_var_name("n_accesses", &vm_proxy, ids_data, ap_tracking)?;
    //Get range_check_builtin
    let range_check_builtin = get_range_check_builtin(vm_proxy.builtin_runners)?;
    let range_check_bound = range_check_builtin._bound.clone();
    //Main Logic
    if ptr_diff % DICT_ACCESS_SIZE != bigint!(0) {
        return Err(VirtualMachineError::PtrDiffNotDivisibleByDictAccessSize);
    }
    let squash_dict_max_size = exec_scopes_proxy.get_int("__squash_dict_max_size");
    if let Ok(max_size) = squash_dict_max_size {
        if n_accesses > &max_size {
            return Err(VirtualMachineError::SquashDictMaxSizeExceeded(
                max_size,
                n_accesses.clone(),
            ));
        };
    };
    let n_accesses_usize = n_accesses
        .to_usize()
        .ok_or_else(|| VirtualMachineError::NAccessesTooBig(n_accesses.clone()))?;
    //A map from key to the list of indices accessing it.
    let mut access_indices = HashMap::<BigInt, Vec<BigInt>>::new();
    for i in 0..n_accesses_usize {
        let key_addr = &address + DICT_ACCESS_SIZE * i;
        let key = vm_proxy
            .memory
            .get_integer(&key_addr)
            .map_err(|_| VirtualMachineError::ExpectedInteger(MaybeRelocatable::from(key_addr)))?;
        access_indices
            .entry(key.clone())
            .or_insert(Vec::<BigInt>::new())
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
    insert_value_from_var_name("big_keys", big_keys, vm_proxy, ids_data, ap_tracking)?;
    let key = keys.pop().ok_or(VirtualMachineError::EmptyKeys)?;
    insert_value_from_var_name("first_key", key.clone(), vm_proxy, ids_data, ap_tracking)?;
    //Insert local variables into scope
    exec_scopes_proxy.insert_value("access_indices", access_indices);
    exec_scopes_proxy.insert_value("keys", keys);
    exec_scopes_proxy.insert_value("key", key);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::any::Any;

    use super::*;
    use crate::types::exec_scope::{get_exec_scopes_proxy, ExecutionScopes};
    use crate::utils::test_utils::*;
    use crate::vm::hints::execute_hint::{
        get_vm_proxy, BuiltinHintExecutor, HintProcessorData, HintReference,
    };
    use crate::vm::runners::builtin_runner::RangeCheckBuiltinRunner;
    use crate::vm::vm_core::VirtualMachine;
    use crate::{any_box, bigint};
    use num_bigint::Sign;

    static HINT_EXECUTOR: BuiltinHintExecutor = BuiltinHintExecutor {};
    use crate::types::hint_executor::HintExecutor;

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
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("access_indices", any_box!(access_indices));
        exec_scopes.assign_or_update_variable("key", any_box!(bigint!(5)));
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory (range_check_ptr)
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Create ids_data
        let ids_data = ids_data!["range_check_ptr"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
        //Check scope variables
        //Prepare expected data
        let current_access_indices_scope = exec_scopes_proxy
            .get_list("current_access_indices")
            .unwrap();
        assert_eq!(
            current_access_indices_scope,
            vec![bigint!(10), bigint!(9), bigint!(7)]
        );
        let current_access_index = exec_scopes_proxy.get_int("current_access_index").unwrap();
        assert_eq!(current_access_index, bigint!(3));
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
        let current_accessed_indices = Vec::<BigInt>::new();
        access_indices.insert(bigint!(5), current_accessed_indices);
        //Create vm
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("access_indices", any_box!(access_indices));
        exec_scopes.assign_or_update_variable("key", any_box!(bigint!(5)));
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory (range_check_ptr)
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Create ids_data
        let ids_data = ids_data!["range_check_ptr"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::EmptyCurrentAccessIndices)
        );
    }

    #[test]
    fn squash_dict_inner_first_iteration_no_local_variables() {
        let hint_code = SQUASH_DICT_INNER_FIRST_ITERATION;
        //No scope variables
        //Create vm
        let mut vm = vm!();
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
        //Create ids_data
        let ids_data = ids_data!["range_check_ptr"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
            Err(VirtualMachineError::VariableNotInScopeError(String::from(
                "key"
            )))
        );
    }

    #[test]
    fn should_skip_loop_valid_empty_current_access_indices() {
        let hint_code = SQUASH_DICT_INNER_SKIP_LOOP;
        //Prepare scope variables
        let current_access_indices: Box<dyn Any> = Box::new(Vec::<BigInt>::new());
        //Create vm
        let mut vm = vm!();
        for _ in 0..1 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("current_access_indices", current_access_indices);
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Create ids_data
        let ids_data = ids_data!["should_skip_loop"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
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
        let current_access_indices: Box<dyn Any> = Box::new(vec![bigint!(4), bigint!(7)]);
        //Create vm
        let mut vm = vm!();
        for _ in 0..1 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("current_access_indices", current_access_indices);
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Create ids_data
        let ids_data = ids_data!["should_skip_loop"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
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
        let current_access_indices: Box<dyn Any> =
            Box::new(vec![bigint!(10), bigint!(9), bigint!(7), bigint!(5)]);
        let current_access_index: Box<dyn Any> = Box::new(bigint!(1));
        //Create vm
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("current_access_indices", current_access_indices);
        exec_scopes.assign_or_update_variable("current_access_index", current_access_index);
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Create ids_data
        let ids_data = ids_data!["loop_temps"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
        //Check scope variables
        let current_access_indices_scope = exec_scopes_proxy
            .get_list("current_access_indices")
            .unwrap();
        let new_access_index = exec_scopes_proxy.get_int("new_access_index").unwrap();
        let current_access_index = exec_scopes_proxy.get_int("current_access_index").unwrap();
        assert_eq!(
            current_access_indices_scope,
            vec![bigint!(10), bigint!(9), bigint!(7)]
        );
        assert_eq!(current_access_index, bigint!(5));
        assert_eq!(new_access_index, bigint!(5));
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
        let current_access_indices: Box<dyn Any> = Box::new(Vec::<BigInt>::new());
        let current_access_index: Box<dyn Any> = Box::new(bigint!(1));
        //Create vm
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("current_access_indices", current_access_indices);
        exec_scopes.assign_or_update_variable("current_access_index", current_access_index);
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory (loop_temps)
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Create ids_data
        let ids_data = ids_data!["loop_temps"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::EmptyCurrentAccessIndices)
        );
    }

    #[test]
    fn should_continue_loop_valid_non_empty_current_access_indices() {
        let hint_code = SQUASH_DICT_INNER_CONTINUE_LOOP;
        //Prepare scope variables
        let current_access_indices: Box<dyn Any> = Box::new(vec![bigint!(4), bigint!(7)]);
        //Create vm
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("current_access_indices", current_access_indices);
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Create ids_data
        let ids_data = ids_data!["loop_temps"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
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
        let current_access_indices: Box<dyn Any> = Box::new(Vec::<BigInt>::new());
        //Create vm
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("current_access_indices", current_access_indices);
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Create ids_data
        let ids_data = ids_data!["loop_temps"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
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
        let current_access_indices: Box<dyn Any> = Box::new(Vec::<BigInt>::new());
        //Create vm
        let mut vm = vm!();
        //Store scope variables
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("current_access_indices", current_access_indices);
        //Create hint_data
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        //Execute the hint
        //Hint should produce an error if assertion fails
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
    }

    #[test]
    fn assert_current_indices_len_is_empty_not() {
        let hint_code = SQUASH_DICT_INNER_ASSERT_LEN;
        //Prepare scope variables
        let current_access_indices: Box<dyn Any> = Box::new(vec![bigint!(29)]);
        //Create vm
        let mut vm = vm!();
        //Store scope variables
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("current_access_indices", current_access_indices);
        //Create hint_data
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        //Execute the hint
        //Hint should produce an error if assertion fails
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
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
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("access_indices", any_box!(access_indices));
        exec_scopes.assign_or_update_variable("key", any_box!(bigint!(5)));
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory (n_used_accesses)
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(4)),
            )
            .unwrap();
        //Create hint_data
        let ids_data = ids_data!["n_used_accesses"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        //Hint would fail is assertion fails
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
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
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("access_indices", any_box!(access_indices));
        exec_scopes.assign_or_update_variable("key", any_box!(bigint!(5)));
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory (n_used_accesses)
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();
        //Create hint_data
        let ids_data = ids_data!["n_used_accesses"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
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
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("access_indices", any_box!(access_indices));
        exec_scopes.assign_or_update_variable("key", any_box!(bigint!(5)));
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory (n_used_accesses)
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((0, 2)),
            )
            .unwrap();
        //Create hint_data
        let ids_data = ids_data!["n_used_accesses"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn squash_dict_assert_len_keys_empty() {
        let hint_code = SQUASH_DICT_INNER_LEN_KEYS;
        //Prepare scope variables
        let keys: Box<dyn Any> = Box::new(Vec::<BigInt>::new());
        //Create vm
        let mut vm = vm!();
        //Store scope variables
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("keys", keys);
        //Create hint_data
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
    }

    #[test]
    fn squash_dict_assert_len_keys_not_empty() {
        let hint_code = SQUASH_DICT_INNER_LEN_KEYS;
        //Prepare scope variables
        let keys: Box<dyn Any> = Box::new(vec![bigint!(3)]);
        //Create vm
        let mut vm = vm!();
        //Store scope variables
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("keys", keys);
        //Create hint_data
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::KeysNotEmpty)
        );
    }

    #[test]
    fn squash_dict_assert_len_keys_no_keys() {
        let hint_code = SQUASH_DICT_INNER_LEN_KEYS;
        //Create vm
        let mut vm = vm!();
        //Create hint_data
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
            Err(VirtualMachineError::VariableNotInScopeError(String::from(
                "keys"
            )))
        );
    }

    #[test]
    fn squash_dict_inner_next_key_keys_non_empty() {
        let hint_code = SQUASH_DICT_INNER_NEXT_KEY;
        //Prepare scope variables
        let keys: Box<dyn Any> = Box::new(vec![bigint!(1), bigint!(3)]);
        //Create vm
        let mut vm = vm!();
        for _ in 0..1 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("keys", keys);
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Create hint_data
        let ids_data = ids_data!["next_key"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
        //Check the value of ids.next_key
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(3))))
        );
        //Check local variables
        let keys = exec_scopes_proxy.get_list_ref("keys").unwrap();
        let key = exec_scopes_proxy.get_int_ref("key").unwrap();
        assert_eq!(key, &bigint!(3));
        assert_eq!(keys, &vec![bigint!(1)]);
    }

    #[test]
    fn squash_dict_inner_next_key_keys_empty() {
        let hint_code = SQUASH_DICT_INNER_NEXT_KEY;
        //Prepare scope variables
        let keys: Box<dyn Any> = Box::new(Vec::<BigInt>::new());
        //Create vm
        let mut vm = vm!();
        for _ in 0..1 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Store scope variables
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("keys", keys);
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Create hint_data
        let ids_data = ids_data!["next_key"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::EmptyKeys)
        );
    }

    #[test]
    fn squash_dict_valid_one_key_dict_no_max_size() {
        //Dict = {1: (1,1), 1: (1,2)}
        let hint_code = SQUASH_DICT;
        //Create vm
        let mut vm = vm_with_range_check!();
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
        //Create hint_data
        let ids_data = ids_data![
            "dict_accesses",
            "big_keys",
            "first_key",
            "ptr_diff",
            "n_accesses"
        ];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        let mut exec_scopes = ExecutionScopes::new();
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
        //Check scope variables
        let access_indices = get_access_indices(exec_scopes_proxy).unwrap();
        assert_eq!(
            access_indices,
            &HashMap::from([(bigint!(1), vec![bigint!(0), bigint!(1)])])
        );
        let keys = exec_scopes_proxy.get_list("keys").unwrap();
        assert_eq!(keys, Vec::<BigInt>::new());
        let key = exec_scopes_proxy.get_int("key").unwrap();
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
        //Create vm
        let mut vm = vm_with_range_check!();
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

        //Create hint_data
        let ids_data = ids_data![
            "dict_accesses",
            "big_keys",
            "first_key",
            "ptr_diff",
            "n_accesses"
        ];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        let mut exec_scopes = ExecutionScopes::new();
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
        //Check scope variables
        let access_indices = get_access_indices(exec_scopes_proxy).unwrap();
        assert_eq!(
            access_indices,
            &HashMap::from([
                (bigint!(1), vec![bigint!(0), bigint!(1)]),
                (bigint!(2), vec![bigint!(2), bigint!(3)])
            ])
        );
        let keys = exec_scopes_proxy.get_list("keys").unwrap();
        assert_eq!(keys, vec![bigint!(2)]);
        let key = exec_scopes_proxy.get_int("key").unwrap();
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
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Create scope variables
        let mut exec_scopes = ExecutionScopes::new();
        let max_size: Box<dyn Any> = Box::new(bigint!(12));
        exec_scopes.assign_or_update_variable("__squash_dict_max_size", max_size);
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

        //Create hint_data
        let ids_data = ids_data![
            "dict_accesses",
            "big_keys",
            "first_key",
            "ptr_diff",
            "n_accesses"
        ];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
        //Check scope variables
        let access_indices = get_access_indices(exec_scopes_proxy).unwrap();
        assert_eq!(
            access_indices,
            &HashMap::from([(bigint!(1), vec![bigint!(0), bigint!(1)])])
        );
        let keys = exec_scopes_proxy.get_list("keys").unwrap();
        assert_eq!(keys, Vec::<BigInt>::new());
        let key = exec_scopes_proxy.get_int("key").unwrap();
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
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Create scope variables
        let mut exec_scopes = ExecutionScopes::new();
        let max_size: Box<dyn Any> = Box::new(bigint!(1));
        exec_scopes.assign_or_update_variable("__squash_dict_max_size", max_size);
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

        //Create hint_data
        let ids_data = ids_data![
            "dict_accesses",
            "big_keys",
            "first_key",
            "ptr_diff",
            "n_accesses"
        ];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
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
        let mut vm = vm_with_range_check!();
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

        //Create hint_data
        let ids_data = ids_data![
            "dict_accesses",
            "big_keys",
            "first_key",
            "ptr_diff",
            "n_accesses"
        ];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
            Err(VirtualMachineError::PtrDiffNotDivisibleByDictAccessSize)
        );
    }
    #[test]
    fn squash_dict_invalid_one_key_dict_with_n_access_too_big() {
        //Dict = {1: (1,1), 1: (1,2)}
        let hint_code = SQUASH_DICT;
        //Create vm
        let mut vm = vm_with_range_check!();
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

        //Create hint_data
        let ids_data = ids_data![
            "dict_accesses",
            "big_keys",
            "first_key",
            "ptr_diff",
            "n_accesses"
        ];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
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
        let mut vm = vm_with_range_check!();
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

        //Create hint_data
        let ids_data = ids_data![
            "dict_accesses",
            "big_keys",
            "first_key",
            "ptr_diff",
            "n_accesses"
        ];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        let mut exec_scopes = ExecutionScopes::new();
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
        //Check scope variables
        let access_indices = get_access_indices(exec_scopes_proxy).unwrap();
        assert_eq!(
            access_indices,
            &HashMap::from([(
                BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217727]),
                vec![bigint!(0), bigint!(1)]
            )])
        );
        let keys = exec_scopes_proxy.get_list("keys").unwrap();
        assert_eq!(keys, Vec::<BigInt>::new());
        let key = exec_scopes_proxy.get_int("key").unwrap();
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
