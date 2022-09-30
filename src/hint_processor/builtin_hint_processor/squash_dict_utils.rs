use crate::hint_processor::hint_processor_definition::HintReference;
use crate::hint_processor::hint_processor_utils::get_range_check_builtin;
use crate::hint_processor::proxies::exec_scopes_proxy::ExecutionScopesProxy;
use crate::hint_processor::proxies::vm_proxy::VMProxy;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::ToPrimitive;
use std::collections::HashMap;

use super::dict_hint_utils::DICT_ACCESS_SIZE;
use crate::hint_processor::builtin_hint_processor::hint_utils::{
    get_integer_from_var_name, get_ptr_from_var_name, get_relocatable_from_var_name,
    insert_value_from_var_name,
};
use crate::{
    bigint, serde::deserialize_program::ApTracking, types::relocatable::MaybeRelocatable,
    vm::errors::vm_errors::VirtualMachineError,
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
        get_ptr_from_var_name("range_check_ptr", vm_proxy, ids_data, ap_tracking)?;
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
    vm_proxy.insert_value(&range_check_ptr, first_val)
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
        get_relocatable_from_var_name("loop_temps", vm_proxy, ids_data, ap_tracking)?;
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
    vm_proxy.insert_value(&should_continue_addr, should_continue)
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
        get_integer_from_var_name("n_used_accesses", vm_proxy, ids_data, ap_tracking)?;
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
    let address = get_ptr_from_var_name("dict_accesses", vm_proxy, ids_data, ap_tracking)?;
    let ptr_diff = get_integer_from_var_name("ptr_diff", vm_proxy, ids_data, ap_tracking)?;
    let n_accesses = get_integer_from_var_name("n_accesses", vm_proxy, ids_data, ap_tracking)?;
    //Get range_check_builtin
    let range_check_builtin = get_range_check_builtin(vm_proxy.builtin_runners)?;
    let range_check_bound = range_check_builtin._bound.clone();
    //Main Logic
    if ptr_diff.mod_floor(&bigint!(DICT_ACCESS_SIZE)) != bigint!(0) {
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
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData;
    use crate::hint_processor::proxies::vm_proxy::get_vm_proxy;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::vm::vm_memory::memory::Memory;
    use std::any::Any;

    use super::*;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
    use crate::hint_processor::hint_processor_definition::HintProcessor;
    use crate::hint_processor::proxies::exec_scopes_proxy::get_exec_scopes_proxy;
    use crate::types::exec_scope::ExecutionScopes;
    use crate::utils::test_utils::*;
    use crate::vm::runners::builtin_runner::RangeCheckBuiltinRunner;
    use crate::vm::vm_core::VirtualMachine;
    use crate::{any_box, bigint, bigint_str};
    use num_bigint::Sign;

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
        //Store scope variables
        let mut exec_scopes = scope![("access_indices", access_indices), ("key", bigint!(5))];
        //Initialize fp
        vm.run_context.fp = 1;
        //Insert ids into memory (range_check_ptr)
        vm.memory = memory![((1, 0), (2, 0))];
        add_segments!(vm, 1);
        //Create ids_data
        let ids_data = ids_data!["range_check_ptr"];
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy),
            Ok(())
        );
        //Check scope variables
        check_scope!(
            exec_scopes_proxy,
            [
                (
                    "current_access_indices",
                    vec![bigint!(10), bigint!(9), bigint!(7)]
                ),
                ("current_access_index", bigint!(3))
            ]
        );
        //Check that current_access_index is now at range_check_ptr
        check_memory![vm.memory, ((2, 0), 3)];
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
        //Store scope variables
        let mut exec_scopes = scope![("access_indices", access_indices), ("key", bigint!(5))];
        //Initialize fp
        vm.run_context.fp = 1;
        //Insert ids into memory (range_check_ptr)
        vm.memory = memory![((1, 0), (2, 0))];
        //Create ids_data
        let ids_data = ids_data!["range_check_ptr"];
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy),
            Err(VirtualMachineError::EmptyCurrentAccessIndices)
        );
    }

    #[test]
    fn squash_dict_inner_first_iteration_no_local_variables() {
        let hint_code = SQUASH_DICT_INNER_FIRST_ITERATION;
        //No scope variables
        //Create vm
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 1;
        //Insert ids into memory (range_check_ptr)
        vm.memory = memory![((1, 0), (2, 0))];
        //Create ids_data
        let ids_data = ids_data!["range_check_ptr"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::VariableNotInScopeError(String::from(
                "key"
            )))
        );
    }

    #[test]
    fn should_skip_loop_valid_empty_current_access_indices() {
        let hint_code = SQUASH_DICT_INNER_SKIP_LOOP;
        //Create vm
        let mut vm = vm!();
        add_segments!(vm, 2);
        //Store scope variables
        let mut exec_scopes = scope![("current_access_indices", Vec::<BigInt>::new())];
        //Initialize fp
        vm.run_context.fp = 1;
        //Create ids_data
        let ids_data = ids_data!["should_skip_loop"];
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy),
            Ok(())
        );
        //Check the value of ids.should_skip_loop
        check_memory![vm.memory, ((1, 0), 1)];
    }

    #[test]
    fn should_skip_loop_valid_non_empty_current_access_indices() {
        let hint_code = SQUASH_DICT_INNER_SKIP_LOOP;
        //Create vm
        let mut vm = vm!();
        add_segments!(vm, 2);
        //Store scope variables
        let mut exec_scopes = scope![("current_access_indices", vec![bigint!(4), bigint!(7)])];
        //Initialize fp
        vm.run_context.fp = 1;
        //Create ids_data
        let ids_data = ids_data!["should_skip_loop"];
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy),
            Ok(())
        );
        //Check the value of ids.should_skip_loop
        check_memory![vm.memory, ((1, 0), 0)];
    }

    #[test]
    fn squash_dict_inner_check_access_index_valid() {
        let hint_code = SQUASH_DICT_INNER_CHECK_ACCESS_INDEX;
        //Create vm
        let mut vm = vm!();
        add_segments!(vm, 2);
        //Store scope variables
        let mut exec_scopes = scope![
            (
                "current_access_indices",
                vec![bigint!(10), bigint!(9), bigint!(7), bigint!(5)]
            ),
            ("current_access_index", bigint!(1))
        ];
        //Initialize fp
        vm.run_context.fp = 1;
        //Create ids_data
        let ids_data = ids_data!["loop_temps"];
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy),
            Ok(())
        );
        //Check scope variables
        check_scope!(
            exec_scopes_proxy,
            [
                (
                    "current_access_indices",
                    vec![bigint!(10), bigint!(9), bigint!(7)]
                ),
                ("new_access_index", bigint!(5)),
                ("current_access_index", bigint!(5))
            ]
        );
        //Check the value of loop_temps.index_delta_minus_1
        //new_index - current_index -1
        //5 - 1 - 1 = 3
        check_memory![vm.memory, ((1, 0), 3)];
    }

    #[test]
    fn squash_dict_inner_check_access_current_access_addr_empty() {
        let hint_code = SQUASH_DICT_INNER_CHECK_ACCESS_INDEX;
        //Create vm
        let mut vm = vm!();
        //Store scope variables
        let mut exec_scopes = scope![
            ("current_access_indices", Vec::<BigInt>::new()),
            ("current_access_index", bigint!(1))
        ];
        //Initialize fp
        vm.run_context.fp = 1;
        //Insert ids into memory (loop_temps)
        vm.memory = memory![((1, 0), (2, 0))];
        //Create ids_data
        let ids_data = ids_data!["loop_temps"];
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy),
            Err(VirtualMachineError::EmptyCurrentAccessIndices)
        );
    }

    #[test]
    fn should_continue_loop_valid_non_empty_current_access_indices() {
        let hint_code = SQUASH_DICT_INNER_CONTINUE_LOOP;
        //Create vm
        let mut vm = vm!();
        add_segments!(vm, 2);
        //Store scope variables
        let mut exec_scopes = scope![("current_access_indices", vec![bigint!(4), bigint!(7)])];
        //Initialize fp
        vm.run_context.fp = 1;
        //Create ids_data
        let ids_data = ids_data!["loop_temps"];
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy),
            Ok(())
        );
        //Check the value of ids.loop_temps.should_continue (loop_temps + 3)
        check_memory![vm.memory, ((1, 3), 1)];
    }

    #[test]
    fn should_continue_loop_valid_empty_current_access_indices() {
        let hint_code = SQUASH_DICT_INNER_CONTINUE_LOOP;
        //Create vm
        let mut vm = vm!();
        add_segments!(vm, 2);
        //Store scope variables
        let mut exec_scopes = scope![("current_access_indices", Vec::<BigInt>::new())];
        //Initialize fp
        vm.run_context.fp = 1;
        //Create ids_data
        let ids_data = ids_data!["loop_temps"];
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy),
            Ok(())
        );
        //Check the value of ids.loop_temps.should_continue (loop_temps + 3)
        check_memory![vm.memory, ((1, 3), 0)];
    }

    #[test]
    fn assert_current_indices_len_is_empty() {
        let hint_code = SQUASH_DICT_INNER_ASSERT_LEN;
        //Create vm
        let mut vm = vm!();
        //Store scope variables
        let mut exec_scopes = scope![("current_access_indices", Vec::<BigInt>::new())];
        //Execute the hint
        //Hint should produce an error if assertion fails
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, HashMap::new(), hint_code, exec_scopes_proxy),
            Ok(())
        );
    }

    #[test]
    fn assert_current_indices_len_is_empty_not() {
        let hint_code = SQUASH_DICT_INNER_ASSERT_LEN;
        //Create vm
        let mut vm = vm!();
        //Store scope variables
        let mut exec_scopes = scope![("current_access_indices", vec![bigint!(29)])];
        //Execute the hint
        //Hint should produce an error if assertion fails
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, HashMap::new(), hint_code, exec_scopes_proxy),
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
        //Store scope variables
        let mut exec_scopes = scope![("access_indices", access_indices), ("key", bigint!(5))];
        //Initialize fp
        vm.run_context.fp = 1;
        //Insert ids into memory (n_used_accesses)
        vm.memory = memory![((1, 0), 4)];
        //Create hint_data
        let ids_data = ids_data!["n_used_accesses"];
        //Execute the hint
        //Hint would fail is assertion fails
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy),
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
        //Store scope variables
        let mut exec_scopes = scope![("access_indices", access_indices), ("key", bigint!(5))];
        //Initialize fp
        vm.run_context.fp = 1;
        //Insert ids into memory (n_used_accesses)
        vm.memory = memory![((1, 0), 5)];
        //Create hint_data
        let ids_data = ids_data!["n_used_accesses"];
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy),
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
        //Store scope variables
        let mut exec_scopes = scope![("access_indices", access_indices), ("key", bigint!(5))];
        //Initialize fp
        vm.run_context.fp = 1;
        //Insert ids into memory (n_used_accesses)
        vm.memory = memory![((1, 0), (1, 2))];
        //Create hint_data
        let ids_data = ids_data!["n_used_accesses"];
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 0))
            ))
        );
    }

    #[test]
    fn squash_dict_assert_len_keys_empty() {
        let hint_code = SQUASH_DICT_INNER_LEN_KEYS;
        //Create vm
        let mut vm = vm!();
        //Store scope variables
        let mut exec_scopes = scope![("keys", Vec::<BigInt>::new())];
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, HashMap::new(), hint_code, exec_scopes_proxy),
            Ok(())
        );
    }

    #[test]
    fn squash_dict_assert_len_keys_not_empty() {
        let hint_code = SQUASH_DICT_INNER_LEN_KEYS;
        //Create vm
        let mut vm = vm!();
        //Store scope variables
        let mut exec_scopes = scope![("keys", vec![bigint!(3)])];
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, HashMap::new(), hint_code, exec_scopes_proxy),
            Err(VirtualMachineError::KeysNotEmpty)
        );
    }

    #[test]
    fn squash_dict_assert_len_keys_no_keys() {
        let hint_code = SQUASH_DICT_INNER_LEN_KEYS;
        //Create vm
        let mut vm = vm!();
        //Execute the hint
        assert_eq!(
            run_hint!(vm, HashMap::new(), hint_code),
            Err(VirtualMachineError::VariableNotInScopeError(String::from(
                "keys"
            )))
        );
    }

    #[test]
    fn squash_dict_inner_next_key_keys_non_empty() {
        let hint_code = SQUASH_DICT_INNER_NEXT_KEY;
        //Create vm
        let mut vm = vm!();
        add_segments!(vm, 2);
        //Store scope variables
        let mut exec_scopes = scope![("keys", vec![bigint!(1), bigint!(3)])];
        //Initialize fp
        vm.run_context.fp = 1;
        //Create hint_data
        let ids_data = ids_data!["next_key"];
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy),
            Ok(())
        );
        //Check the value of ids.next_key
        check_memory![vm.memory, ((1, 0), 3)];
        //Check local variables
        check_scope!(
            exec_scopes_proxy,
            [("keys", vec![bigint!(1)]), ("key", bigint!(3))]
        );
    }

    #[test]
    fn squash_dict_inner_next_key_keys_empty() {
        let hint_code = SQUASH_DICT_INNER_NEXT_KEY;
        //Create vm
        let mut vm = vm!();
        //Store scope variables
        let mut exec_scopes = scope![("keys", Vec::<BigInt>::new())];
        //Initialize fp
        vm.run_context.fp = 1;
        //Create hint_data
        let ids_data = ids_data!["next_key"];
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy),
            Err(VirtualMachineError::EmptyKeys)
        );
    }

    #[test]
    fn squash_dict_valid_one_key_dict_no_max_size() {
        //Dict = {1: (1,1), 1: (1,2)}
        let hint_code = SQUASH_DICT;
        //Create vm
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 5;
        //Insert ids into memory
        vm.memory = memory![
            ((1, 0), (2, 0)),
            ((1, 3), 6),
            ((1, 4), 2),
            ((2, 0), 1),
            ((2, 1), 1),
            ((2, 2), 1),
            ((2, 3), 1),
            ((2, 4), 1),
            ((2, 5), 2)
        ];
        //Create hint_data
        let ids_data = ids_data![
            "dict_accesses",
            "big_keys",
            "first_key",
            "ptr_diff",
            "n_accesses"
        ];
        let mut exec_scopes = ExecutionScopes::new();
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy),
            Ok(())
        );
        //Check scope variables
        check_scope!(
            exec_scopes_proxy,
            [
                (
                    "access_indices",
                    HashMap::from([(bigint!(1), vec![bigint!(0), bigint!(1)])])
                ),
                ("keys", Vec::<BigInt>::new()),
                ("key", bigint!(1))
            ]
        );
        //Check ids variables
        check_memory![vm.memory, ((1, 1), 0), ((1, 2), 1)];
    }

    #[test]
    fn squash_dict_valid_two_key_dict_no_max_size() {
        //Dict = {1: (1,1), 1: (1,2), 2: (10,10), 2: (10,20)}
        let hint_code = SQUASH_DICT;
        //Create vm
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 5;
        //Insert ids into memory
        vm.memory = memory![
            ((1, 0), (2, 0)),
            ((1, 3), 6),
            ((1, 4), 4),
            ((2, 0), 1),
            ((2, 1), 1),
            ((2, 2), 1),
            ((2, 3), 1),
            ((2, 4), 1),
            ((2, 5), 2),
            ((2, 6), 2),
            ((2, 7), 10),
            ((2, 8), 10),
            ((2, 9), 2),
            ((2, 10), 10),
            ((2, 11), 20)
        ];
        //Create hint_data
        let ids_data = ids_data![
            "dict_accesses",
            "big_keys",
            "first_key",
            "ptr_diff",
            "n_accesses"
        ];
        let mut exec_scopes = ExecutionScopes::new();
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy),
            Ok(())
        );
        //Check scope variables
        check_scope!(
            exec_scopes_proxy,
            [
                (
                    "access_indices",
                    HashMap::from([
                        (bigint!(1), vec![bigint!(0), bigint!(1)]),
                        (bigint!(2), vec![bigint!(2), bigint!(3)])
                    ])
                ),
                ("keys", vec![bigint!(2)]),
                ("key", bigint!(1))
            ]
        );
        let keys = exec_scopes_proxy.get_list("keys").unwrap();
        assert_eq!(keys, vec![bigint!(2)]);
        //Check ids variables
        check_memory![vm.memory, ((1, 1), 0), ((1, 2), 1)];
    }

    #[test]
    fn squash_dict_valid_one_key_dict_with_max_size() {
        //Dict = {1: (1,1), 1: (1,2)}
        let hint_code = SQUASH_DICT;
        //Create vm
        let mut vm = vm_with_range_check!();
        //Create scope variables
        let mut exec_scopes = scope![("__squash_dict_max_size", bigint!(12))];
        //Initialize fp
        vm.run_context.fp = 5;
        //Insert ids into memory
        vm.memory = memory![
            ((1, 0), (2, 0)),
            ((1, 3), 6),
            ((1, 4), 2),
            ((2, 0), 1),
            ((2, 1), 1),
            ((2, 2), 1),
            ((2, 3), 1),
            ((2, 4), 1),
            ((2, 5), 2)
        ];
        //Create ids_data
        let ids_data = ids_data![
            "dict_accesses",
            "big_keys",
            "first_key",
            "ptr_diff",
            "n_accesses"
        ];
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy),
            Ok(())
        );
        //Check scope variables
        check_scope!(
            exec_scopes_proxy,
            [
                (
                    "access_indices",
                    HashMap::from([(bigint!(1), vec![bigint!(0), bigint!(1)])])
                ),
                ("keys", Vec::<BigInt>::new()),
                ("key", bigint!(1))
            ]
        );
        //Check ids variables
        check_memory![vm.memory, ((1, 1), 0), ((1, 2), 1)];
    }

    #[test]
    fn squash_dict_invalid_one_key_dict_with_max_size_exceeded() {
        //Dict = {1: (1,1), 1: (1,2)}
        let hint_code = SQUASH_DICT;
        //Create vm
        let mut vm = vm_with_range_check!();
        //Create scope variables
        let mut exec_scopes = scope![("__squash_dict_max_size", bigint!(1))];
        //Initialize fp
        vm.run_context.fp = 5;
        //Insert ids into memory
        vm.memory = memory![
            ((1, 0), (2, 0)),
            ((1, 3), 6),
            ((1, 4), 2),
            ((2, 0), 1),
            ((2, 1), 1),
            ((2, 2), 1),
            ((2, 3), 1),
            ((2, 4), 1),
            ((2, 5), 2)
        ];
        //Create ids_data
        let ids_data = ids_data![
            "dict_accesses",
            "big_keys",
            "first_key",
            "ptr_diff",
            "n_accesses"
        ];
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy),
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
        //Initialize fp
        vm.run_context.fp = 5;
        //Insert ids into memory
        vm.memory = memory![
            ((1, 0), (2, 0)),
            ((1, 3), 7),
            ((1, 4), 2),
            ((2, 0), 1),
            ((2, 1), 1),
            ((2, 2), 1),
            ((2, 3), 1),
            ((2, 4), 1),
            ((2, 5), 2)
        ];
        //Create hint_data
        let ids_data = ids_data![
            "dict_accesses",
            "big_keys",
            "first_key",
            "ptr_diff",
            "n_accesses"
        ];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::PtrDiffNotDivisibleByDictAccessSize)
        );
    }
    #[test]
    fn squash_dict_invalid_one_key_dict_with_n_access_too_big() {
        //Dict = {1: (1,1), 1: (1,2)}
        let hint_code = SQUASH_DICT;
        //Create vm
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 5;
        //Insert ids into memory
        vm.memory = memory![
            ((1, 0), (2, 0)),
            ((1, 3), 6),
            (
                (1, 4),
                (
                    b"3618502761706184546546682988428055018603476541694452277432519575032261771265",
                    10
                )
            ),
            ((2, 0), 1),
            ((2, 1), 1),
            ((2, 2), 1),
            ((2, 3), 1),
            ((2, 4), 1),
            ((2, 5), 2)
        ];
        //Create hint_data
        let ids_data = ids_data![
            "dict_accesses",
            "big_keys",
            "first_key",
            "ptr_diff",
            "n_accesses"
        ];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::NAccessesTooBig(bigint_str!(
                b"3618502761706184546546682988428055018603476541694452277432519575032261771265"
            )))
        );
    }

    #[test]
    fn squash_dict_valid_one_key_dict_no_max_size_big_keys() {
        //Dict = {(prime - 1): (1,1), (prime - 1): (1,2)}
        let hint_code = SQUASH_DICT;
        //Create vm
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 5;
        //Insert ids into memory
        vm.memory = memory![
            ((1, 0), (2, 0)),
            ((1, 3), 6),
            ((1, 4), 2),
            (
                (2, 0),
                (
                    b"3618502761706184546546682988428055018603476541694452277432519575032261771265",
                    10
                )
            ),
            ((2, 1), 1),
            ((2, 2), 1),
            (
                (2, 3),
                (
                    b"3618502761706184546546682988428055018603476541694452277432519575032261771265",
                    10
                )
            ),
            ((2, 4), 1),
            ((2, 5), 2)
        ];
        //Create hint_data
        let ids_data = ids_data![
            "dict_accesses",
            "big_keys",
            "first_key",
            "ptr_diff",
            "n_accesses"
        ];
        let mut exec_scopes = ExecutionScopes::new();
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy),
            Ok(())
        );
        //Check scope variables
        check_scope!(exec_scopes_proxy, [("access_indices", HashMap::from([(
           bigint_str!(b"3618502761706184546546682988428055018603476541694452277432519575032261771265"),
            vec![bigint!(0), bigint!(1)]
        )])), ("keys", Vec::<BigInt>::new()), ("key", bigint_str!(b"3618502761706184546546682988428055018603476541694452277432519575032261771265"))]);
        //Check ids variables
        check_memory![
            vm.memory,
            ((1, 1), 1),
            (
                (1, 2),
                (
                    b"3618502761706184546546682988428055018603476541694452277432519575032261771265",
                    10
                )
            )
        ];
    }
}
