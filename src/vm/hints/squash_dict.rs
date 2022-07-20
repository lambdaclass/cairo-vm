use std::collections::HashMap;

use num_bigint::BigInt;
use num_traits::FromPrimitive;

use crate::{
    bigint,
    types::{exec_scope::PyValueType, relocatable::MaybeRelocatable},
    vm::{errors::vm_errors::VirtualMachineError, vm_core::VirtualMachine},
};

use super::hint_utils::get_address_from_reference;

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

fn get_int_from_scope(vm: &mut VirtualMachine, name: &str) -> Option<BigInt> {
    let mut val: Option<BigInt> = None;
    if let Some(variables) = vm.exec_scopes.get_local_variables() {
        if let Some(PyValueType::BigInt(py_val)) = variables.get(name) {
            val = Some(py_val.clone());
        }
    }
    val
}

fn get_list_from_scope(vm: &mut VirtualMachine, name: &str) -> Option<Vec<BigInt>> {
    let mut val: Option<Vec<BigInt>> = None;
    if let Some(variables) = vm.exec_scopes.get_local_variables() {
        if let Some(PyValueType::List(py_val)) = variables.get(name) {
            val = Some(py_val.clone());
        }
    }
    val
}

/*Implements hint:
    current_access_indices = sorted(access_indices[key])[::-1]
    current_access_index = current_access_indices.pop()
    memory[ids.range_check_ptr] = current_access_index
*/
pub fn squash_dict_inner_first_iteration(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    //Check that access_indices and key are in scope
    let access_indices = get_access_indices(vm)
        .ok_or_else(|| VirtualMachineError::NoLocalVariable(String::from("access_indices")))?;
    let key = get_int_from_scope(vm, "key")
        .ok_or_else(|| VirtualMachineError::NoLocalVariable(String::from("key")))?;
    //Check that ids contains the reference id for each variable used by the hint
    let range_check_ptr_ref = ids.get(&String::from("range_check_ptr")).ok_or_else(|| {
        VirtualMachineError::IncorrectIds(
            vec![String::from("range_check_ptr")],
            ids.clone().into_keys().collect(),
        )
    })?;
    //Check that each reference id corresponds to a value in the reference manager
    let range_check_ptr_addr =
        get_address_from_reference(range_check_ptr_ref, &vm.references, &vm.run_context, vm)
            .ok_or_else(|| {
                VirtualMachineError::FailedToGetReference(range_check_ptr_ref.clone())
            })?;
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
    ids: HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    //Check that current_access_indices is in scope
    let current_access_indices =
        get_list_from_scope(vm, "current_access_indices").ok_or_else(|| {
            VirtualMachineError::NoLocalVariable(String::from("current_access_indices"))
        })?;
    //Check that ids contains the reference id for each variable used by the hint
    let should_skip_loop_ref = ids.get(&String::from("should_skip_loop")).ok_or_else(|| {
        VirtualMachineError::IncorrectIds(
            vec![String::from("should_skip_loop")],
            ids.clone().into_keys().collect(),
        )
    })?;
    //Check that each reference id corresponds to a value in the reference manager
    let should_skip_loop_addr =
        get_address_from_reference(should_skip_loop_ref, &vm.references, &vm.run_context, vm)
            .ok_or_else(|| {
                VirtualMachineError::FailedToGetReference(should_skip_loop_ref.clone())
            })?;
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
    ids: HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    //Check that current_access_indices and current_access_index are in scope
    let mut current_access_indices =
        get_list_from_scope(vm, "current_access_indices").ok_or_else(|| {
            VirtualMachineError::NoLocalVariable(String::from("current_access_indices"))
        })?;
    let current_access_index = get_int_from_scope(vm, "current_access_index").ok_or_else(|| {
        VirtualMachineError::NoLocalVariable(String::from("current_access_index"))
    })?;
    //Check that ids contains the reference id for each variable used by the hint
    let loop_temps_ref = ids.get(&String::from("loop_temps")).ok_or_else(|| {
        VirtualMachineError::IncorrectIds(
            vec![String::from("loop_temps")],
            ids.clone().into_keys().collect(),
        )
    })?;
    //Check that each reference id corresponds to a value in the reference manager
    let loop_temps_addr =
        get_address_from_reference(loop_temps_ref, &vm.references, &vm.run_context, vm)
            .ok_or_else(|| VirtualMachineError::FailedToGetReference(loop_temps_ref.clone()))?;
    //Get loop_temps from memory
    let loop_temps = vm
        .memory
        .get(&loop_temps_addr)
        .map_err(VirtualMachineError::MemoryError)?
        .ok_or_else(|| VirtualMachineError::MemoryGet(loop_temps_addr.clone()))?
        .clone();
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
        .insert(&loop_temps, &MaybeRelocatable::from(index_delta_minus1))
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
    ids: HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    //Check that current_access_indices is in scope
    let current_access_indices =
        get_list_from_scope(vm, "current_access_indices").ok_or_else(|| {
            VirtualMachineError::NoLocalVariable(String::from("current_access_indices"))
        })?;
    //Check that ids contains the reference id for each variable used by the hint
    let loop_temps_ref = ids.get(&String::from("loop_temps")).ok_or_else(|| {
        VirtualMachineError::IncorrectIds(
            vec![String::from("loop_temps")],
            ids.clone().into_keys().collect(),
        )
    })?;
    //Check that each reference id corresponds to a value in the reference manager
    let loop_temps_addr =
        get_address_from_reference(loop_temps_ref, &vm.references, &vm.run_context, vm)
            .ok_or_else(|| VirtualMachineError::FailedToGetReference(loop_temps_ref.clone()))?;
    //Get loop_temps from memory
    let loop_temps = vm
        .memory
        .get(&loop_temps_addr)
        .map_err(VirtualMachineError::MemoryError)?
        .ok_or_else(|| VirtualMachineError::MemoryGet(loop_temps_addr.clone()))?;
    //Main Logic
    let should_continue = if current_access_indices.is_empty() {
        bigint!(0)
    } else {
        bigint!(1)
    };
    //loop_temps.delta_minus1 = loop_temps + 3 as it is the fourth field of the struct
    //Insert loop_temps.delta_minus1 into memory
    let should_continue_addr = loop_temps.add_usize_mod(3, None);
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
#[cfg(test)]
mod tests {
    use crate::bigint;
    use crate::types::exec_scope::PyValueType;
    use crate::types::instruction::Register;
    use crate::vm::hints::execute_hint::{execute_hint, HintReference};
    use num_bigint::Sign;
    use num_traits::FromPrimitive;

    use super::*;
    //Hint code as consts
    const SQUASH_DICT_INNER_FIRST_ITERATION : &str = "current_access_indices = sorted(access_indices[key])[::-1]\n    current_access_index = current_access_indices.pop()\n    memory[ids.range_check_ptr] = current_access_index";
    const SQUASH_DICT_INNER_SKIP_LOOP: &str =
        "ids.should_skip_loop = 0 if current_access_indices else 1";
    const SQUASH_DICT_INNER_CHECK_ACCESS_INDEX: &str = "new_access_index = current_access_indices.pop()\n    ids.loop_temps.index_delta_minus1 = new_access_index - current_access_index - 1\n    current_access_index = new_access_index";
    const SQUASH_DICT_INNER_CONTINUE_LOOP: &str =
        "ids.loop_temps.should_continue = 1 if current_access_indices else 0";
    const SQUASH_DICT_INNER_ASSERT_LEN: &str = "assert len(current_access_indices) == 0";
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
            },
        )]);
        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids), Ok(()));
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
            },
        )]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
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
            },
        )]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::NoLocalVariable(String::from(
                "access_indices"
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
            },
        )]);
        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids), Ok(()));
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
            },
        )]);
        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids), Ok(()));
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
            },
        )]);
        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids), Ok(()));
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
            vm.memory.get(&MaybeRelocatable::from((1, 0))),
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
            },
        )]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
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
        //Insert ids into memory
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
            },
        )]);
        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids), Ok(()));
        //Check the value of ids.loop_temps.should_continue (loop_temps + 3)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 3))),
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
        //Insert ids into memory
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
            },
        )]);
        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids), Ok(()));
        //Check the value of ids.loop_temps.should_continue (loop_temps + 3)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 3))),
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
        assert_eq!(execute_hint(&mut vm, hint_code, HashMap::new()), Ok(()));
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
            execute_hint(&mut vm, hint_code, HashMap::new()),
            Err(VirtualMachineError::CurrentAccessIndicesNotEmpty)
        );
    }
}
