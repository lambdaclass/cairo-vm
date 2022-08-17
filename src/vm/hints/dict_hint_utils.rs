use std::{any::Any, cell::RefCell, collections::HashMap, rc::Rc};

use num_bigint::BigInt;

use crate::{
    any_box,
    serde::deserialize_program::ApTracking,
    types::exec_scope::ExecutionScopesProxy,
    vm::{errors::vm_errors::VirtualMachineError, vm_core::VMProxy},
};

use super::{
    dict_manager::DictManager,
    execute_hint::HintReference,
    hint_utils::{
        get_integer_from_var_name, get_ptr_from_var_name, insert_value_from_var_name,
        insert_value_into_ap,
    },
};
//DictAccess struct has three memebers, so the size of DictAccess* is 3
pub const DICT_ACCESS_SIZE: usize = 3;

fn copy_initial_dict(
    exec_scopes_proxy: &mut ExecutionScopesProxy,
) -> Option<HashMap<BigInt, BigInt>> {
    let mut initial_dict: Option<HashMap<BigInt, BigInt>> = None;
    if let Some(variable) = exec_scopes_proxy
        .get_local_variables()
        .ok()?
        .get("initial_dict")
    {
        if let Some(dict) = variable.downcast_ref::<HashMap<BigInt, BigInt>>() {
            initial_dict = Some(dict.clone());
        }
    }
    initial_dict
}

/*Implements hint:
   if '__dict_manager' not in globals():
           from starkware.cairo.common.dict import DictManager
           __dict_manager = DictManager()

       memory[ap] = __dict_manager.new_dict(segments, initial_dict)
       del initial_dict

For now, the functionality to create a dictionary from a previously defined initial_dict (using a hint)
is not available
*/
pub fn dict_new(
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
) -> Result<(), VirtualMachineError> {
    //Get initial dictionary from scope (defined by an earlier hint)
    let initial_dict =
        copy_initial_dict(exec_scopes_proxy).ok_or(VirtualMachineError::NoInitialDict)?;
    //Check if there is a dict manager in scope, create it if there isnt one
    let base = if let Ok(dict_manager) = exec_scopes_proxy.get_dict_manager() {
        dict_manager
            .borrow_mut()
            .new_dict(vm_proxy.segments, &mut vm_proxy.memory, initial_dict)?
    } else {
        let mut dict_manager = DictManager::new();
        let base = dict_manager.new_dict(vm_proxy.segments, &mut vm_proxy.memory, initial_dict)?;
        exec_scopes_proxy.insert_value("dict_manager", Rc::new(RefCell::new(dict_manager)));
        base
    };
    insert_value_into_ap(&mut vm_proxy.memory, vm_proxy.run_context, base)
}

/*Implements hint:
   if '__dict_manager' not in globals():
            from starkware.cairo.common.dict import DictManager
            __dict_manager = DictManager()

        memory[ap] = __dict_manager.new_default_dict(segments, ids.default_value)

For now, the functionality to create a dictionary from a previously defined initial_dict (using a hint)
is not available, an empty dict is created always
*/
pub fn default_dict_new(
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    //Check that ids contains the reference id for each variable used by the hint
    let default_value =
        get_integer_from_var_name("default_value", &vm_proxy, ids_data, ap_tracking)?.clone();
    //Get initial dictionary from scope (defined by an earlier hint) if available
    let initial_dict = copy_initial_dict(exec_scopes_proxy);
    //Check if there is a dict manager in scope, create it if there isnt one
    let base = if let Ok(dict_manager) = exec_scopes_proxy.get_dict_manager() {
        dict_manager.borrow_mut().new_default_dict(
            vm_proxy.segments,
            &mut vm_proxy.memory,
            &default_value,
            initial_dict,
        )?
    } else {
        let mut dict_manager = DictManager::new();
        let base = dict_manager.new_default_dict(
            vm_proxy.segments,
            &mut vm_proxy.memory,
            &default_value,
            initial_dict,
        )?;
        exec_scopes_proxy.insert_value("dict_manager", Rc::new(RefCell::new(dict_manager)));
        base
    };
    insert_value_into_ap(&mut vm_proxy.memory, vm_proxy.run_context, base)
}

/* Implements hint:
   dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)
   dict_tracker.current_ptr += ids.DictAccess.SIZE
   ids.value = dict_tracker.data[ids.key]
*/
pub fn dict_read(
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let key = get_integer_from_var_name("key", &vm_proxy, ids_data, ap_tracking)?;
    let dict_ptr = get_ptr_from_var_name("dict_ptr", &vm_proxy, ids_data, ap_tracking)?;
    let dict_manager_ref = exec_scopes_proxy.get_dict_manager()?;
    let mut dict = dict_manager_ref.borrow_mut();
    let tracker = dict.get_tracker_mut(&dict_ptr)?;
    tracker.current_ptr.offset += DICT_ACCESS_SIZE;
    let value = tracker.get_value(key)?;
    insert_value_from_var_name("value", value.clone(), vm_proxy, ids_data, ap_tracking)
}

/* Implements hint:
    dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)
    dict_tracker.current_ptr += ids.DictAccess.SIZE
    ids.dict_ptr.prev_value = dict_tracker.data[ids.key]
    dict_tracker.data[ids.key] = ids.new_value
*/
pub fn dict_write(
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let key = get_integer_from_var_name("key", &vm_proxy, ids_data, ap_tracking)?;
    let new_value = get_integer_from_var_name("new_value", &vm_proxy, ids_data, ap_tracking)?;
    let dict_ptr = get_ptr_from_var_name("dict_ptr", &vm_proxy, ids_data, ap_tracking)?;
    //Get tracker for dictionary
    let dict_manager_ref = exec_scopes_proxy.get_dict_manager()?;
    let mut dict = dict_manager_ref.borrow_mut();
    let tracker = dict.get_tracker_mut(&dict_ptr)?;
    //dict_ptr is a pointer to a struct, with the ordered fields (key, prev_value, new_value),
    //dict_ptr.prev_value will be equal to dict_ptr + 1
    let dict_ptr_prev_value = dict_ptr + 1;
    //Tracker set to track next dictionary entry
    tracker.current_ptr.offset += DICT_ACCESS_SIZE;
    //Get previous value
    let prev_value = tracker.get_value(key)?.clone();
    //Insert new value into tracker
    tracker.insert_value(key, new_value);
    //Insert previous value into dict_ptr.prev_value
    //Addres for dict_ptr.prev_value should be dict_ptr* + 1 (defined above)
    vm_proxy
        .memory
        .insert_value(&dict_ptr_prev_value, prev_value)?;
    Ok(())
}

/* Implements hint:
    # Verify dict pointer and prev value.
        dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)
        current_value = dict_tracker.data[ids.key]
        assert current_value == ids.prev_value, \
            f'Wrong previous value in dict. Got {ids.prev_value}, expected {current_value}.'

        # Update value.
        dict_tracker.data[ids.key] = ids.new_value
        dict_tracker.current_ptr += ids.DictAccess.SIZE
*/
pub fn dict_update(
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let key = get_integer_from_var_name("key", &vm_proxy, ids_data, ap_tracking)?;
    let prev_value = get_integer_from_var_name("prev_value", &vm_proxy, ids_data, ap_tracking)?;
    let new_value = get_integer_from_var_name("new_value", &vm_proxy, ids_data, ap_tracking)?;
    let dict_ptr = get_ptr_from_var_name("dict_ptr", &vm_proxy, ids_data, ap_tracking)?;

    //Get tracker for dictionary
    let dict_manager_ref = exec_scopes_proxy.get_dict_manager()?;
    let mut dict = dict_manager_ref.borrow_mut();
    let tracker = dict.get_tracker_mut(&dict_ptr)?;
    //Check that prev_value is equal to the current value at the given key
    let current_value = tracker.get_value(key)?;
    if current_value != prev_value {
        return Err(VirtualMachineError::WrongPrevValue(
            prev_value.clone(),
            current_value.clone(),
            key.clone(),
        ));
    }
    //Update Value
    tracker.insert_value(key, new_value);
    tracker.current_ptr.offset += DICT_ACCESS_SIZE;
    Ok(())
}

/* Implements hint:
   # Prepare arguments for dict_new. In particular, the same dictionary values should be copied
   # to the new (squashed) dictionary.
   vm_enter_scope({
       # Make __dict_manager accessible.
       '__dict_manager': __dict_manager,
       # Create a copy of the dict, in case it changes in the future.
       'initial_dict': dict(__dict_manager.get_dict(ids.dict_accesses_end)),
   })
*/
pub fn dict_squash_copy_dict(
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let dict_accesses_end =
        get_ptr_from_var_name("dict_accesses_end", &vm_proxy, ids_data, ap_tracking)?;
    let dict_manager_ref = exec_scopes_proxy.get_dict_manager()?;
    let dict_manager = dict_manager_ref.borrow();
    let dict_copy: Box<dyn Any> = Box::new(
        dict_manager
            .get_tracker(&dict_accesses_end)?
            .get_dictionary_copy(),
    );
    exec_scopes_proxy.enter_scope(HashMap::from([
        (
            String::from("dict_manager"),
            any_box!(exec_scopes_proxy.get_dict_manager()?),
        ),
        (String::from("initial_dict"), dict_copy),
    ]));
    Ok(())
}

/* Implements Hint:
    # Update the DictTracker's current_ptr to point to the end of the squashed dict.
    __dict_manager.get_tracker(ids.squashed_dict_start).current_ptr = \
    ids.squashed_dict_end.address_
*/
pub fn dict_squash_update_ptr(
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let squashed_dict_start =
        get_ptr_from_var_name("squashed_dict_start", &vm_proxy, ids_data, ap_tracking)?;
    let squashed_dict_end =
        get_ptr_from_var_name("squashed_dict_end", &vm_proxy, ids_data, ap_tracking)?;
    exec_scopes_proxy
        .get_dict_manager()?
        .borrow_mut()
        .get_tracker_mut(&squashed_dict_start)?
        .current_ptr = squashed_dict_end;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::any_box;
    use crate::types::exec_scope::get_exec_scopes_proxy;
    use crate::types::exec_scope::ExecutionScopes;
    use crate::vm::hints::execute_hint::HintProcessorData;
    use crate::vm::vm_memory::memory::Memory;
    use std::collections::HashMap;

    use num_bigint::{BigInt, Sign};

    use crate::types::hint_executor::HintExecutor;
    use crate::types::relocatable::MaybeRelocatable;
    use crate::types::relocatable::Relocatable;
    use crate::utils::test_utils::*;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::vm::hints::dict_manager::DictTracker;
    use crate::vm::hints::dict_manager::{DictManager, Dictionary};
    use crate::vm::hints::execute_hint::BuiltinHintExecutor;
    use crate::vm::hints::execute_hint::{get_vm_proxy, HintReference};
    use crate::vm::vm_core::VirtualMachine;
    use crate::{bigint, relocatable};

    static HINT_EXECUTOR: BuiltinHintExecutor = BuiltinHintExecutor {};

    use super::*;
    #[test]
    fn run_dict_new_with_initial_dict_empty() {
        let hint_code = "if '__dict_manager' not in globals():\n    from starkware.cairo.common.dict import DictManager\n    __dict_manager = DictManager()\n\nmemory[ap] = __dict_manager.new_dict(segments, initial_dict)\ndel initial_dict";
        let mut vm = vm!();
        //Store initial dict in scope
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes
            .assign_or_update_variable("initial_dict", any_box!(HashMap::<BigInt, BigInt>::new()));
        //ids and references are not needed for this test
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        HINT_EXECUTOR
            .execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data))
            .expect("Error while executing hint");
        //first new segment is added for the dictionary
        assert_eq!(vm.segments.num_segments, 1);
        //new segment base (0,0) is inserted into ap (0,0)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from((0, 0))))
        );
        //Check the dict manager has a tracker for segment 0,
        //and that tracker contains the ptr (0,0) and an empty dict
        assert_eq!(
            exec_scopes_proxy
                .get_dict_manager()
                .unwrap()
                .borrow()
                .trackers
                .get(&0),
            Some(&DictTracker::new_empty(&relocatable!(0, 0)))
        );
    }

    #[test]
    fn run_dict_new_with_no_initial_dict() {
        let hint_code = "if '__dict_manager' not in globals():\n    from starkware.cairo.common.dict import DictManager\n    __dict_manager = DictManager()\n\nmemory[ap] = __dict_manager.new_dict(segments, initial_dict)\ndel initial_dict";
        let mut vm = vm!();
        //ids and references are not needed for this test
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
            Err(VirtualMachineError::NoInitialDict)
        );
    }

    #[test]
    fn run_dict_new_ap_is_taken() {
        let hint_code = "if '__dict_manager' not in globals():\n    from starkware.cairo.common.dict import DictManager\n    __dict_manager = DictManager()\n\nmemory[ap] = __dict_manager.new_dict(segments, initial_dict)\ndel initial_dict";
        let mut vm = vm!();
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes
            .assign_or_update_variable("initial_dict", any_box!(HashMap::<BigInt, BigInt>::new()));
        vm.memory = memory![((0, 0), 1)];
        //ids and references are not needed for this test
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((0, 0)),
                    MaybeRelocatable::from(bigint!(1)),
                    MaybeRelocatable::from((0, 0))
                )
            ))
        );
    }

    #[test]
    fn run_dict_read_valid() {
        let hint_code = "dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ndict_tracker.current_ptr += ids.DictAccess.SIZE\nids.value = dict_tracker.data[ids.key]";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        //Create tracker
        let mut tracker = DictTracker::new_empty(&relocatable!(1, 0));
        tracker.insert_value(&bigint!(5_i32), &bigint!(12_i32));
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        //Insert ids into memory
        vm.memory = memory![((0, 0), 5), ((0, 2), (1, 0))];
        vm.segments.add(&mut vm.memory, None);
        let ids_data = ids_data!["key", "value", "dict_ptr"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        let mut exec_scopes = ExecutionScopes::new();
        let mut exec_scopes_proxy = get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, &mut exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
        //Check that value variable (at address (0,1)) contains the proper value
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(12))))
        );
        //Check that the tracker's current_ptr has moved accordingly
        assert_eq!(
            exec_scopes_proxy
                .get_dict_manager()
                .unwrap()
                .borrow()
                .trackers
                .get(&1)
                .unwrap()
                .current_ptr,
            relocatable!(1, 3)
        );
    }

    #[test]
    fn run_dict_read_invalid_key() {
        let hint_code = "dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ndict_tracker.current_ptr += ids.DictAccess.SIZE\nids.value = dict_tracker.data[ids.key]";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        //Initialize dictionary
        let mut dictionary = HashMap::<BigInt, BigInt>::new();
        dictionary.insert(bigint!(5), bigint!(12));
        //Create tracker
        let mut tracker = DictTracker::new_empty(&relocatable!(1, 0));
        tracker.data = Dictionary::SimpleDictionary(dictionary);
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        //Insert ids into memory
        vm.memory = memory![((0, 0), 6), ((0, 2), (1, 0))];
        let ids_data = ids_data!["key", "value", "dict_ptr"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let mut exec_scopes = ExecutionScopes::new();
        let mut exec_scopes_proxy = get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, &mut exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::NoValueForKey(bigint!(6)))
        );
    }
    #[test]
    fn run_dict_read_no_tracker() {
        let hint_code = "dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ndict_tracker.current_ptr += ids.DictAccess.SIZE\nids.value = dict_tracker.data[ids.key]";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        //Create manager
        let dict_manager = DictManager::new();
        let mut exec_scopes = ExecutionScopes::new();
        let mut exec_scopes_proxy = get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        //Insert ids into memory
        vm.memory = memory![((0, 0), 6), ((0, 2), (1, 0))];
        vm.segments.add(&mut vm.memory, None);
        let ids_data = ids_data!["key", "value", "dict_ptr"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, &mut exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::NoDictTracker(1))
        );
    }

    #[test]
    fn run_default_dict_new_valid() {
        let hint_code = "if '__dict_manager' not in globals():\n    from starkware.cairo.common.dict import DictManager\n    __dict_manager = DictManager()\n\nmemory[ap] = __dict_manager.new_default_dict(segments, ids.default_value)";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 1));
        //insert ids.default_value into memory
        vm.memory = memory![((1, 0), 17)];
        let ids_data = ids_data!["default_value"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        let mut exec_scopes = ExecutionScopes::new();
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        HINT_EXECUTOR
            .execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data))
            .expect("Error while executing hint");
        //third new segment is added for the dictionary
        assert_eq!(vm.memory.data.len(), 3);
        //new segment base (0,0) is inserted into ap (0,0)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from((0, 0))))
        );
        //Check the dict manager has a tracker for segment 0,
        //and that tracker contains the ptr (0,0) and an empty dict
        assert_eq!(
            exec_scopes_proxy
                .get_dict_manager()
                .unwrap()
                .borrow()
                .trackers
                .get(&0),
            Some(&DictTracker::new_default_dict(
                &relocatable!(0, 0),
                &bigint!(17),
                None
            ))
        );
    }

    #[test]
    fn run_default_dict_new_no_default_value() {
        let hint_code = "if '__dict_manager' not in globals():\n    from starkware.cairo.common.dict import DictManager\n    __dict_manager = DictManager()\n\nmemory[ap] = __dict_manager.new_default_dict(segments, ids.default_value)";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        let ids_data = ids_data!["key", "value", "dict_ptr"];
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
    fn run_dict_write_default_valid_empty_dict() {
        let hint_code = "dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ndict_tracker.current_ptr += ids.DictAccess.SIZE\nids.dict_ptr.prev_value = dict_tracker.data[ids.key]\ndict_tracker.data[ids.key] = ids.new_value";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        //Create tracker
        //current_ptr = dict_ptr = (1, 0)
        let tracker = DictTracker::new_default_dict(&relocatable!(1, 0), &bigint!(2), None);
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        let mut exec_scopes_proxy = get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        //Insert ids into memory
        vm.memory = memory![((0, 0), 5), ((0, 1), 17)];
        vm.segments.add(&mut vm.memory, None);
        //ids.value (at (1, 0))
        //ids.dict_ptr (1, 0):
        //  dict_ptr.key = (1, 1)
        //  dict_ptr.prev_value = (1, 2)
        //  dict_ptr.new_value = (1, 3)
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        let ids_data = ids_data!["key", "new_value", "dict_ptr"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, &mut exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
        //Check that the dictionary was updated with the new key-value pair (5, 17)
        assert_eq!(
            exec_scopes_proxy
                .get_dict_manager()
                .unwrap()
                .borrow_mut()
                .trackers
                .get_mut(&1)
                .unwrap()
                .get_value(&bigint!(5)),
            Ok(&bigint!(17))
        );
        //Check that the tracker's current_ptr has moved accordingly
        assert_eq!(
            exec_scopes_proxy
                .get_dict_manager()
                .unwrap()
                .borrow()
                .trackers
                .get(&1)
                .unwrap()
                .current_ptr,
            relocatable!(1, 3)
        );
        //Check the value of dict_ptr.prev_value, should be equal to the default_value (2)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(2))))
        );
    }

    #[test]
    fn run_dict_write_default_valid_overwrite_value() {
        let hint_code = "dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ndict_tracker.current_ptr += ids.DictAccess.SIZE\nids.dict_ptr.prev_value = dict_tracker.data[ids.key]\ndict_tracker.data[ids.key] = ids.new_value";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        //Create tracker
        //current_ptr = dict_ptr = (1, 0)
        let mut tracker = DictTracker::new_default_dict(&relocatable!(1, 0), &bigint!(2), None);
        //Add key-value pair (5, 10)
        tracker.insert_value(&bigint!(5_i32), &bigint!(10_i32));
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        let mut exec_scopes_proxy = get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        //Insert ids into memory
        vm.memory = memory![((0, 0), 5), ((0, 1), 17), ((0, 2), (1, 0))];
        vm.segments.add(&mut vm.memory, None);
        //ids.value (at (1, 0))
        //ids.dict_ptr (1, 0):
        //  dict_ptr.key = (1, 1)
        //  dict_ptr.prev_value = (1, 2)
        //  dict_ptr.new_value = (1, 3)
        let ids_data = ids_data!["key", "new_value", "dict_ptr"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, &mut exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
        //Check that the dictionary was updated with the new key-value pair (5, 17)
        assert_eq!(
            exec_scopes_proxy
                .get_dict_manager()
                .unwrap()
                .borrow_mut()
                .trackers
                .get_mut(&1)
                .unwrap()
                .get_value(&bigint!(5)),
            Ok(&bigint!(17))
        );
        //Check that the tracker's current_ptr has moved accordingly
        assert_eq!(
            exec_scopes_proxy
                .get_dict_manager()
                .unwrap()
                .borrow()
                .trackers
                .get(&1)
                .unwrap()
                .current_ptr,
            relocatable!(1, 3)
        );
        //Check the value of dict_ptr.prev_value, should be equal to the previously inserted value (10)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(10))))
        );
    }

    #[test]
    fn run_dict_write_simple_valid_overwrite_value() {
        let hint_code = "dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ndict_tracker.current_ptr += ids.DictAccess.SIZE\nids.dict_ptr.prev_value = dict_tracker.data[ids.key]\ndict_tracker.data[ids.key] = ids.new_value";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        //Create tracker
        //current_ptr = dict_ptr = (1, 0)
        let mut tracker = DictTracker::new_empty(&relocatable!(1, 0));
        //Add key-value pair (5, 10)
        tracker.insert_value(&bigint!(5), &bigint!(10));
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        let mut exec_scopes_proxy = get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        //Insert ids into memory
        vm.memory = memory![((0, 0), 5), ((0, 1), 17), ((0, 2), (1, 0))];
        vm.segments.add(&mut vm.memory, None);
        //ids.value (at (1, 0))
        //ids.dict_ptr (1, 0):
        //  dict_ptr.key = (1, 1)
        //  dict_ptr.prev_value = (1, 2)
        //  dict_ptr.new_value = (1, 3)
        let ids_data = ids_data!["key", "new_value", "dict_ptr"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, &mut exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
        //Check that the dictionary was updated with the new key-value pair (5, 17)
        assert_eq!(
            exec_scopes_proxy
                .get_dict_manager()
                .unwrap()
                .borrow_mut()
                .trackers
                .get_mut(&1)
                .unwrap()
                .get_value(&bigint!(5)),
            Ok(&bigint!(17))
        );
        //Check that the tracker's current_ptr has moved accordingly
        assert_eq!(
            exec_scopes_proxy
                .get_dict_manager()
                .unwrap()
                .borrow()
                .trackers
                .get(&1)
                .unwrap()
                .current_ptr,
            relocatable!(1, 3)
        );
        //Check the value of dict_ptr.prev_value, should be equal to the previously inserted value (10)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(10))))
        );
    }

    #[test]
    fn run_dict_write_simple_valid_cant_write_new_key() {
        let hint_code = "dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ndict_tracker.current_ptr += ids.DictAccess.SIZE\nids.dict_ptr.prev_value = dict_tracker.data[ids.key]\ndict_tracker.data[ids.key] = ids.new_value";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        //Create tracker
        //current_ptr = dict_ptr = (1, 0)
        let tracker = DictTracker::new_empty(&relocatable!(1, 0));
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        let mut exec_scopes_proxy = get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        //Insert ids into memory
        vm.memory = memory![((0, 0), 5), ((0, 1), 17), ((0, 2), (1, 0))];
        vm.segments.add(&mut vm.memory, None);
        //ids.value (at (1, 0))
        //ids.dict_ptr (1, 0):
        //  dict_ptr.key = (1, 1)
        //  dict_ptr.prev_value = (1, 2)
        //  dict_ptr.new_value = (1, 3)
        let ids_data = ids_data!["key", "new_value", "dict_ptr"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, &mut exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::NoValueForKey(bigint!(5)))
        );
    }

    #[test]
    fn run_dict_update_simple_valid() {
        let hint_code = "# Verify dict pointer and prev value.\ndict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ncurrent_value = dict_tracker.data[ids.key]\nassert current_value == ids.prev_value, \\\n    f'Wrong previous value in dict. Got {ids.prev_value}, expected {current_value}.'\n\n# Update value.\ndict_tracker.data[ids.key] = ids.new_value\ndict_tracker.current_ptr += ids.DictAccess.SIZE";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Create tracker
        //current_ptr = dict_ptr = (1, 0)
        let mut tracker = DictTracker::new_empty(&relocatable!(1, 0));
        //Add key-value pair (5, 10)
        tracker.insert_value(&bigint!(5), &bigint!(10));
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        let mut exec_scopes_proxy = get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        //Insert ids into memory
        vm.memory = memory![((0, 0), 5), ((0, 1), 10), ((0, 2), 20), ((0, 3), (1, 0))];
        vm.segments.add(&mut vm.memory, None);
        //ids.dict_ptr (1, 0):
        //  dict_ptr.key = (1, 1)
        //  dict_ptr.prev_value = (1, 2)
        //  dict_ptr.new_value = (1, 3)
        let ids_data = ids_data!["key", "prev_value", "new_value", "dict_ptr"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, &mut exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
        //Check that the dictionary was updated with the new key-value pair (5, 20)
        assert_eq!(
            exec_scopes_proxy
                .get_dict_manager()
                .unwrap()
                .borrow_mut()
                .trackers
                .get_mut(&1)
                .unwrap()
                .get_value(&bigint!(5)),
            Ok(&bigint!(20))
        );
        //Check that the tracker's current_ptr has moved accordingly
        assert_eq!(
            exec_scopes_proxy
                .get_dict_manager()
                .unwrap()
                .borrow()
                .trackers
                .get(&1)
                .unwrap()
                .current_ptr,
            relocatable!(1, 3)
        );
    }

    #[test]
    fn run_dict_update_simple_valid_no_change() {
        let hint_code = "# Verify dict pointer and prev value.\ndict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ncurrent_value = dict_tracker.data[ids.key]\nassert current_value == ids.prev_value, \\\n    f'Wrong previous value in dict. Got {ids.prev_value}, expected {current_value}.'\n\n# Update value.\ndict_tracker.data[ids.key] = ids.new_value\ndict_tracker.current_ptr += ids.DictAccess.SIZE";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Create tracker
        //current_ptr = dict_ptr = (1, 0)
        let mut tracker = DictTracker::new_empty(&relocatable!(1, 0));
        //Add key-value pair (5, 10)
        tracker.insert_value(&bigint!(5), &bigint!(10));
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        let mut exec_scopes_proxy = get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        //Insert ids into memory
        vm.memory = memory![((0, 0), 5), ((0, 1), 10), ((0, 2), 10), ((0, 3), (1, 0))];
        vm.segments.add(&mut vm.memory, None);
        //ids.dict_ptr (1, 0):
        //  dict_ptr.key = (1, 1)
        //  dict_ptr.prev_value = (1, 2)
        //  dict_ptr.new_value = (1, 3)
        let ids_data = ids_data!["key", "prev_value", "new_value", "dict_ptr"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, &mut exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
        //Check that the dictionary was updated with the new key-value pair (5, 20)
        assert_eq!(
            exec_scopes_proxy
                .get_dict_manager()
                .unwrap()
                .borrow_mut()
                .trackers
                .get_mut(&1)
                .unwrap()
                .get_value(&bigint!(5)),
            Ok(&bigint!(10))
        );
        //Check that the tracker's current_ptr has moved accordingly
        assert_eq!(
            exec_scopes_proxy
                .get_dict_manager()
                .unwrap()
                .borrow()
                .trackers
                .get(&1)
                .unwrap()
                .current_ptr,
            relocatable!(1, 3)
        );
    }

    #[test]
    fn run_dict_update_simple_invalid_wrong_prev_key() {
        let hint_code = "# Verify dict pointer and prev value.\ndict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ncurrent_value = dict_tracker.data[ids.key]\nassert current_value == ids.prev_value, \\\n    f'Wrong previous value in dict. Got {ids.prev_value}, expected {current_value}.'\n\n# Update value.\ndict_tracker.data[ids.key] = ids.new_value\ndict_tracker.current_ptr += ids.DictAccess.SIZE";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Create tracker
        //current_ptr = dict_ptr = (1, 0)
        let mut tracker = DictTracker::new_empty(&relocatable!(1, 0));
        //Add key-value pair (5, 10)
        tracker.insert_value(&bigint!(5), &bigint!(10));
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        let mut exec_scopes_proxy = get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        //Insert ids into memory
        vm.memory = memory![((0, 0), 5), ((0, 1), 11), ((0, 2), 20), ((0, 3), (1, 0))];
        vm.segments.add(&mut vm.memory, None);
        //ids.dict_ptr (1, 0):
        //  dict_ptr.key = (1, 1)
        //  dict_ptr.prev_value = (1, 2)
        //  dict_ptr.new_value = (1, 3)
        let ids_data = ids_data!["key", "prev_value", "new_value", "dict_ptr"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, &mut exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::WrongPrevValue(
                bigint!(11),
                bigint!(10),
                bigint!(5)
            ))
        );
    }

    #[test]
    fn run_dict_update_simple_invalid_wrong_key() {
        let hint_code = "# Verify dict pointer and prev value.\ndict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ncurrent_value = dict_tracker.data[ids.key]\nassert current_value == ids.prev_value, \\\n    f'Wrong previous value in dict. Got {ids.prev_value}, expected {current_value}.'\n\n# Update value.\ndict_tracker.data[ids.key] = ids.new_value\ndict_tracker.current_ptr += ids.DictAccess.SIZE"
            ;
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Create tracker
        //current_ptr = dict_ptr = (1, 0)
        let mut tracker = DictTracker::new_empty(&relocatable!(1, 0));
        //Add key-value pair (5, 10)
        tracker.insert_value(&bigint!(5), &bigint!(10));
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        let mut exec_scopes_proxy = get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        //Insert ids into memory
        vm.memory = memory![((0, 0), 6), ((0, 1), 10), ((0, 2), 10), ((0, 3), (1, 0))];
        vm.segments.add(&mut vm.memory, None);
        //ids.dict_ptr (1, 0):
        //  dict_ptr.key = (1, 1)
        //  dict_ptr.prev_value = (1, 2)
        //  dict_ptr.new_value = (1, 3)
        let ids_data = ids_data!["key", "prev_value", "new_value", "dict_ptr"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, &mut exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::NoValueForKey(bigint!(6),))
        );
    }

    #[test]
    fn run_dict_update_default_valid() {
        let hint_code = "# Verify dict pointer and prev value.\ndict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ncurrent_value = dict_tracker.data[ids.key]\nassert current_value == ids.prev_value, \\\n    f'Wrong previous value in dict. Got {ids.prev_value}, expected {current_value}.'\n\n# Update value.\ndict_tracker.data[ids.key] = ids.new_value\ndict_tracker.current_ptr += ids.DictAccess.SIZE";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Create tracker
        //current_ptr = dict_ptr = (1, 0)
        let mut tracker =
            DictTracker::new_default_dict(&relocatable!(1, 0), &bigint!(17), Some(HashMap::new()));
        //Add key-value pair (5, 10)
        tracker.insert_value(&bigint!(5), &bigint!(10));
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        let mut exec_scopes_proxy = get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        //Insert ids into memory
        vm.memory = memory![((0, 0), 5), ((0, 1), 10), ((0, 2), 20), ((0, 3), (1, 0))];
        vm.segments.add(&mut vm.memory, None);
        //ids.dict_ptr (1, 0):
        //  dict_ptr.key = (1, 1)
        //  dict_ptr.prev_value = (1, 2)
        //  dict_ptr.new_value = (1, 3)
        let ids_data = ids_data!["key", "prev_value", "new_value", "dict_ptr"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, &mut exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
        //Check that the dictionary was updated with the new key-value pair (5, 20)
        assert_eq!(
            exec_scopes_proxy
                .get_dict_manager()
                .unwrap()
                .borrow_mut()
                .trackers
                .get_mut(&1)
                .unwrap()
                .get_value(&bigint!(5)),
            Ok(&bigint!(20))
        );
        //Check that the tracker's current_ptr has moved accordingly
        assert_eq!(
            exec_scopes_proxy
                .get_dict_manager()
                .unwrap()
                .borrow()
                .trackers
                .get(&1)
                .unwrap()
                .current_ptr,
            relocatable!(1, 3)
        );
    }

    #[test]
    fn run_dict_update_default_valid_no_change() {
        let hint_code = "# Verify dict pointer and prev value.\ndict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ncurrent_value = dict_tracker.data[ids.key]\nassert current_value == ids.prev_value, \\\n    f'Wrong previous value in dict. Got {ids.prev_value}, expected {current_value}.'\n\n# Update value.\ndict_tracker.data[ids.key] = ids.new_value\ndict_tracker.current_ptr += ids.DictAccess.SIZE";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Create tracker
        //current_ptr = dict_ptr = (1, 0)
        let mut tracker =
            DictTracker::new_default_dict(&relocatable!(1, 0), &bigint!(17), Some(HashMap::new()));
        //Add key-value pair (5, 10)
        tracker.insert_value(&bigint!(5), &bigint!(10));
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        let mut exec_scopes_proxy = get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        //Insert ids into memory
        vm.memory = memory![((0, 0), 5), ((0, 1), 10), ((0, 2), 10), ((0, 3), (1, 0))];
        vm.segments.add(&mut vm.memory, None);
        //ids.dict_ptr (1, 0):
        //  dict_ptr.key = (1, 1)
        //  dict_ptr.prev_value = (1, 2)
        //  dict_ptr.new_value = (1, 3)
        let ids_data = ids_data!["key", "prev_value", "new_value", "dict_ptr"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, &mut exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
        //Check that the dictionary was updated with the new key-value pair (5, 20)
        assert_eq!(
            exec_scopes_proxy
                .get_dict_manager()
                .unwrap()
                .borrow_mut()
                .trackers
                .get_mut(&1)
                .unwrap()
                .get_value(&bigint!(5)),
            Ok(&bigint!(10))
        );
        //Check that the tracker's current_ptr has moved accordingly
        assert_eq!(
            exec_scopes_proxy
                .get_dict_manager()
                .unwrap()
                .borrow()
                .trackers
                .get(&1)
                .unwrap()
                .current_ptr,
            relocatable!(1, 3)
        );
    }

    #[test]
    fn run_dict_update_default_invalid_wrong_prev_key() {
        let hint_code = "# Verify dict pointer and prev value.\ndict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ncurrent_value = dict_tracker.data[ids.key]\nassert current_value == ids.prev_value, \\\n    f'Wrong previous value in dict. Got {ids.prev_value}, expected {current_value}.'\n\n# Update value.\ndict_tracker.data[ids.key] = ids.new_value\ndict_tracker.current_ptr += ids.DictAccess.SIZE";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Create tracker
        //current_ptr = dict_ptr = (1, 0)
        let mut tracker =
            DictTracker::new_default_dict(&relocatable!(1, 0), &bigint!(17), Some(HashMap::new()));
        //Add key-value pair (5, 10)
        tracker.insert_value(&bigint!(5), &bigint!(10));
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        let mut exec_scopes_proxy = get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        //Insert ids into memory
        vm.memory = memory![((0, 0), 5), ((0, 1), 11), ((0, 2), 10), ((0, 3), (1, 0))];
        vm.segments.add(&mut vm.memory, None);
        //ids.dict_ptr (1, 0):
        //  dict_ptr.key = (1, 1)
        //  dict_ptr.prev_value = (1, 2)
        //  dict_ptr.new_value = (1, 3)
        let ids_data = ids_data!["key", "prev_value", "new_value", "dict_ptr"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, &mut exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::WrongPrevValue(
                bigint!(11),
                bigint!(10),
                bigint!(5)
            ))
        );
    }

    #[test]
    fn run_dict_update_default_invalid_wrong_key() {
        let hint_code = "# Verify dict pointer and prev value.\ndict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ncurrent_value = dict_tracker.data[ids.key]\nassert current_value == ids.prev_value, \\\n    f'Wrong previous value in dict. Got {ids.prev_value}, expected {current_value}.'\n\n# Update value.\ndict_tracker.data[ids.key] = ids.new_value\ndict_tracker.current_ptr += ids.DictAccess.SIZE";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Create tracker
        //current_ptr = dict_ptr = (1, 0)
        let mut tracker =
            DictTracker::new_default_dict(&relocatable!(1, 0), &bigint!(17), Some(HashMap::new()));
        //Add key-value pair (5, 10)
        tracker.insert_value(&bigint!(5), &bigint!(10));
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        let mut exec_scopes_proxy = get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        //Insert ids into memory
        vm.memory = memory![((0, 0), 6), ((0, 1), 10), ((0, 2), 10), ((0, 3), (1, 0))];
        vm.segments.add(&mut vm.memory, None);
        //ids.dict_ptr (1, 0):
        //  dict_ptr.key = (1, 1)
        //  dict_ptr.prev_value = (1, 2)
        //  dict_ptr.new_value = (1, 3)
        let ids_data = ids_data!["key", "prev_value", "new_value", "dict_ptr"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, &mut exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::WrongPrevValue(
                bigint!(10),
                bigint!(17),
                bigint!(6)
            ))
        );
    }

    #[test]
    fn run_dict_update_default_valid_no_key_prev_value_equals_default() {
        let hint_code = "# Verify dict pointer and prev value.\ndict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ncurrent_value = dict_tracker.data[ids.key]\nassert current_value == ids.prev_value, \\\n    f'Wrong previous value in dict. Got {ids.prev_value}, expected {current_value}.'\n\n# Update value.\ndict_tracker.data[ids.key] = ids.new_value\ndict_tracker.current_ptr += ids.DictAccess.SIZE";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Create tracker
        //current_ptr = dict_ptr = (1, 0)
        let tracker =
            DictTracker::new_default_dict(&relocatable!(1, 0), &bigint!(17), Some(HashMap::new()));
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        let mut exec_scopes_proxy = get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        //Insert ids into memory
        vm.memory = memory![((0, 0), 5), ((0, 1), 17), ((0, 2), 20), ((0, 3), (1, 0))];
        vm.segments.add(&mut vm.memory, None);
        //ids.dict_ptr (1, 0):
        //  dict_ptr.key = (1, 1)
        //  dict_ptr.prev_value = (1, 2)
        //  dict_ptr.new_value = (1, 3)
        let ids_data = ids_data!["key", "prev_value", "new_value", "dict_ptr"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, &mut exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
        //Check that the dictionary was updated with the new key-value pair (5, 20)
        assert_eq!(
            exec_scopes_proxy
                .get_dict_manager()
                .unwrap()
                .borrow_mut()
                .trackers
                .get_mut(&1)
                .unwrap()
                .get_value(&bigint!(5)),
            Ok(&bigint!(20))
        );
        //Check that the tracker's current_ptr has moved accordingly
        assert_eq!(
            exec_scopes_proxy
                .get_dict_manager()
                .unwrap()
                .borrow()
                .trackers
                .get(&1)
                .unwrap()
                .current_ptr,
            relocatable!(1, 3)
        );
    }

    #[test]
    fn run_dict_squash_copy_dict_valid_empty_dict() {
        let hint_code = "# Prepare arguments for dict_new. In particular, the same dictionary values should be copied\n# to the new (squashed) dictionary.\nvm_enter_scope({\n    # Make __dict_manager accessible.\n    '__dict_manager': __dict_manager,\n    # Create a copy of the dict, in case it changes in the future.\n    'initial_dict': dict(__dict_manager.get_dict(ids.dict_accesses_end)),\n})";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Initialize dictionary
        let dictionary = HashMap::<BigInt, BigInt>::new();
        //Create tracker
        let mut tracker = DictTracker::new_empty(&relocatable!(1, 0));
        tracker.data = Dictionary::SimpleDictionary(dictionary);
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        //ids.dict_access
        vm.memory = memory![((0, 0), (1, 0))];
        vm.segments.add(&mut vm.memory, None);
        let ids_data = ids_data!["dict_access_end"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let mut exec_scopes = ExecutionScopes::new();
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
        //Check that a new exec scope has been created
        assert_eq!(exec_scopes.data.len(), 2);
        //Check that this scope contains the expected initial-dict
        let variables = exec_scopes.get_local_variables().unwrap();
        assert_eq!(variables.len(), 2); //Two of them, as DictManager is also there
        assert_eq!(
            variables
                .get("initial_dict")
                .unwrap()
                .downcast_ref::<HashMap<BigInt, BigInt>>(),
            Some(&HashMap::<BigInt, BigInt>::new())
        );
    }

    #[test]
    fn run_dict_squash_copy_dict_valid_non_empty_dict() {
        let hint_code = "# Prepare arguments for dict_new. In particular, the same dictionary values should be copied\n# to the new (squashed) dictionary.\nvm_enter_scope({\n    # Make __dict_manager accessible.\n    '__dict_manager': __dict_manager,\n    # Create a copy of the dict, in case it changes in the future.\n    'initial_dict': dict(__dict_manager.get_dict(ids.dict_accesses_end)),\n})";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Initialize dictionary
        let mut dictionary = HashMap::<BigInt, BigInt>::new();
        dictionary.insert(bigint!(1), bigint!(2));
        dictionary.insert(bigint!(3), bigint!(4));
        dictionary.insert(bigint!(5), bigint!(6));
        //Create tracker
        let mut tracker = DictTracker::new_empty(&relocatable!(1, 0));
        tracker.data = Dictionary::SimpleDictionary(dictionary);
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        vm.memory = memory![((0, 0), (1, 0))];
        vm.segments.add(&mut vm.memory, None);
        let ids_data = ids_data!["dict_access_end"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let mut exec_scopes = ExecutionScopes::new();
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
        //Check that a new exec scope has been created
        assert_eq!(exec_scopes.data.len(), 2);
        //Check that this scope contains the expected initial-dict
        let variables = exec_scopes.get_local_variables().unwrap();
        assert_eq!(variables.len(), 2); //Two of them, as DictManager is also there
        assert_eq!(
            variables
                .get("initial_dict")
                .unwrap()
                .downcast_ref::<HashMap<BigInt, BigInt>>(),
            Some(&HashMap::from([
                (bigint!(1), bigint!(2)),
                (bigint!(3), bigint!(4)),
                (bigint!(5), bigint!(6))
            ]))
        );
    }

    #[test]
    fn run_dict_squash_copy_dict_invalid_no_dict() {
        let hint_code = "# Prepare arguments for dict_new. In particular, the same dictionary values should be copied\n# to the new (squashed) dictionary.\nvm_enter_scope({\n    # Make __dict_manager accessible.\n    '__dict_manager': __dict_manager,\n    # Create a copy of the dict, in case it changes in the future.\n    'initial_dict': dict(__dict_manager.get_dict(ids.dict_accesses_end)),\n})";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Create manager
        let dict_manager = DictManager::new();
        let mut exec_scopes = ExecutionScopes::new();
        let mut exec_scopes_proxy = get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        vm.memory = memory![((0, 0), (1, 0))];
        vm.segments.add(&mut vm.memory, None);
        let ids_data = ids_data!["dict_accesses_end"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, &mut exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::NoDictTracker(1))
        );
    }

    #[test]
    fn run_dict_squash_update_ptr_no_tracker() {
        let hint_code = "# Update the DictTracker's current_ptr to point to the end of the squashed dict.\n__dict_manager.get_tracker(ids.squashed_dict_start).current_ptr = \\\n    ids.squashed_dict_end.address_";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Create manager
        let dict_manager = DictManager::new();
        let mut exec_scopes = ExecutionScopes::new();
        let mut exec_scopes_proxy = get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        vm.memory = memory![((0, 0), (1, 0)), ((0, 1), (1, 3))];
        vm.segments.add(&mut vm.memory, None);
        //Create ids
        let ids_data = ids_data!["squashed_dict_start", "squashed_dict_end"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, &mut exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::NoDictTracker(1))
        );
    }

    #[test]
    fn run_dict_squash_update_ptr_valid() {
        let hint_code = "# Update the DictTracker's current_ptr to point to the end of the squashed dict.\n__dict_manager.get_tracker(ids.squashed_dict_start).current_ptr = \\\n    ids.squashed_dict_end.address_";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Initialize dictionary
        let mut dictionary = HashMap::<BigInt, BigInt>::new();
        dictionary.insert(bigint!(1), bigint!(2));
        //Create tracker
        let mut tracker = DictTracker::new_empty(&relocatable!(1, 0));
        tracker.data = Dictionary::SimpleDictionary(dictionary);
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        let mut exec_scopes_proxy = get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        //ids.squash_dict_start
        vm.memory = memory![((0, 0), (1, 0)), ((0, 1), (1, 3))];
        vm.segments.add(&mut vm.memory, None);
        //Create ids
        let ids_data = ids_data!["squashed_dict_start", "squashed_dict_end"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, &mut exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );
        //Check the updated pointer
        assert_eq!(
            exec_scopes_proxy
                .get_dict_manager()
                .unwrap()
                .borrow()
                .get_tracker(&relocatable!(1, 3))
                .unwrap()
                .current_ptr,
            relocatable!(1, 3)
        );
    }

    #[test]
    fn run_dict_squash_update_ptr_mismatched_dict_ptr() {
        let hint_code = "# Update the DictTracker's current_ptr to point to the end of the squashed dict.\n__dict_manager.get_tracker(ids.squashed_dict_start).current_ptr = \\\n    ids.squashed_dict_end.address_";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Initialize dictionary
        let mut dictionary = HashMap::<BigInt, BigInt>::new();
        dictionary.insert(bigint!(1), bigint!(2));
        //Create tracker
        let mut tracker = DictTracker::new_empty(&relocatable!(1, 0));
        tracker.data = Dictionary::SimpleDictionary(dictionary);
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        let mut exec_scopes = ExecutionScopes::new();
        let mut exec_scopes_proxy = get_exec_scopes_proxy(&mut exec_scopes);
        add_dict_manager!(exec_scopes_proxy, dict_manager);
        vm.memory = memory![((0, 0), (1, 3)), ((0, 1), (1, 6))];
        vm.segments.add(&mut vm.memory, None);
        //Create ids
        let ids_data = ids_data!["squashed_dict_start", "squashed_dict_end"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, &mut exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::MismatchedDictPtr(
                relocatable!(1, 0),
                relocatable!(1, 3)
            ))
        );
    }
}
