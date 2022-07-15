use std::collections::HashMap;

use num_bigint::BigInt;

use crate::{
    types::relocatable::MaybeRelocatable,
    vm::{errors::vm_errors::VirtualMachineError, vm_core::VirtualMachine},
};

use super::{dict_manager::DictManager, hint_utils::get_address_from_reference};

const DICT_ACCESS_SIZE: usize = 3;
/*Implements hint:

   if '__dict_manager' not in globals():
           from starkware.cairo.common.dict import DictManager
           __dict_manager = DictManager()

       memory[ap] = __dict_manager.new_dict(segments, initial_dict)
       del initial_dict

For now, the functionality to create a dictionary from a previously defined initial_dict (using a hint)
is not available, an empty dict is created always
*/
pub fn dict_new(vm: &mut VirtualMachine) -> Result<(), VirtualMachineError> {
    if vm.dict_manager.is_none() {
        vm.dict_manager = Some(DictManager::new());
    }
    //This unwrap will never fail as dict_manager is checked for None value beforehand
    let base = vm
        .dict_manager
        .as_mut()
        .unwrap()
        .new_dict(&mut vm.segments, &mut vm.memory)?;
    vm.memory
        .insert(&vm.run_context.ap, &base)
        .map_err(VirtualMachineError::MemoryError)
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
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    if vm.dict_manager.is_none() {
        vm.dict_manager = Some(DictManager::new());
    }
    //Check that ids contains the reference id for each variable used by the hint
    let default_value_ref = if let Some(default_value_ref) = ids.get(&String::from("default_value"))
    {
        default_value_ref
    } else {
        return Err(VirtualMachineError::IncorrectIds(
            vec![String::from("default_value")],
            ids.into_keys().collect(),
        ));
    };
    //Check that each reference id corresponds to a value in the reference manager
    let default_value_addr = if let Some(default_value_addr) =
        get_address_from_reference(default_value_ref, &vm.references, &vm.run_context)
    {
        default_value_addr
    } else {
        return Err(VirtualMachineError::FailedToGetReference(
            default_value_ref.clone(),
        ));
    };
    //Check that ids.default_value is an Int value
    let default_value = if let Ok(Some(&MaybeRelocatable::Int(ref default_value))) =
        vm.memory.get(&default_value_addr)
    {
        default_value.clone()
    } else {
        return Err(VirtualMachineError::ExpectedInteger(default_value_addr));
    };
    //This unwrap will never fail as dict_manager is checked for None value beforehand
    let base = vm.dict_manager.as_mut().unwrap().new_default_dict(
        &mut vm.segments,
        &mut vm.memory,
        &default_value,
    )?;
    vm.memory
        .insert(&vm.run_context.ap, &base)
        .map_err(VirtualMachineError::MemoryError)
}

/* Implements hint:
   dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)
   dict_tracker.current_ptr += ids.DictAccess.SIZE
   ids.value = dict_tracker.data[ids.key]
*/
pub fn dict_read(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    if vm.dict_manager.is_none() {
        return Err(VirtualMachineError::NoDictManager);
    }
    //Check that ids contains the reference id for each variable used by the hint
    let (key_ref, value_ref, dict_ptr_ref) =
        if let (Some(key_ref), Some(value_ref), Some(dict_ptr_ref)) = (
            ids.get(&String::from("key")),
            ids.get(&String::from("value")),
            ids.get(&String::from("dict_ptr")),
        ) {
            (key_ref, value_ref, dict_ptr_ref)
        } else {
            return Err(VirtualMachineError::IncorrectIds(
                vec![
                    String::from("key"),
                    String::from("value"),
                    String::from("dict_ptr"),
                ],
                ids.into_keys().collect(),
            ));
        };
    //Check that each reference id corresponds to a value in the reference manager
    let (key_addr, value_addr, dict_ptr_addr) =
        if let (Some(key_addr), Some(value_addr), Some(dict_ptr_addr)) = (
            get_address_from_reference(key_ref, &vm.references, &vm.run_context),
            get_address_from_reference(value_ref, &vm.references, &vm.run_context),
            get_address_from_reference(dict_ptr_ref, &vm.references, &vm.run_context),
        ) {
            (key_addr, value_addr, dict_ptr_addr)
        } else {
            return Err(VirtualMachineError::FailedToGetIds);
        };
    //Check that these addresses point to the data types needed
    match (
        vm.memory.get(&key_addr),
        vm.memory.get(&value_addr),
        vm.memory.get(&dict_ptr_addr),
    ) {
        (
            Ok(Some(MaybeRelocatable::Int(key))),
            Ok(_),
            Ok(Some(MaybeRelocatable::RelocatableValue(dict_ptr))),
        ) => {
            let tracker = if let Some(tracker) = vm
                .dict_manager
                .as_mut()
                .unwrap()
                .trackers
                .get_mut(&dict_ptr.segment_index)
            {
                tracker
            } else {
                return Err(VirtualMachineError::NoDictTracker(dict_ptr.segment_index));
            };
            tracker.current_ptr.offset += DICT_ACCESS_SIZE;
            let value = if let Some(value) = tracker.data.get(key) {
                value
            } else {
                return Err(VirtualMachineError::NoValueForKey(key.clone()));
            };
            vm.memory
                .insert(&value_addr, &MaybeRelocatable::from(value.clone()))
                .map_err(VirtualMachineError::MemoryError)
        }
        _ => Err(VirtualMachineError::FailedToGetIds),
    }
}

/* Implements hint:
    dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)
    dict_tracker.current_ptr += ids.DictAccess.SIZE
    ids.dict_ptr.prev_value = dict_tracker.data[ids.key]
    dict_tracker.data[ids.key] = ids.new_value
*/
pub fn dict_write(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    if vm.dict_manager.is_none() {
        return Err(VirtualMachineError::NoDictManager);
    }
    //Check that ids contains the reference id for each variable used by the hint
    let (key_ref, value_ref, dict_ptr_ref) =
        if let (Some(key_ref), Some(value_ref), Some(dict_ptr_ref)) = (
            ids.get(&String::from("key")),
            ids.get(&String::from("new_value")),
            ids.get(&String::from("dict_ptr")),
        ) {
            (key_ref, value_ref, dict_ptr_ref)
        } else {
            return Err(VirtualMachineError::IncorrectIds(
                vec![
                    String::from("key"),
                    String::from("new_value"),
                    String::from("dict_ptr"),
                ],
                ids.into_keys().collect(),
            ));
        };
    //Check that each reference id corresponds to a value in the reference manager
    let (key_addr, value_addr, dict_ptr_addr) =
        if let (Some(key_addr), Some(value_addr), Some(dict_ptr_addr)) = (
            get_address_from_reference(key_ref, &vm.references, &vm.run_context),
            get_address_from_reference(value_ref, &vm.references, &vm.run_context),
            get_address_from_reference(dict_ptr_ref, &vm.references, &vm.run_context),
        ) {
            (key_addr, value_addr, dict_ptr_addr)
        } else {
            return Err(VirtualMachineError::FailedToGetIds);
        };
    //Check that these addresses point to the data types needed
    let (key, new_value, dict_ptr) = if let (
        Ok(Some(MaybeRelocatable::Int(ref key))),
        Ok(Some(MaybeRelocatable::Int(new_value))),
        Ok(Some(MaybeRelocatable::RelocatableValue(dict_ptr))),
    ) = (
        vm.memory.get(&key_addr),
        vm.memory.get(&value_addr),
        vm.memory.get(&dict_ptr_addr),
    ) {
        (key, new_value, dict_ptr)
    } else {
        return Err(VirtualMachineError::FailedToGetIds);
    };
    //Auxiliary copy values
    let key_copy = key.clone();
    let value_copy = new_value.clone();

    //Get tracker for dictionary
    let tracker = if let Some(tracker) = vm
        .dict_manager
        .as_mut()
        .unwrap()
        .trackers
        .get_mut(&dict_ptr.segment_index)
    {
        tracker
    } else {
        return Err(VirtualMachineError::NoDictTracker(dict_ptr.segment_index));
    };

    //dict_ptr is a pointer to a struct, with the ordered fields (key, prev_value, new_value),
    //dict_ptr.prev_value will be equal to dict_ptr + 1
    let dict_ptr_prev_value =
        MaybeRelocatable::RelocatableValue(dict_ptr.clone()).add_usize_mod(1, None);
    //Tracker set to track next dictionary entry
    tracker.current_ptr.offset += DICT_ACCESS_SIZE;
    //Get previous value
    let prev_value = if let Some(value) = tracker.data.get(key) {
        value
    } else {
        return Err(VirtualMachineError::NoValueForKey(key.clone()));
    };
    //Insert previous value into dict_ptr.prev_value
    //Addres for dict_ptr.prev_value should be dict_ptr* + 1 (defined above)
    vm.memory
        .insert(
            &dict_ptr_prev_value,
            &MaybeRelocatable::from(prev_value.clone()),
        )
        .map_err(VirtualMachineError::MemoryError)?;
    //Insert new value into tracker
    tracker.data.insert(&key_copy, &value_copy);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use num_bigint::{BigInt, Sign};
    use num_traits::FromPrimitive;

    use crate::types::instruction::Register;
    use crate::types::relocatable::Relocatable;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::vm::hints::dict_manager::Dictionary;
    use crate::vm::hints::execute_hint::HintReference;
    use crate::{bigint, relocatable};
    use crate::{
        types::relocatable::MaybeRelocatable,
        vm::hints::{dict_manager::DictTracker, execute_hint::execute_hint},
    };

    use super::*;
    #[test]
    fn run_dict_new() {
        let hint_code = "if '__dict_manager' not in globals():\nfrom starkware.cairo.common.dict import DictManager\n__dict_manager = DictManager()\n\nmemory[ap] = __dict_manager.new_dict(segments, initial_dict)\ndel initial_dict".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            //ap value is (0,0)
            Vec::new(),
        );
        //ids and references are not needed for this test
        execute_hint(&mut vm, hint_code, HashMap::new()).expect("Error while executing hint");
        //first new segment is added for the dictionary
        assert_eq!(vm.segments.num_segments, 1);
        //new segment base (0,0) is inserted into ap (0,0)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from((0, 0))))
        );
        //Check there is a dict_manager
        assert_ne!(vm.dict_manager, None);
        //Check the dict manager has a tracker for segment 0,
        //and that tracker contains the ptr (0,0) and an empty dict
        assert_eq!(
            vm.dict_manager.unwrap().trackers.get(&0),
            Some(&DictTracker::new_empty(&relocatable!(0, 0)))
        );
    }

    #[test]
    fn run_dict_new_ap_is_taken() {
        let hint_code = "if '__dict_manager' not in globals():\nfrom starkware.cairo.common.dict import DictManager\n__dict_manager = DictManager()\n\nmemory[ap] = __dict_manager.new_dict(segments, initial_dict)\ndel initial_dict".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            //ap value is (0,0)
            Vec::new(),
        );
        vm.segments.add(&mut vm.memory, None);
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //ids and references are not needed for this test
        assert_eq!(
            execute_hint(&mut vm, hint_code, HashMap::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((0, 0)),
                    MaybeRelocatable::from(bigint!(1)),
                    MaybeRelocatable::from((1, 0))
                )
            ))
        );
    }

    #[test]
    fn run_dict_read_valid() {
        let hint_code = "dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ndict_tracker.current_ptr += ids.DictAccess.SIZE\nids.value = dict_tracker.data[ids.key]"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        //Initialize dictionary
        let mut dictionary = Dictionary::SimpleDictionary(HashMap::<BigInt, BigInt>::new());
        dictionary.insert(&bigint!(5), &bigint!(12));
        //Create tracker
        let mut tracker = DictTracker::new_empty(&relocatable!(1, 0));
        tracker.data = dictionary;
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        vm.dict_manager = Some(dict_manager);
        //Insert ids into memory
        //ids.key
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();
        //ids.value
        //ids.dict_ptr
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("key"), bigint!(0));
        ids.insert(String::from("value"), bigint!(1));
        ids.insert(String::from("dict_ptr"), bigint!(2));
        //Create references
        vm.references = vec![
            HintReference {
                register: Register::FP,
                offset: -3,
            },
            HintReference {
                register: Register::FP,
                offset: -2,
            },
            HintReference {
                register: Register::FP,
                offset: -1,
            },
        ];
        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids), Ok(()));
        //Check that value variable (at address (0,1)) contains the proper value
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(12))))
        );
        //Check that the tracker's current_ptr has moved accordingly
        assert_eq!(
            vm.dict_manager
                .as_mut()
                .unwrap()
                .trackers
                .get(&1)
                .unwrap()
                .current_ptr,
            relocatable!(1, 3)
        );
    }

    #[test]
    fn run_dict_read_invalid_key() {
        let hint_code = "dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ndict_tracker.current_ptr += ids.DictAccess.SIZE\nids.value = dict_tracker.data[ids.key]"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
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
        vm.dict_manager = Some(dict_manager);
        //Insert ids into memory
        //ids.key
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(6)),
            )
            .unwrap();
        //ids.value
        //ids.dict_ptr
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("key"), bigint!(0));
        ids.insert(String::from("value"), bigint!(1));
        ids.insert(String::from("dict_ptr"), bigint!(2));
        //Create references
        vm.references = vec![
            HintReference {
                register: Register::FP,
                offset: -3,
            },
            HintReference {
                register: Register::FP,
                offset: -2,
            },
            HintReference {
                register: Register::FP,
                offset: -1,
            },
        ];
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::NoValueForKey(bigint!(6)))
        );
    }
    #[test]
    fn run_dict_read_no_tracker() {
        let hint_code = "dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ndict_tracker.current_ptr += ids.DictAccess.SIZE\nids.value = dict_tracker.data[ids.key]"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        //Create manager
        let dict_manager = DictManager::new();
        vm.dict_manager = Some(dict_manager);
        //Insert ids into memory
        //ids.key
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(6)),
            )
            .unwrap();
        //ids.value
        //ids.dict_ptr
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("key"), bigint!(0));
        ids.insert(String::from("value"), bigint!(1));
        ids.insert(String::from("dict_ptr"), bigint!(2));
        //Create references
        vm.references = vec![
            HintReference {
                register: Register::FP,
                offset: -3,
            },
            HintReference {
                register: Register::FP,
                offset: -2,
            },
            HintReference {
                register: Register::FP,
                offset: -1,
            },
        ];
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::NoDictTracker(1))
        );
    }

    #[test]
    fn run_dict_read_no_manager() {
        let hint_code = "dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ndict_tracker.current_ptr += ids.DictAccess.SIZE\nids.value = dict_tracker.data[ids.key]"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        //Insert ids into memory
        //ids.key
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(6)),
            )
            .unwrap();
        //ids.value
        //ids.dict_ptr
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("key"), bigint!(0));
        ids.insert(String::from("value"), bigint!(1));
        ids.insert(String::from("dict_ptr"), bigint!(2));
        //Create references
        vm.references = vec![
            HintReference {
                register: Register::FP,
                offset: -3,
            },
            HintReference {
                register: Register::FP,
                offset: -2,
            },
            HintReference {
                register: Register::FP,
                offset: -1,
            },
        ];
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::NoDictManager)
        );
    }

    #[test]
    fn run_default_dict_new_valid() {
        let hint_code = "if '__dict_manager' not in globals():\n    from starkware.cairo.common.dict import DictManager\n    __dict_manager = DictManager()\n\nmemory[ap] = __dict_manager.new_default_dict(segments, ids.default_value)".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            //ap value is (0,0)
            Vec::new(),
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 1));
        //insert ids.default_value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(bigint!(17)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("default_value"), bigint!(0));
        //Create references
        vm.references = vec![HintReference {
            register: Register::FP,
            offset: -1,
        }];
        execute_hint(&mut vm, hint_code, ids).expect("Error while executing hint");
        //third new segment is added for the dictionary
        assert_eq!(vm.segments.num_segments, 3);
        //new segment base (2,0) is inserted into ap (0,0)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from((2, 0))))
        );
        //Check there is a dict_manager
        assert_ne!(vm.dict_manager, None);
        //Check the dict manager has a tracker for segment 2,
        //and that tracker contains the ptr (2,0) and an empty dict
        assert_eq!(
            vm.dict_manager.unwrap().trackers.get(&2),
            Some(&DictTracker::new_default_dict(
                &relocatable!(2, 0),
                &bigint!(17)
            ))
        );
    }

    #[test]
    fn run_default_dict_new_no_default_value() {
        let hint_code = "if '__dict_manager' not in globals():\n    from starkware.cairo.common.dict import DictManager\n    __dict_manager = DictManager()\n\nmemory[ap] = __dict_manager.new_default_dict(segments, ids.default_value)".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            //ap value is (0,0)
            Vec::new(),
        );
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("default_value"), bigint!(0));
        //Create references
        vm.references = vec![HintReference {
            register: Register::FP,
            offset: -1,
        }];
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn run_dict_write_valid_empty_dict() {
        let hint_code = "dict_tracker = __dict_manager.get_tracker(ids.dict_ptr)\ndict_tracker.current_ptr += ids.DictAccess.SIZE\nids.dict_ptr.prev_value = dict_tracker.data[ids.key]\ndict_tracker.data[ids.key] = ids.new_value"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        //Create tracker
        //current_ptr = dict_ptr = (1, 0)
        let tracker = DictTracker::new_default_dict(&relocatable!(1, 0), &bigint!(2));
        //Create manager
        let mut dict_manager = DictManager::new();
        dict_manager.trackers.insert(1, tracker);
        vm.dict_manager = Some(dict_manager);
        //Insert ids into memory
        //ids.key
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();
        //ids.value
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(17)),
            )
            .unwrap();
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
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("key"), bigint!(0));
        ids.insert(String::from("new_value"), bigint!(1));
        ids.insert(String::from("dict_ptr"), bigint!(2));
        //Create references
        vm.references = vec![
            HintReference {
                register: Register::FP,
                offset: -3,
            },
            HintReference {
                register: Register::FP,
                offset: -2,
            },
            HintReference {
                register: Register::FP,
                offset: -1,
            },
        ];
        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids), Ok(()));
        //Check that the dictionary was updated with the new key-value pair (5, 17)
        assert_eq!(
            vm.dict_manager
                .as_mut()
                .unwrap()
                .trackers
                .get_mut(&1)
                .unwrap()
                .data
                .get(&bigint!(5)),
            Some(&bigint!(17))
        );
        //Check that the tracker's current_ptr has moved accordingly
        assert_eq!(
            vm.dict_manager
                .as_mut()
                .unwrap()
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
}
