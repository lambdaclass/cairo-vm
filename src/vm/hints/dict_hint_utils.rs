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
            let value = if let Some(value) = tracker.data.get(&key) {
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use num_bigint::{BigInt, Sign};
    use num_traits::FromPrimitive;

    use crate::types::relocatable::Relocatable;
    use crate::vm::errors::memory_errors::MemoryError;
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
}
