use crate::vm::{errors::vm_errors::VirtualMachineError, vm_core::VirtualMachine};

use super::dict_manager::DictManager;

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
