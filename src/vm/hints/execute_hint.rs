use std::collections::HashMap;

use num_bigint::BigInt;

use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::hint_utils::{add_segment, is_nn};
use crate::vm::vm_core::VirtualMachine;

pub fn execute_hint(
    vm: &mut VirtualMachine,
    hint_code: &[u8],
    ids: Option<HashMap<String, BigInt>>,
) -> Result<(), VirtualMachineError> {
    match std::str::from_utf8(hint_code) {
        Ok("memory[ap] = segments.add()") => add_segment(vm),
        Ok("memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1") => {
            if let Some(ids) = ids {
                is_nn(vm, ids)
            } else {
                Err(VirtualMachineError::NoIdsError(String::from(
                    "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1",
                )))
            }
        }
        Ok(hint_code) => Err(VirtualMachineError::UnknownHinError(String::from(
            hint_code,
        ))),
        Err(_) => Err(VirtualMachineError::HintException(
            vm.run_context.pc.clone(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::types::relocatable::MaybeRelocatable;
    use crate::{bigint, vm::runners::builtin_runner::RangeCheckBuiltinRunner};
    use num_bigint::{BigInt, Sign};
    use num_traits::FromPrimitive;

    use super::*;
    #[test]
    fn run_alloc_hint_empty_memory() {
        let hint_code = "memory[ap] = segments.add()".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            //ap value is (0,0)
            Vec::new(),
        );
        execute_hint(&mut vm, hint_code, None).expect("Error while executing hint");
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
        let hint_code = "memory[ap] = segments.add()".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
        //Add 3 segments to the memory
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        vm.run_context.ap = MaybeRelocatable::from((2, 6));
        execute_hint(&mut vm, hint_code, None).expect("Error while executing hint");
        //Segment N°4 is added
        assert_eq!(vm.segments.num_segments, 4);
        //new segment base (3,0) is inserted into ap (2,6)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((2, 6))),
            Ok(Some(&MaybeRelocatable::from((3, 0))))
        );
    }

    #[test]
    fn run_unknown_hint() {
        let hint_code = "random_invalid_code".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
        assert_eq!(
            execute_hint(&mut vm, hint_code, None),
            Err(VirtualMachineError::UnknownHinError(
                String::from_utf8(hint_code.to_vec()).unwrap()
            ))
        );
    }

    #[test]
    fn run_is_nn_hint_false() {
        let hint_code =
            "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(-1));
        //Execute the hint
        execute_hint(&mut vm, hint_code, Some(ids)).expect("Error while executing hint");
        //Check that ap now contains false (0)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
    }

    #[test]
    fn run_is_nn_hint_true() {
        let hint_code =
            "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(1));
        //Execute the hint
        execute_hint(&mut vm, hint_code, Some(ids)).expect("Error while executing hint");
        //Check that ap now contains false (0)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1))))
        );
    }
}
