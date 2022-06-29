use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::hint_utils::add_segment;
use crate::vm::vm_core::VirtualMachine;

pub fn execute_hint(vm: &mut VirtualMachine, hint_code: &[u8]) -> Result<(), VirtualMachineError> {
    match std::str::from_utf8(hint_code).unwrap() {
        "memory[ap] = segments.add()" => add_segment(vm),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::{BigInt, Sign};

    use crate::types::relocatable::MaybeRelocatable;

    use super::*;
    #[test]
    fn run_alloc_hint_empty_memory() {
        let hint_code = "memory[ap] = segments.add()".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            //ap value is (0,0)
            Vec::new(),
        );
        execute_hint(&mut vm, hint_code).expect("Error while executing hint");
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
        execute_hint(&mut vm, hint_code).expect("Error while executing hint");
        //Segment N°4 is added
        assert_eq!(vm.segments.num_segments, 4);
        //new segment base (3,0) is inserted into ap (2,6)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((2, 6))),
            Ok(Some(&MaybeRelocatable::from((3, 0))))
        );
    }
}
