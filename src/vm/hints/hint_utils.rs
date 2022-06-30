use num_bigint::BigInt;
use num_traits::FromPrimitive;
use std::collections::HashMap;

use crate::{
    bigint,
    types::relocatable::MaybeRelocatable,
    vm::{
        errors::vm_errors::VirtualMachineError, runners::builtin_runner::RangeCheckBuiltinRunner,
        vm_core::VirtualMachine,
    },
};

pub fn add_segment(vm: &mut VirtualMachine) -> Result<(), VirtualMachineError> {
    let new_segment_base =
        MaybeRelocatable::RelocatableValue(vm.segments.add(&mut vm.memory, None));
    match vm.memory.insert(&vm.run_context.ap, &new_segment_base) {
        Ok(_) => Ok(()),
        Err(memory_error) => Err(VirtualMachineError::MemoryError(memory_error)),
    }
}

//Implements hint: memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1
pub fn is_nn(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    //Check that ids contains the needed values
    if let Some(a) = ids.get(&String::from("a")) {
        for (name, builtin) in &vm.builtin_runners {
            //Check that range_check_builtin is present
            if name == &String::from("range_check") {
                match builtin.as_any().downcast_ref::<RangeCheckBuiltinRunner>() {
                    None => return Err(VirtualMachineError::NoRangeCheckBuiltin),
                    Some(builtin) => {
                        //Main logic (assert a is not negative and within the expected range)
                        let mut value = bigint!(0);
                        if *a > bigint!(0) && *a < vm.prime && *a < builtin._bound {
                            value = bigint!(1);
                        }
                        match vm
                            .memory
                            .insert(&vm.run_context.ap, &MaybeRelocatable::from(value))
                        {
                            Ok(_) => return Ok(()),
                            Err(memory_error) => {
                                return Err(VirtualMachineError::MemoryError(memory_error))
                            }
                        }
                    }
                }
            }
        }
        return Err(VirtualMachineError::NoRangeCheckBuiltin);
    }
    Err(VirtualMachineError::IncorrectIds(
        vec![String::from("a")],
        ids.into_keys().collect(),
    ))
}
