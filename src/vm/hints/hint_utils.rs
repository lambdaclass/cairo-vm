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
    ids: HashMap<String, MaybeRelocatable>,
) -> Result<(), VirtualMachineError> {
    //Check that ids contains the needed values
    if let Some(a_addr) = ids.get(&String::from("a")) {
        //Check that the ids are in memory
        match vm.memory.get(a_addr) {
            Ok(Some(maybe_rel_a)) => {
                //Check that the value at the ids address is an Int
                if let &MaybeRelocatable::Int(ref a) = maybe_rel_a {
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
                                            return Err(VirtualMachineError::MemoryError(
                                                memory_error,
                                            ))
                                        }
                                    }
                                }
                            }
                        }
                    }
                    return Err(VirtualMachineError::NoRangeCheckBuiltin);
                } else {
                    return Err(VirtualMachineError::ExpectedInteger(a_addr.clone()));
                }
            }
            Ok(None) => return Err(VirtualMachineError::MemoryGet(a_addr.clone())),
            Err(memory_error) => return Err(VirtualMachineError::MemoryError(memory_error)),
        };
    } else {
        Err(VirtualMachineError::IncorrectIds(
            vec![String::from("a")],
            ids.into_keys().collect(),
        ))
    }
}
//Implements hint:from starkware.cairo.common.math_utils import assert_integer
//        assert_integer(ids.a)
//        assert_integer(ids.b)
//        a = ids.a % PRIME
//        b = ids.b % PRIME
//        assert a <= b, f'a = {a} is not less than or equal to b = {b}.'

//        ids.small_inputs = int(
//            a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)
pub fn assert_le_felt(
    vm: &mut VirtualMachine,
    ids: HashMap<String, MaybeRelocatable>,
) -> Result<(), VirtualMachineError> {
    //Check that ids contains the needed values
    if let (Some(a_addr), Some(b_addr), Some(small_inputs_addr)) = (
        ids.get(&String::from("a")),
        ids.get(&String::from("b")),
        ids.get(&String::from("small_inputs")),
    ) {
        //Check that the ids are in memory (except for small_inputs which is local, and should contain None)
        //small_inputs needs to be None, as we cant change it value otherwise
        match (
            vm.memory.get(a_addr),
            vm.memory.get(b_addr),
            vm.memory.get(small_inputs_addr),
        ) {
            (Ok(Some(maybe_rel_a)), Ok(Some(maybe_rel_b)), Ok(None)) => {
                //Check that the values at the ids address are Int
                if let (&MaybeRelocatable::Int(ref a), &MaybeRelocatable::Int(ref b)) =
                    (maybe_rel_a, maybe_rel_b)
                {
                    for (name, builtin) in &vm.builtin_runners {
                        //Check that range_check_builtin is present
                        if name == &String::from("range_check") {
                            match builtin.as_any().downcast_ref::<RangeCheckBuiltinRunner>() {
                                None => return Err(VirtualMachineError::NoRangeCheckBuiltin),
                                Some(builtin) => {
                                    //Assert a <= b
                                    if a % vm.prime.clone() > b % vm.prime.clone() {
                                        return Err(VirtualMachineError::NonLeFelt(
                                            a.clone(),
                                            b.clone(),
                                        ));
                                    }
                                    //Calculate value of small_inputs
                                    let mut value = bigint!(0);
                                    if *a < builtin._bound && (a - b) < builtin._bound {
                                        value = bigint!(1);
                                    }
                                    match vm
                                        .memory
                                        .insert(&small_inputs_addr, &MaybeRelocatable::from(value))
                                    {
                                        Ok(_) => return Ok(()),
                                        Err(memory_error) => {
                                            return Err(VirtualMachineError::MemoryError(
                                                memory_error,
                                            ))
                                        }
                                    }
                                }
                            }
                        }
                    }
                    return Err(VirtualMachineError::NoRangeCheckBuiltin);
                } else {
                    return Err(VirtualMachineError::ExpectedInteger(a_addr.clone()));
                }
            }
            _ => return Err(VirtualMachineError::FailedToGetIds),
        }
    } else {
        Err(VirtualMachineError::IncorrectIds(
            vec![
                String::from("a"),
                String::from("b"),
                String::from("small_inputs"),
            ],
            ids.into_keys().collect(),
        ))
    }
}
