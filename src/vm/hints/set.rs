use crate::bigint;
use crate::types::relocatable::MaybeRelocatable;
use crate::vm::hints::hint_utils::get_address_from_reference;
use crate::vm::{
    errors::vm_errors::VirtualMachineError, runners::builtin_runner::RangeCheckBuiltinRunner,
    vm_core::VirtualMachine,
};
use num_bigint::{BigInt, ToBigInt};
use num_traits::{FromPrimitive, ToPrimitive};
use std::collections::HashMap;

pub fn set_add(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    //Check that ids contains the reference id for each variable used by the hint
    let (is_elm_in_set_ref, index_ref, set_ptr_ref, elm_size_ref, elm_ptr_ref, set_end_ptr_ref) =
        if let (
            Some(is_elm_in_set_ref),
            Some(index_ref),
            Some(set_ptr_ref),
            Some(elm_size_ref),
            Some(elm_ptr_ref),
            Some(set_end_ptr_ref),
        ) = (
            ids.get(&String::from("is_elm_in_set")),
            ids.get(&String::from("index")),
            ids.get(&String::from("set_ptr")),
            ids.get(&String::from("elm_size")),
            ids.get(&String::from("elm_ptr")),
            ids.get(&String::from("set_end_ptr")),
        ) {
            (
                is_elm_in_set_ref,
                index_ref,
                set_ptr_ref,
                elm_size_ref,
                elm_ptr_ref,
                set_end_ptr_ref,
            )
        } else {
            return Err(VirtualMachineError::IncorrectIds(
                vec![
                    String::from("is_elm_in_set"),
                    String::from("index"),
                    String::from("set_ptr"),
                    String::from("elm_size"),
                    String::from("elm_ptr"),
                    String::from("set_end_ptr"),
                ],
                ids.into_keys().collect(),
            ));
        };
    //Check that each reference id corresponds to a value in the reference manager
    let (
        is_elm_in_set_addr,
        index_addr,
        set_ptr_addr,
        elm_size_addr,
        elm_ptr_addr,
        set_end_ptr_addr,
    ) = if let (
        Some(is_elm_in_set_addr),
        Some(index_addr),
        Some(set_ptr_addr),
        Some(elm_size_addr),
        Some(elm_ptr_addr),
        Some(set_end_ptr_addr),
    ) = (
        get_address_from_reference(is_elm_in_set_ref, &vm.references, &vm.run_context, vm),
        get_address_from_reference(index_ref, &vm.references, &vm.run_context, vm),
        get_address_from_reference(set_ptr_ref, &vm.references, &vm.run_context, vm),
        get_address_from_reference(elm_size_ref, &vm.references, &vm.run_context, vm),
        get_address_from_reference(elm_ptr_ref, &vm.references, &vm.run_context, vm),
        get_address_from_reference(set_end_ptr_ref, &vm.references, &vm.run_context, vm),
    ) {
        (
            is_elm_in_set_addr,
            index_addr,
            set_ptr_addr,
            elm_size_addr,
            elm_ptr_addr,
            set_end_ptr_addr,
        )
    } else {
        return Err(VirtualMachineError::FailedToGetIds);
    };
    match (
        vm.memory.get(&is_elm_in_set_addr),
        vm.memory.get(&index_addr),
        vm.memory.get(&set_ptr_addr),
        vm.memory.get(&elm_size_addr),
        vm.memory.get(&elm_ptr_addr),
        vm.memory.get(&set_end_ptr_addr),
    ) {
        (
            Ok(_),
            Ok(_),
            Ok(Some(maybe_rel_set_ptr)),
            Ok(Some(maybe_rel_elm_size)),
            Ok(Some(_)),
            Ok(Some(maybe_rel_set_end_ptr)),
        ) => {
            for (name, builtin) in &vm.builtin_runners {
                //Check that range_check_builtin is present
                if name == &String::from("range_check") {
                    match builtin.as_any().downcast_ref::<RangeCheckBuiltinRunner>() {
                        Some(_) => {
                            let elm_size =
                                if let &MaybeRelocatable::Int(ref elm_size) = maybe_rel_elm_size {
                                    elm_size
                                } else {
                                    return Err(VirtualMachineError::ExpectedInteger(
                                        elm_size_addr.clone(),
                                    ));
                                };

                            let elm_usize =
                                if let &MaybeRelocatable::Int(ref elm_size) = maybe_rel_elm_size {
                                    match elm_size.to_usize() {
                                        Some(elm_usize) => elm_usize,
                                        None => {
                                            return Err(VirtualMachineError::ValueOutOfRange(
                                                elm_size.clone(),
                                            ))
                                        }
                                    }
                                } else {
                                    return Err(VirtualMachineError::ExpectedInteger(
                                        elm_size_addr.clone(),
                                    ));
                                };

                            let set_ptr =
                                if let &MaybeRelocatable::Int(ref set_ptr) = maybe_rel_set_ptr {
                                    set_ptr
                                } else {
                                    return Err(VirtualMachineError::ExpectedInteger(
                                        set_ptr_addr.clone(),
                                    ));
                                };

                            let set_end_ptr = if let &MaybeRelocatable::Int(ref set_end_ptr) =
                                maybe_rel_set_end_ptr
                            {
                                set_end_ptr
                            } else {
                                return Err(VirtualMachineError::ExpectedInteger(
                                    set_end_ptr_addr.clone(),
                                ));
                            };
                            // Main logic

                            if set_ptr > set_end_ptr {
                                return Err(VirtualMachineError::OutOfValidRange(
                                    set_ptr.clone(),
                                    set_end_ptr.clone(),
                                ));
                            }

                            let elm = match vm.memory.get_range(&elm_ptr_addr, elm_usize) {
                                Ok(vec) => vec,
                                Err(e) => return Err(VirtualMachineError::MemoryError(e)),
                            };

                            let set_size = match (set_end_ptr - set_ptr).to_usize() {
                                Some(size) => size,
                                None => {
                                    return Err(VirtualMachineError::ValueOutOfRange(
                                        elm_size.clone(),
                                    ))
                                }
                            };

                            for i in (0..set_size).step_by(elm_usize) {
                                let set_iter = match vm
                                    .memory
                                    .get_range(&elm_ptr_addr.add_usize_mod(i, None), elm_usize)
                                {
                                    Ok(vec) => vec,
                                    Err(e) => return Err(VirtualMachineError::MemoryError(e)),
                                };
                                if elm == set_iter {
                                    let index = match (i / elm_usize).to_bigint() {
                                        Some(elm_usize) => elm_usize,
                                        None => {
                                            return Err(VirtualMachineError::ValueOutOfRange(
                                                elm_size.clone(),
                                            ))
                                        }
                                    };
                                    return match (
                                        vm.memory
                                            .insert(&index_addr, &MaybeRelocatable::Int(index))
                                            .map_err(VirtualMachineError::MemoryError),
                                        vm.memory
                                            .insert(
                                                &is_elm_in_set_addr,
                                                &MaybeRelocatable::Int(bigint!(1)),
                                            )
                                            .map_err(VirtualMachineError::MemoryError),
                                    ) {
                                        (Ok(_), Ok(_)) => Ok(()),
                                        (Err(e), _) | (_, Err(e)) => Err(e),
                                    };
                                }
                            }

                            return vm
                                .memory
                                .insert(&is_elm_in_set_addr, &MaybeRelocatable::Int(bigint!(0)))
                                .map_err(VirtualMachineError::MemoryError);
                        }
                        None => {
                            return Err(VirtualMachineError::NoRangeCheckBuiltin);
                        }
                    }
                };
            }
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        }
        _ => Err(VirtualMachineError::FailedToGetIds),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::hints::hint_utils::execute_hint;

    #[test]
    fn set_add_successful() {
        let hint_code = "assert ids.elm_size > 0\n        assert ids.set_ptr <= ids.set_end_ptr\n        elm_list = memory.get_range(ids.elm_ptr, ids.elm_size)\n        for i in range(0, ids.set_end_ptr - ids.set_ptr, ids.elm_size):\n            if memory.get_range(ids.set_ptr + i, ids.elm_size) == elm_list:\n                ids.index = i // ids.elm_size\n                ids.is_elm_in_set = 1\n                break\n        else:\n            ids.is_elm_in_set = 0".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );

        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("is_elm_in_set"), bigint!(0));
        ids.insert(String::from("index"), bigint!(1));
        ids.insert(String::from("set_ptr"), bigint!(2));
        ids.insert(String::from("elm_size"), bigint!(3));
        ids.insert(String::from("elm_ptr"), bigint!(4));
        ids.insert(String::from("set_end_ptr"), bigint!(5));
    }
}
