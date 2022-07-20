use crate::bigint;
use crate::serde::deserialize_program::ApTracking;
use crate::types::relocatable::MaybeRelocatable;
use crate::vm::{
    errors::vm_errors::VirtualMachineError, hints::hint_utils::get_address_from_reference,
    runners::builtin_runner::RangeCheckBuiltinRunner, vm_core::VirtualMachine,
};
use num_bigint::BigInt;
use num_traits::{FromPrimitive, Signed, ToPrimitive};
use std::collections::HashMap;

pub fn find_element(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let (array_ptr_ref, elm_size_ref, n_elms_ref, index_ref, key_ref) = if let (
        Some(array_ptr_ref),
        Some(elm_size_ref),
        Some(n_elms_ref),
        Some(index_ref),
        Some(key_ref),
    ) = (
        ids.get("array_ptr"),
        ids.get("elm_size"),
        ids.get("n_elms"),
        ids.get("index"),
        ids.get("key"),
    ) {
        (array_ptr_ref, elm_size_ref, n_elms_ref, index_ref, key_ref)
    } else {
        return Err(VirtualMachineError::IncorrectIds(
            vec!["array_ptr", "elm_size", "n_elms", "index", "key"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ids.into_keys().collect(),
        ));
    };

    let (array_ptr_addr, elm_size_addr, n_elms_addr, index_addr, key_addr) = if let (
        Ok(Some(array_ptr_addr)),
        Ok(Some(elm_size_addr)),
        Ok(Some(n_elms_addr)),
        Ok(Some(index_addr)),
        Ok(Some(key_addr)),
    ) = (
        get_address_from_reference(
            array_ptr_ref,
            &vm.references,
            &vm.run_context,
            vm,
            hint_ap_tracking,
        ),
        get_address_from_reference(
            elm_size_ref,
            &vm.references,
            &vm.run_context,
            vm,
            hint_ap_tracking,
        ),
        get_address_from_reference(
            n_elms_ref,
            &vm.references,
            &vm.run_context,
            vm,
            hint_ap_tracking,
        ),
        get_address_from_reference(
            index_ref,
            &vm.references,
            &vm.run_context,
            vm,
            hint_ap_tracking,
        ),
        get_address_from_reference(
            key_ref,
            &vm.references,
            &vm.run_context,
            vm,
            hint_ap_tracking,
        ),
    ) {
        (
            array_ptr_addr,
            elm_size_addr,
            n_elms_addr,
            index_addr,
            key_addr,
        )
    } else {
        return Err(VirtualMachineError::FailedToGetIds);
    };

    match (
        vm.memory.get(&array_ptr_addr),
        vm.memory.get(&elm_size_addr),
        vm.memory.get(&n_elms_addr),
        vm.memory.get(&index_addr),
        vm.memory.get(&key_addr),
    ) {
        (
            Ok(_),
            Ok(Some(maybe_rel_elm_size)),
            Ok(Some(maybe_rel_n_elms)),
            Ok(_),
            Ok(Some(maybe_rel_key)),
        ) => {
            for (name, builtin) in &vm.builtin_runners {
                //Check that range_check_builtin is present
                let _builtin = match builtin.as_any().downcast_ref::<RangeCheckBuiltinRunner>() {
                    Some(b) => b,
                    None => return Err(VirtualMachineError::NoRangeCheckBuiltin),
                };

                if name == &"range_check".to_string() {
                    let elm_size = if let MaybeRelocatable::Int(ref elm_size) = maybe_rel_elm_size {
                        elm_size
                    } else {
                        return Err(VirtualMachineError::ExpectedInteger(
                            maybe_rel_elm_size.clone(),
                        ));
                    };

                    if !elm_size.is_positive() {
                        return Err(VirtualMachineError::ValueOutOfRange(elm_size.clone()));
                    }

                    if let Some(find_element_index_value) = vm.find_element_index.clone() {
                        vm.find_element_index = None;
                        let array_start = vm
                            .memory
                            .get(&array_ptr_addr)
                            .map_err(VirtualMachineError::MemoryError)?
                            .ok_or(VirtualMachineError::FindElemNoFoundKey)?;

                        let found_key =
                            vm.memory
                                .get(&array_start.add_int_mod(
                                    &(elm_size * &find_element_index_value),
                                    &vm.prime,
                                )?)
                                .map_err(VirtualMachineError::MemoryError)?
                                .ok_or(VirtualMachineError::FindElemNoFoundKey)?;

                        if found_key != maybe_rel_key {
                            return Err(VirtualMachineError::InvalidIndex(
                                find_element_index_value,
                                maybe_rel_key.clone(),
                                found_key.clone(),
                            ));
                        }

                        return vm
                            .memory
                            .insert(
                                &index_addr,
                                &MaybeRelocatable::Int(find_element_index_value),
                            )
                            .map_err(VirtualMachineError::MemoryError);
                    } else {
                        let n_elms = if let MaybeRelocatable::Int(ref n_elms) = maybe_rel_n_elms {
                            n_elms
                        } else {
                            return Err(VirtualMachineError::ExpectedInteger(
                                maybe_rel_n_elms.clone(),
                            ));
                        };

                        if n_elms.is_negative() {
                            return Err(VirtualMachineError::ValueOutOfRange(n_elms.clone()));
                        }

                        if let Some(find_element_max_size) = &vm.find_element_max_size {
                            if n_elms > find_element_max_size {
                                return Err(VirtualMachineError::FindElemMaxSize(
                                    find_element_max_size.clone(),
                                    n_elms.clone(),
                                ));
                            }
                        }

                        let n_elms_iter: i32 = n_elms
                            .to_i32()
                            .ok_or(VirtualMachineError::OffsetExceeded(n_elms.clone()))?;

                        let array_start = vm
                            .memory
                            .get(&array_ptr_addr)
                            .map_err(VirtualMachineError::MemoryError)?
                            .ok_or(VirtualMachineError::FindElemNoFoundKey)?;

                        for i in 0..n_elms_iter {
                            let iter_addr =
                                &array_start.add_int_mod(&(elm_size * bigint!(i)), &vm.prime)?;
                            let iter_key = vm
                                .memory
                                .get(iter_addr)
                                .map_err(VirtualMachineError::MemoryError)?
                                .ok_or(VirtualMachineError::FindElemNoFoundKey)?;

                            if iter_key == maybe_rel_key {
                                return vm
                                    .memory
                                    .insert(&index_addr, &MaybeRelocatable::Int(bigint!(i)))
                                    .map_err(VirtualMachineError::MemoryError);
                            }
                        }

                        return Err(VirtualMachineError::FindElemKeyNotFound(
                            maybe_rel_key.clone(),
                        ));
                    }
                }
            }

            Err(VirtualMachineError::NoRangeCheckBuiltin)
        }
        _ => Err(VirtualMachineError::FailedToGetIds),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::instruction::Register;
    use crate::vm::hints::execute_hint::{execute_hint, HintReference};
    use crate::vm::runners::builtin_runner::OutputBuiltinRunner;
    use num_bigint::Sign;

    const FIND_ELEMENT_HINT: &[u8] = "array_ptr = ids.array_ptr\nelm_size = ids.elm_size\nassert isinstance(elm_size, int) and elm_size > 0, \\\n    f'Invalid value for elm_size. Got: {elm_size}.'\nkey = ids.key\n\nif '__find_element_index' in globals():\n    ids.index = __find_element_index\n    found_key = memory[array_ptr + elm_size * __find_element_index]\n    assert found_key == key, \\\n        f'Invalid index found in __find_element_index. index: {__find_element_index}, ' \\\n        f'expected key {key}, found key: {found_key}.'\n    # Delete __find_element_index to make sure it's not used for the next calls.\n    del __find_element_index\nelse:\n    n_elms = ids.n_elms\n    assert isinstance(n_elms, int) and n_elms >= 0, \\\n        f'Invalid value for n_elms. Got: {n_elms}.'\n    if '__find_element_max_size' in globals():\n        assert n_elms <= __find_element_max_size, \\\n            f'find_element() can only be used with n_elms<={__find_element_max_size}. ' \\\n            f'Got: n_elms={n_elms}.'\n\n    for i in range(n_elms):\n        if memory[array_ptr + elm_size * i] == key:\n            ids.index = i\n            break\n    else:\n        raise ValueError(f'Key {key} was not found.')".as_bytes();

    fn init_vm_ids() -> (VirtualMachine, HashMap<String, BigInt>) {
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );

        vm.run_context.fp = MaybeRelocatable::from((0, 4));

        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        /* array_ptr = (1,0) -> [Struct{1, 2}, Struct{3, 4}]
          elm_size = 2
          n_elms = 2
          index = None. Should become 1
          key = 3
        */
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(bigint!(3)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(3)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from(bigint!(4)),
            )
            .expect("Unexpected memory insert fail");

        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                4,
                HintReference {
                    register: Register::FP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
        ]);

        let mut ids = HashMap::<String, BigInt>::new();
        for (i, s) in ["array_ptr", "elm_size", "n_elms", "index", "key"]
            .iter()
            .enumerate()
        {
            ids.insert(s.to_string(), bigint!(i as i32));
        }

        (vm, ids)
    }

    #[test]
    fn element_found_by_search() {
        let (mut vm, ids) = init_vm_ids();

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Ok(())
        );

        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 3))),
            Ok(Some(&MaybeRelocatable::Int(bigint!(1))))
        )
    }

    #[test]
    fn element_found_by_global() {
        let (mut vm, ids) = init_vm_ids();
        vm.find_element_index = Some(bigint!(1));

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Ok(())
        );

        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 3))),
            Ok(Some(&MaybeRelocatable::Int(bigint!(1))))
        )
    }

    #[test]
    fn element_not_found_search() {
        let (mut vm, ids) = init_vm_ids();
        vm.memory.data[0][4] = Some(MaybeRelocatable::from(bigint!(7)));

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::FindElemKeyNotFound(
                MaybeRelocatable::Int(bigint!(7))
            ))
        );
    }

    #[test]
    fn element_not_found_global() {
        let (mut vm, ids) = init_vm_ids();
        vm.find_element_index = Some(bigint!(2));

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::FindElemNoFoundKey)
        );
    }

    #[test]
    fn find_elm_incorrect_ids() {
        let (mut vm, mut ids) = init_vm_ids();
        ids.remove(&"array_ptr".to_string());

        assert!(matches!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::IncorrectIds(_, _))
        ));
    }

    #[test]
    fn find_elm_failed_ids_get_addres() {
        let (mut vm, ids) = init_vm_ids();
        vm.references.insert(
            0,
            HintReference {
                register: Register::FP,
                offset1: -7,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
            },
        );

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn find_elm_failed_ids_get_from_mem() {
        let (mut vm, ids) = init_vm_ids();
        vm.memory.data[0][2] = None;

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn find_elm_builtin_is_none() {
        let (mut vm, ids) = init_vm_ids();
        _ = vm.builtin_runners.pop();

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn find_elm_range_check_not_present() {
        let (mut vm, ids) = init_vm_ids();
        _ = vm.builtin_runners.pop();
        vm.builtin_runners.push((
            "output".to_string(),
            Box::new(OutputBuiltinRunner::new(true)),
        ));

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn find_elm_not_int_elm_size() {
        let (mut vm, ids) = init_vm_ids();
        vm.memory.data[0][1] = Some(MaybeRelocatable::from((7, 8)));

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((7, 8))
            ))
        );
    }

    #[test]
    fn find_elm_zero_elm_size() {
        let (mut vm, ids) = init_vm_ids();
        vm.memory.data[0][1] = Some(MaybeRelocatable::Int(bigint!(0)));

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::ValueOutOfRange(bigint!(0)))
        );
    }

    #[test]
    fn find_elm_negative_elm_size() {
        let (mut vm, ids) = init_vm_ids();
        vm.memory.data[0][1] = Some(MaybeRelocatable::Int(bigint!(-1)));

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::ValueOutOfRange(bigint!(-1)))
        );
    }

    #[test]
    fn find_elm_not_int_n_elms() {
        let (mut vm, ids) = init_vm_ids();
        let relocatable = MaybeRelocatable::from((1, 2));
        vm.memory.data[0][2] = Some(relocatable.clone());

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(relocatable))
        );
    }

    #[test]
    fn find_elm_negative_n_elms() {
        let (mut vm, ids) = init_vm_ids();
        vm.memory.data[0][2] = Some(MaybeRelocatable::Int(bigint!(-1)));

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::ValueOutOfRange(bigint!(-1)))
        );
    }

    #[test]
    fn find_elm_n_elms_gt_max_size() {
        let (mut vm, ids) = init_vm_ids();
        vm.find_element_max_size = Some(bigint!(1));

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::FindElemMaxSize(bigint!(1), bigint!(2)))
        );
    }
}
