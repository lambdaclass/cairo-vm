use crate::bigint;
use crate::serde::deserialize_program::ApTracking;
use crate::types::{relocatable::MaybeRelocatable, exec_scope::PyValueType};
use crate::vm::{
    errors::vm_errors::VirtualMachineError, hints::hint_utils::get_address_from_var_name,
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
    let array_ptr_addr = get_address_from_var_name("array_ptr", ids.clone(), vm, hint_ap_tracking)?;
    let elm_size_addr = get_address_from_var_name("elm_size", ids.clone(), vm, hint_ap_tracking)?;
    let n_elms_addr = get_address_from_var_name("n_elms", ids.clone(), vm, hint_ap_tracking)?;
    let index_addr = get_address_from_var_name("index", ids.clone(), vm, hint_ap_tracking)?;
    let key_addr = get_address_from_var_name("key", ids, vm, hint_ap_tracking)?;

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
            let _ = vm.builtin_runners.iter()
                .find(|(name, _)| name.as_str() == "range_check")
                .ok_or(VirtualMachineError::NoRangeCheckBuiltin)?
                .1
                .as_any().downcast_ref::<RangeCheckBuiltinRunner>()
                .ok_or(VirtualMachineError::NoRangeCheckBuiltin)?;

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

            let find_element_index = if let Some(variables) = vm.exec_scopes.get_local_variables() {
                if let Some(PyValueType::BigInt(bigint)) = variables.get("find_element_index") {
                    Some(bigint)
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(find_element_index_value) = find_element_index {
                let array_start = vm
                    .memory
                    .get(&array_ptr_addr)
                    .map_err(VirtualMachineError::MemoryError)?
                    .ok_or(VirtualMachineError::FindElemNoFoundKey)?;

                let found_key =
                    vm.memory
                        .get(&array_start.add_int_mod(
                            &(elm_size * find_element_index_value),
                            &vm.prime,
                        )?)
                        .map_err(VirtualMachineError::MemoryError)?
                        .ok_or(VirtualMachineError::FindElemNoFoundKey)?;


                if found_key != maybe_rel_key {
                    return Err(VirtualMachineError::InvalidIndex(
                        find_element_index_value.clone(),
                        maybe_rel_key.clone(),
                        found_key.clone(),
                    ));
                }

                vm
                .memory
                .insert(
                    &index_addr,
                    &MaybeRelocatable::Int(find_element_index_value.clone()),
                )
                .map_err(VirtualMachineError::MemoryError)?;

                vm.exec_scopes.delete_variable("find_element_index");
                return Ok(());
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

                if let Some(variables) = vm.exec_scopes.get_local_variables() {
                    if let Some(PyValueType::BigInt(find_element_max_size)) = variables.get("find_element_max_size") {
                        if n_elms > find_element_max_size {
                            return Err(VirtualMachineError::FindElemMaxSize(
                                find_element_max_size.clone(),
                                n_elms.clone(),
                            ));
                        }
                    }
                }

                let n_elms_iter: i32 = n_elms
                    .to_i32()
                    .ok_or_else(|| VirtualMachineError::OffsetExceeded(n_elms.clone()))?;

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

    fn init_vm_ids(
        elm_size: Option<&MaybeRelocatable>,
        n_elms: Option<&MaybeRelocatable>,
        key: Option<&MaybeRelocatable>,
        skip_insertion: bool,
    ) -> (VirtualMachine, HashMap<String, BigInt>) {
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
        let elm_size_default = MaybeRelocatable::from(bigint!(2));
        let n_elms_default = MaybeRelocatable::from(bigint!(2));
        let key_default = MaybeRelocatable::from(bigint!(3));
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                if let Some(rel) = elm_size {
                    rel
                } else {
                    &elm_size_default
                },
            )
            .expect("Unexpected memory insert fail");
        if !skip_insertion {
            vm.memory
                .insert(
                    &MaybeRelocatable::from((0, 2)),
                    if let Some(rel) = n_elms {
                        rel
                    } else {
                        &n_elms_default
                    },
                )
                .expect("Unexpected memory insert fail");
        }
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                if let Some(rel) = key {
                    rel
                } else {
                    &key_default
                },
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
        let (mut vm, ids) = init_vm_ids(None, None, None, false);

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
    fn element_found_by_oracle() {
        let (mut vm, ids) = init_vm_ids(None, None, None, false);
        vm.exec_scopes
            .assign_or_update_variable("find_element_index", PyValueType::BigInt(bigint!(1)));

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
        let (mut vm, ids) =
            init_vm_ids(None, None, Some(&MaybeRelocatable::from(bigint!(7))), false);

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::FindElemKeyNotFound(
                MaybeRelocatable::Int(bigint!(7))
            ))
        );
    }

    #[test]
    fn element_not_found_oracle() {
        let (mut vm, ids) = init_vm_ids(None, None, None, false);
        vm.exec_scopes
            .assign_or_update_variable("find_element_index", PyValueType::BigInt(bigint!(2)));

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::FindElemNoFoundKey)
        );
    }

    #[test]
    fn find_elm_failed_ids_get_addres() {
        let (mut vm, ids) = init_vm_ids(None, None, None, false);
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
        let (mut vm, ids) = init_vm_ids(None, None, None, true);

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn find_elm_builtin_is_none() {
        let (mut vm, ids) = init_vm_ids(None, None, None, false);
        _ = vm.builtin_runners.pop();

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn find_elm_range_check_not_present() {
        let (mut vm, ids) = init_vm_ids(None, None, None, false);
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
    fn find_elm_range_check_not_first() {
        let (mut vm, ids) = init_vm_ids(None, None, None, false);
        let range_builtin = vm.builtin_runners.pop();
        vm.builtin_runners.push((
            "output".to_string(),
            Box::new(OutputBuiltinRunner::new(true)),
        ));
        vm.builtin_runners.push(range_builtin.expect("Lost range check builtin"));

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Ok(())
        );
    }

    #[test]
    fn find_elm_not_int_elm_size() {
        let (mut vm, ids) = init_vm_ids(Some(&MaybeRelocatable::from((7, 8))), None, None, false);

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((7, 8))
            ))
        );
    }

    #[test]
    fn find_elm_zero_elm_size() {
        let (mut vm, ids) =
            init_vm_ids(Some(&MaybeRelocatable::Int(bigint!(0))), None, None, false);

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::ValueOutOfRange(bigint!(0)))
        );
    }

    #[test]
    fn find_elm_negative_elm_size() {
        let (mut vm, ids) =
            init_vm_ids(Some(&MaybeRelocatable::Int(bigint!(-1))), None, None, false);

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::ValueOutOfRange(bigint!(-1)))
        );
    }

    #[test]
    fn find_elm_not_int_n_elms() {
        let relocatable = MaybeRelocatable::from((1, 2));
        let (mut vm, ids) = init_vm_ids(None, Some(&relocatable), None, false);

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(relocatable))
        );
    }

    #[test]
    fn find_elm_negative_n_elms() {
        let (mut vm, ids) =
            init_vm_ids(None, Some(&MaybeRelocatable::Int(bigint!(-1))), None, false);

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::ValueOutOfRange(bigint!(-1)))
        );
    }

    #[test]
    fn find_elm_n_elms_gt_max_size() {
        let (mut vm, ids) = init_vm_ids(None, None, None, false);
        vm.exec_scopes
            .assign_or_update_variable("find_element_max_size", PyValueType::BigInt(bigint!(1)));

        assert_eq!(
            execute_hint(&mut vm, FIND_ELEMENT_HINT, ids, &ApTracking::new()),
            Err(VirtualMachineError::FindElemMaxSize(bigint!(1), bigint!(2)))
        );
    }
}
