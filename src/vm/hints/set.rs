use crate::serde::deserialize_program::ApTracking;
use crate::types::relocatable::MaybeRelocatable;
use crate::vm::hints::hint_utils::get_address_from_var_name;
use crate::vm::{
    errors::vm_errors::VirtualMachineError, runners::builtin_runner::RangeCheckBuiltinRunner,
    vm_core::VirtualMachine,
};
use crate::{bigint, bigintusize};
use num_bigint::BigInt;
use num_traits::{FromPrimitive, ToPrimitive, Zero};
use std::collections::HashMap;

pub fn set_add(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let is_elm_in_set_addr =
        get_address_from_var_name("is_elm_in_set", ids.clone(), vm, hint_ap_tracking)?;
    let index_addr = get_address_from_var_name("index", ids.clone(), vm, hint_ap_tracking)?;
    let set_ptr_addr = get_address_from_var_name("set_ptr", ids.clone(), vm, hint_ap_tracking)?;
    let elm_size_addr = get_address_from_var_name("elm_size", ids.clone(), vm, hint_ap_tracking)?;
    let elm_ptr_addr = get_address_from_var_name("elm_ptr", ids.clone(), vm, hint_ap_tracking)?;
    let set_end_ptr_addr = get_address_from_var_name("set_end_ptr", ids, vm, hint_ap_tracking)?;

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
            Ok(Some(set_ptr)),
            Ok(Some(maybe_rel_elm_size)),
            Ok(Some(elm_ptr)),
            Ok(Some(set_end_ptr)),
        ) => {
            let _ = vm
                .builtin_runners
                .iter()
                .find(|(name, _)| name.as_str() == "range_check")
                .ok_or(VirtualMachineError::NoRangeCheckBuiltin)?
                .1
                .as_any()
                .downcast_ref::<RangeCheckBuiltinRunner>()
                .ok_or(VirtualMachineError::NoRangeCheckBuiltin)?;

            let elm_size = if let MaybeRelocatable::Int(ref elm_size) = maybe_rel_elm_size {
                if elm_size.is_zero() {
                    return Err(VirtualMachineError::ValueNotPositive(elm_size.clone()));
                }
                elm_size
                    .to_usize()
                    .ok_or(VirtualMachineError::BigintToUsizeFail)?
            } else {
                return Err(VirtualMachineError::ExpectedInteger(
                    maybe_rel_elm_size.clone(),
                ));
            };

            let elm = vm
                .memory
                .get_range(elm_ptr, elm_size)
                .map_err(VirtualMachineError::MemoryError)?;

            if set_ptr > set_end_ptr {
                return Err(VirtualMachineError::InvalidSetRange(
                    set_ptr.clone(),
                    set_end_ptr.clone(),
                ));
            }

            let set_span = set_end_ptr.sub(set_ptr, &vm.prime)?;
            // sub method always returns a MaybeRelocatable::Int
            let range_limit = if let MaybeRelocatable::Int(ref range_limit) = set_span {
                range_limit
                    .to_usize()
                    .ok_or(VirtualMachineError::BigintToUsizeFail)?
            } else {
                return Err(VirtualMachineError::ExpectedInteger(set_span));
            };

            for i in (0..range_limit).step_by(elm_size) {
                let set_iter = vm
                    .memory
                    .get_range(&set_ptr.add_usize_mod(i as usize, None), elm_size)
                    .map_err(VirtualMachineError::MemoryError)?;

                if set_iter == elm {
                    vm.memory
                        .insert(
                            &index_addr,
                            &MaybeRelocatable::Int(bigintusize!(i / elm_size)),
                        )
                        .map_err(VirtualMachineError::MemoryError)?;
                    return vm
                        .memory
                        .insert(&is_elm_in_set_addr, &MaybeRelocatable::Int(bigint!(1)))
                        .map_err(VirtualMachineError::MemoryError);
                }
            }
            vm.memory
                .insert(&is_elm_in_set_addr, &MaybeRelocatable::Int(bigint!(0)))
                .map_err(VirtualMachineError::MemoryError)
        }
        _ => Err(VirtualMachineError::FailedToGetIds),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::instruction::Register;
    use crate::vm::{
        hints::execute_hint::{execute_hint, HintReference},
        runners::builtin_runner::OutputBuiltinRunner,
    };
    use num_bigint::Sign;

    const HINT_CODE: &[u8] = "assert ids.elm_size > 0\nassert ids.set_ptr <= ids.set_end_ptr\nelm_list = memory.get_range(ids.elm_ptr, ids.elm_size)\nfor i in range(0, ids.set_end_ptr - ids.set_ptr, ids.elm_size):\n    if memory.get_range(ids.set_ptr + i, ids.elm_size) == elm_list:\n        ids.index = i // ids.elm_size\n        ids.is_elm_in_set = 1\n        break\nelse:\n    ids.is_elm_in_set = 0".as_bytes();

    fn init_vm_ids(
        set_ptr: Option<&MaybeRelocatable>,
        elm_size: Option<&MaybeRelocatable>,
        elm_a: Option<&MaybeRelocatable>,
        elm_b: Option<&MaybeRelocatable>,
    ) -> (VirtualMachine, HashMap<String, BigInt>) {
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );

        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        vm.run_context.fp = MaybeRelocatable::from((0, 5));

        let set_ptr_default = MaybeRelocatable::from((1, 0));
        let elm_size_default = MaybeRelocatable::from(bigint!(2));
        let elm_a_default = MaybeRelocatable::from(bigint!(2));
        let elm_b_default = MaybeRelocatable::from(bigint!(3));

        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                if let Some(rel) = set_ptr {
                    rel
                } else {
                    &set_ptr_default
                },
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                if let Some(rel) = elm_size {
                    rel
                } else {
                    &elm_size_default
                },
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from((2, 0)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 5)),
                &MaybeRelocatable::from((1, 2)),
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
                &MaybeRelocatable::from(bigint!(3)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from(bigint!(7)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((2, 0)),
                if let Some(rel) = elm_a {
                    rel
                } else {
                    &elm_a_default
                },
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((2, 1)),
                if let Some(rel) = elm_b {
                    rel
                } else {
                    &elm_b_default
                },
            )
            .expect("Unexpected memory insert fail");

        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                4,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                5,
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
        for (i, s) in [
            "is_elm_in_set",
            "index",
            "set_ptr",
            "elm_size",
            "elm_ptr",
            "set_end_ptr",
        ]
        .iter()
        .enumerate()
        {
            ids.insert(s.to_string(), bigint!(i as i32));
        }

        (vm, ids)
    }

    #[test]
    fn set_add_new_elem() {
        let (mut vm, ids) = init_vm_ids(None, None, None, None);

        assert_eq!(
            execute_hint(&mut vm, HINT_CODE, ids, &ApTracking::new()),
            Ok(())
        );

        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::Int(bigint!(0))))
        )
    }

    #[test]
    fn set_add_already_exists() {
        let (mut vm, ids) = init_vm_ids(
            None,
            None,
            Some(&MaybeRelocatable::from(bigint!(1))),
            Some(&MaybeRelocatable::from(bigint!(3))),
        );

        assert_eq!(
            execute_hint(&mut vm, HINT_CODE, ids, &ApTracking::new()),
            Ok(())
        );

        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::Int(bigint!(1))))
        );

        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Ok(Some(&MaybeRelocatable::Int(bigint!(0))))
        )
    }

    #[test]
    fn elm_size_not_int() {
        let (mut vm, ids) = init_vm_ids(None, Some(&MaybeRelocatable::from((7, 8))), None, None);

        assert_eq!(
            execute_hint(&mut vm, HINT_CODE, ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((7, 8))
            ))
        );
    }

    #[test]
    fn elm_size_negative() {
        let int = bigint!(-2);
        let (mut vm, ids) =
            init_vm_ids(None, Some(&MaybeRelocatable::Int(int.clone())), None, None);

        assert_eq!(
            execute_hint(&mut vm, HINT_CODE, ids, &ApTracking::new()),
            Err(VirtualMachineError::BigintToUsizeFail)
        );
    }

    #[test]
    fn elm_size_zero() {
        let int = bigint!(0);
        let (mut vm, ids) =
            init_vm_ids(None, Some(&MaybeRelocatable::Int(int.clone())), None, None);

        assert_eq!(
            execute_hint(&mut vm, HINT_CODE, ids, &ApTracking::new()),
            Err(VirtualMachineError::ValueNotPositive(int))
        );
    }
    #[test]
    fn set_ptr_gt_set_end_ptr() {
        let (mut vm, ids) = init_vm_ids(Some(&MaybeRelocatable::from((1, 3))), None, None, None);

        assert_eq!(
            execute_hint(&mut vm, HINT_CODE, ids, &ApTracking::new()),
            Err(VirtualMachineError::InvalidSetRange(
                MaybeRelocatable::from((1, 3)),
                MaybeRelocatable::from((1, 2)),
            ))
        );
    }

    #[test]
    fn find_elm_failed_ids_get_addres() {
        let (mut vm, ids) = init_vm_ids(None, None, None, None);
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
            execute_hint(&mut vm, HINT_CODE, ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn builtin_is_none() {
        let (mut vm, ids) = init_vm_ids(None, None, None, None);
        _ = vm.builtin_runners.pop();

        assert_eq!(
            execute_hint(&mut vm, HINT_CODE, ids, &ApTracking::new()),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn range_check_not_present() {
        let (mut vm, ids) = init_vm_ids(None, None, None, None);
        _ = vm.builtin_runners.pop();
        vm.builtin_runners.push((
            "output".to_string(),
            Box::new(OutputBuiltinRunner::new(true)),
        ));

        assert_eq!(
            execute_hint(&mut vm, HINT_CODE, ids, &ApTracking::new()),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn range_check_not_first_builtin() {
        let (mut vm, ids) = init_vm_ids(None, None, None, None);
        _ = vm.builtin_runners.pop();
        vm.builtin_runners.push((
            "output".to_string(),
            Box::new(OutputBuiltinRunner::new(true)),
        ));

        vm.builtin_runners.push((
            "range_check".to_string(),
            Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
        ));

        assert!(execute_hint(&mut vm, HINT_CODE, ids, &ApTracking::new()).is_ok());
    }
}
