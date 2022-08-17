use crate::bigint;
use crate::serde::deserialize_program::ApTracking;
use crate::vm::vm_core::VMProxy;
use crate::vm::{
    errors::vm_errors::VirtualMachineError,
    hints::hint_utils::{
        get_int_from_scope, get_integer_from_var_name, get_relocatable_from_var_name,
    },
};
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive};
use std::collections::HashMap;

use super::hint_utils::bigint_to_usize;
use super::hint_utils::get_int_ref_from_scope;
use super::hint_utils::get_ptr_from_var_name;
use super::hint_utils::insert_value_from_var_name;

pub fn find_element(
    vm_proxy: &mut VMProxy,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let key = get_integer_from_var_name("key", ids, vm_proxy, hint_ap_tracking)?;
    let elm_size_bigint = get_integer_from_var_name("elm_size", ids, vm_proxy, hint_ap_tracking)?;
    let n_elms = get_integer_from_var_name("n_elms", ids, vm_proxy, hint_ap_tracking)?;
    let array_start = get_ptr_from_var_name("array_ptr", ids, vm_proxy, hint_ap_tracking)?;
    let find_element_index = get_int_from_scope(vm_proxy.exec_scopes, "find_element_index").ok();
    let elm_size = elm_size_bigint
        .to_usize()
        .ok_or_else(|| VirtualMachineError::ValueOutOfRange(elm_size_bigint.clone()))?;
    if elm_size == 0 {
        return Err(VirtualMachineError::ValueOutOfRange(
            elm_size_bigint.clone(),
        ));
    }

    if let Some(find_element_index_value) = find_element_index {
        let find_element_index_usize = bigint_to_usize(&find_element_index_value)?;
        let found_key = vm_proxy
            .memory
            .get_integer(&(array_start + (elm_size * find_element_index_usize)))
            .map_err(|_| VirtualMachineError::KeyNotFound)?;

        if found_key != key {
            return Err(VirtualMachineError::InvalidIndex(
                find_element_index_value,
                key.clone(),
                found_key.clone(),
            ));
        }
        insert_value_from_var_name(
            "index",
            find_element_index_value,
            ids,
            vm_proxy,
            hint_ap_tracking,
        )?;
        vm_proxy.exec_scopes.delete_variable("find_element_index");
        Ok(())
    } else {
        if n_elms.is_negative() {
            return Err(VirtualMachineError::ValueOutOfRange(n_elms.clone()));
        }

        if let Ok(find_element_max_size) =
            get_int_ref_from_scope(vm_proxy.exec_scopes, "find_element_max_size")
        {
            if n_elms > find_element_max_size {
                return Err(VirtualMachineError::FindElemMaxSize(
                    find_element_max_size.clone(),
                    n_elms.clone(),
                ));
            }
        }
        let n_elms_iter: i32 = n_elms
            .to_i32()
            .ok_or_else(|| VirtualMachineError::OffsetExceeded(n_elms.clone()))?;

        for i in 0..n_elms_iter {
            let iter_key = vm_proxy
                .memory
                .get_integer(&(array_start.clone() + (elm_size * i as usize)))
                .map_err(|_| VirtualMachineError::KeyNotFound)?;

            if iter_key == key {
                return insert_value_from_var_name(
                    "index",
                    bigint!(i),
                    ids,
                    vm_proxy,
                    hint_ap_tracking,
                );
            }
        }

        Err(VirtualMachineError::NoValueForKey(key.clone()))
    }
}

pub fn search_sorted_lower(
    vm_proxy: &mut VMProxy,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let find_element_max_size = get_int_from_scope(vm_proxy.exec_scopes, "find_element_max_size");
    let n_elms = get_integer_from_var_name("n_elms", ids, vm_proxy, hint_ap_tracking)?;
    let rel_array_ptr =
        get_relocatable_from_var_name("array_ptr", ids, vm_proxy, hint_ap_tracking)?;
    let elm_size = get_integer_from_var_name("elm_size", ids, vm_proxy, hint_ap_tracking)?;
    let key = get_integer_from_var_name("key", ids, vm_proxy, hint_ap_tracking)?;

    if !elm_size.is_positive() {
        return Err(VirtualMachineError::ValueOutOfRange(elm_size.clone()));
    }

    if n_elms.is_negative() {
        return Err(VirtualMachineError::ValueOutOfRange(n_elms.clone()));
    }

    if let Ok(find_element_max_size) = find_element_max_size {
        if n_elms > &find_element_max_size {
            return Err(VirtualMachineError::FindElemMaxSize(
                find_element_max_size,
                n_elms.clone(),
            ));
        }
    }

    let mut array_iter = vm_proxy.memory.get_relocatable(&rel_array_ptr)?.clone();
    let n_elms_usize = n_elms.to_usize().ok_or(VirtualMachineError::KeyNotFound)?;
    let elm_size_usize = elm_size
        .to_usize()
        .ok_or(VirtualMachineError::KeyNotFound)?;

    for i in 0..n_elms_usize {
        let value = vm_proxy.memory.get_integer(&array_iter)?;
        if value >= key {
            return insert_value_from_var_name(
                "index",
                bigint!(i),
                ids,
                vm_proxy,
                hint_ap_tracking,
            );
        }
        array_iter.offset += elm_size_usize;
    }
    insert_value_from_var_name("index", n_elms.clone(), ids, vm_proxy, hint_ap_tracking)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::exec_scope::PyValueType;
    use crate::types::relocatable::MaybeRelocatable;
    use crate::types::{exec_scope::ExecutionScopes, instruction::Register};
    use crate::utils::test_utils::vm;
    use crate::vm::hints::execute_hint::get_vm_proxy;
    use crate::vm::hints::{
        execute_hint::{BuiltinHintExecutor, HintReference},
        hint_code,
    };
    use crate::vm::vm_core::VirtualMachine;
    use num_bigint::Sign;

    static HINT_EXECUTOR: BuiltinHintExecutor = BuiltinHintExecutor {};
    use crate::types::hint_executor::HintExecutor;

    const FIND_ELEMENT_HINT: &str = "array_ptr = ids.array_ptr\nelm_size = ids.elm_size\nassert isinstance(elm_size, int) and elm_size > 0, \\\n    f'Invalid value for elm_size. Got: {elm_size}.'\nkey = ids.key\n\nif '__find_element_index' in globals():\n    ids.index = __find_element_index\n    found_key = memory[array_ptr + elm_size * __find_element_index]\n    assert found_key == key, \\\n        f'Invalid index found in __find_element_index. index: {__find_element_index}, ' \\\n        f'expected key {key}, found key: {found_key}.'\n    # Delete __find_element_index to make sure it's not used for the next calls.\n    del __find_element_index\nelse:\n    n_elms = ids.n_elms\n    assert isinstance(n_elms, int) and n_elms >= 0, \\\n        f'Invalid value for n_elms. Got: {n_elms}.'\n    if '__find_element_max_size' in globals():\n        assert n_elms <= __find_element_max_size, \\\n            f'find_element() can only be used with n_elms<={__find_element_max_size}. ' \\\n            f'Got: n_elms={n_elms}.'\n\n    for i in range(n_elms):\n        if memory[array_ptr + elm_size * i] == key:\n            ids.index = i\n            break\n    else:\n        raise ValueError(f'Key {key} was not found.')";
    const SEARCH_SORTED_LOWER_HINT: &str = "array_ptr = ids.array_ptr\nelm_size = ids.elm_size\nassert isinstance(elm_size, int) and elm_size > 0, \\\n    f'Invalid value for elm_size. Got: {elm_size}.'\n\nn_elms = ids.n_elms\nassert isinstance(n_elms, int) and n_elms >= 0, \\\n    f'Invalid value for n_elms. Got: {n_elms}.'\nif '__find_element_max_size' in globals():\n    assert n_elms <= __find_element_max_size, \\\n        f'find_element() can only be used with n_elms<={__find_element_max_size}. ' \\\n        f'Got: n_elms={n_elms}.'\n\nfor i in range(n_elms):\n    if memory[array_ptr + elm_size * i] >= ids.key:\n        ids.index = i\n        break\nelse:\n    ids.index = n_elms";

    fn init_vm_ids(
        values_to_override: HashMap<String, MaybeRelocatable>,
    ) -> (VirtualMachine, HashMap<String, BigInt>) {
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![],
            false,
        );

        const FP_OFFSET_START: usize = 4;
        vm.run_context.fp = MaybeRelocatable::from((0, FP_OFFSET_START));

        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }

        let addresses = vec![
            MaybeRelocatable::from((0, 0)),
            MaybeRelocatable::from((0, 1)),
            MaybeRelocatable::from((0, 2)),
            MaybeRelocatable::from((0, 4)),
            MaybeRelocatable::from((1, 0)),
            MaybeRelocatable::from((1, 1)),
            MaybeRelocatable::from((1, 2)),
            MaybeRelocatable::from((1, 3)),
        ];

        let default_values = vec![
            ("array_ptr", MaybeRelocatable::from((1, 0))),
            ("elm_size", MaybeRelocatable::from(bigint!(2))),
            ("n_elms", MaybeRelocatable::from(bigint!(2))),
            ("key", MaybeRelocatable::from(bigint!(3))),
            ("arr[0].a", MaybeRelocatable::from(bigint!(1))),
            ("arr[0].b", MaybeRelocatable::from(bigint!(2))),
            ("arr[1].a", MaybeRelocatable::from(bigint!(3))),
            ("arr[1].b", MaybeRelocatable::from(bigint!(4))),
        ];

        /* array_ptr = (1,0) -> [Struct{1, 2}, Struct{3, 4}]
          elm_size = 2
          n_elms = 2
          index = None. Should become 1
          key = 3
        */

        // Build memory
        // default_values[i].0 -> contains name
        // default_values[i].1 -> contains maybe relocatable
        for (i, memory_cell) in addresses.iter().enumerate() {
            let value_to_insert = values_to_override
                .get(default_values[i].0)
                .unwrap_or(&default_values[i].1);
            vm.memory
                .insert(memory_cell, value_to_insert)
                .expect("Unexpected memory insert fail");
        }

        vm.references = HashMap::new();
        for i in 0..=FP_OFFSET_START {
            vm.references.insert(
                i,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: i as i32 - FP_OFFSET_START as i32,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            );
        }

        let mut ids = HashMap::<String, BigInt>::new();
        for (i, s) in ["array_ptr", "elm_size", "n_elms", "index", "key"]
            .iter()
            .enumerate()
        {
            ids.insert(s.to_string(), bigint!(i));
        }

        (vm, ids)
    }

    #[test]
    fn element_found_by_search() {
        assert_eq!(hint_code::FIND_ELEMENT, FIND_ELEMENT_HINT);
        let (mut vm, ids) = init_vm_ids(HashMap::new());
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, FIND_ELEMENT_HINT, &ids, &ApTracking::new()),
            Ok(())
        );

        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 3))),
            Ok(Some(&MaybeRelocatable::Int(bigint!(1))))
        )
    }

    #[test]
    fn element_found_by_oracle() {
        let (mut vm, ids) = init_vm_ids(HashMap::new());
        vm.exec_scopes
            .assign_or_update_variable("find_element_index", PyValueType::BigInt(bigint!(1)));
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, FIND_ELEMENT_HINT, &ids, &ApTracking::new()),
            Ok(())
        );

        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 3))),
            Ok(Some(&MaybeRelocatable::Int(bigint!(1))))
        )
    }

    #[test]
    fn element_not_found_search() {
        let (mut vm, ids) = init_vm_ids(HashMap::from([(
            "key".to_string(),
            MaybeRelocatable::from(bigint!(7)),
        )]));
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, FIND_ELEMENT_HINT, &ids, &ApTracking::new()),
            Err(VirtualMachineError::NoValueForKey(bigint!(7)))
        );
    }

    #[test]
    fn element_not_found_oracle() {
        let (mut vm, ids) = init_vm_ids(HashMap::new());
        vm.exec_scopes
            .assign_or_update_variable("find_element_index", PyValueType::BigInt(bigint!(2)));
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, FIND_ELEMENT_HINT, &ids, &ApTracking::new()),
            Err(VirtualMachineError::KeyNotFound)
        );
    }

    #[test]
    fn find_elm_failed_ids_get_addres() {
        let (mut vm, ids) = init_vm_ids(HashMap::new());
        vm.references.insert(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -7,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        );
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, FIND_ELEMENT_HINT, &ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn find_elm_failed_ids_get_from_mem() {
        let mut vm = vm!();
        const FP_OFFSET_START: usize = 4;
        vm.references = HashMap::new();
        for i in 0..=FP_OFFSET_START {
            vm.references.insert(
                i,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: i as i32 - FP_OFFSET_START as i32,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            );
        }

        let mut ids = HashMap::<String, BigInt>::new();
        for (i, s) in ["array_ptr", "elm_size", "n_elms", "index", "key"]
            .iter()
            .enumerate()
        {
            ids.insert(s.to_string(), bigint!(i as i32));
        }
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, FIND_ELEMENT_HINT, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn find_elm_not_int_elm_size() {
        let (mut vm, ids) = init_vm_ids(HashMap::from([(
            "elm_size".to_string(),
            MaybeRelocatable::from((7, 8)),
        )]));
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, FIND_ELEMENT_HINT, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 1))
            ))
        );
    }

    #[test]
    fn find_elm_zero_elm_size() {
        let (mut vm, ids) = init_vm_ids(HashMap::from([(
            "elm_size".to_string(),
            MaybeRelocatable::Int(bigint!(0)),
        )]));
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, FIND_ELEMENT_HINT, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ValueOutOfRange(bigint!(0)))
        );
    }

    #[test]
    fn find_elm_negative_elm_size() {
        let (mut vm, ids) = init_vm_ids(HashMap::from([(
            "elm_size".to_string(),
            MaybeRelocatable::Int(bigint!(-1)),
        )]));
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, FIND_ELEMENT_HINT, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ValueOutOfRange(bigint!(-1)))
        );
    }

    #[test]
    fn find_elm_not_int_n_elms() {
        let relocatable = MaybeRelocatable::from((0, 2));
        let (mut vm, ids) =
            init_vm_ids(HashMap::from([("n_elms".to_string(), relocatable.clone())]));
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, FIND_ELEMENT_HINT, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(relocatable))
        );
    }

    #[test]
    fn find_elm_negative_n_elms() {
        let (mut vm, ids) = init_vm_ids(HashMap::from([(
            "n_elms".to_string(),
            MaybeRelocatable::Int(bigint!(-1)),
        )]));
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, FIND_ELEMENT_HINT, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ValueOutOfRange(bigint!(-1)))
        );
    }

    #[test]
    fn find_elm_empty_scope() {
        let (mut vm, ids) = init_vm_ids(HashMap::new());
        vm.exec_scopes = ExecutionScopes::new();
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, FIND_ELEMENT_HINT, &ids, &ApTracking::new()),
            Ok(())
        );
    }

    #[test]
    fn find_elm_n_elms_gt_max_size() {
        let (mut vm, ids) = init_vm_ids(HashMap::new());
        vm.exec_scopes
            .assign_or_update_variable("find_element_max_size", PyValueType::BigInt(bigint!(1)));
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, FIND_ELEMENT_HINT, &ids, &ApTracking::new()),
            Err(VirtualMachineError::FindElemMaxSize(bigint!(1), bigint!(2)))
        );
    }

    #[test]
    fn find_elm_key_not_int() {
        let relocatable = MaybeRelocatable::from((0, 4));
        let (mut vm, ids) = init_vm_ids(HashMap::from([("key".to_string(), relocatable.clone())]));
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, FIND_ELEMENT_HINT, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(relocatable))
        );
    }

    #[test]
    fn search_sorted_lower() {
        let (mut vm, ids) = init_vm_ids(HashMap::new());

        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(
                &mut vm_proxy,
                SEARCH_SORTED_LOWER_HINT,
                &ids,
                &ApTracking::new()
            ),
            Ok(())
        );

        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 3))),
            Ok(Some(&MaybeRelocatable::Int(bigint!(1))))
        )
    }

    #[test]
    fn search_sorted_lower_no_matches() {
        let (mut vm, ids) = init_vm_ids(HashMap::from([(
            "key".to_string(),
            MaybeRelocatable::Int(bigint!(7)),
        )]));

        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(
                &mut vm_proxy,
                SEARCH_SORTED_LOWER_HINT,
                &ids,
                &ApTracking::new()
            ),
            Ok(())
        );

        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 3))),
            Ok(Some(&MaybeRelocatable::Int(bigint!(2))))
        )
    }

    #[test]
    fn search_sorted_lower_failed_ids_get_addres() {
        let (mut vm, ids) = init_vm_ids(HashMap::new());
        vm.references.insert(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -7,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        );
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(
                &mut vm_proxy,
                SEARCH_SORTED_LOWER_HINT,
                &ids,
                &ApTracking::new()
            ),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn search_sorted_lower_failed_ids_get_from_mem() {
        let mut vm = vm!();
        const FP_OFFSET_START: usize = 4;
        vm.references = HashMap::new();
        for i in 0..=FP_OFFSET_START {
            vm.references.insert(
                i,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: i as i32 - FP_OFFSET_START as i32,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            );
        }

        let mut ids = HashMap::<String, BigInt>::new();
        for (i, s) in ["array_ptr", "elm_size", "n_elms", "index", "key"]
            .iter()
            .enumerate()
        {
            ids.insert(s.to_string(), bigint!(i as i32));
        }

        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(
                &mut vm_proxy,
                SEARCH_SORTED_LOWER_HINT,
                &ids,
                &ApTracking::new()
            ),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn search_sorted_lower_not_int_elm_size() {
        let (mut vm, ids) = init_vm_ids(HashMap::from([(
            "elm_size".to_string(),
            MaybeRelocatable::from((7, 8)),
        )]));

        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(
                &mut vm_proxy,
                SEARCH_SORTED_LOWER_HINT,
                &ids,
                &ApTracking::new()
            ),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 1))
            ))
        );
    }

    #[test]
    fn search_sorted_lower_zero_elm_size() {
        let (mut vm, ids) = init_vm_ids(HashMap::from([(
            "elm_size".to_string(),
            MaybeRelocatable::Int(bigint!(0)),
        )]));

        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(
                &mut vm_proxy,
                SEARCH_SORTED_LOWER_HINT,
                &ids,
                &ApTracking::new()
            ),
            Err(VirtualMachineError::ValueOutOfRange(bigint!(0)))
        );
    }

    #[test]
    fn search_sorted_lower_negative_elm_size() {
        let (mut vm, ids) = init_vm_ids(HashMap::from([(
            "elm_size".to_string(),
            MaybeRelocatable::Int(bigint!(-1)),
        )]));

        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(
                &mut vm_proxy,
                SEARCH_SORTED_LOWER_HINT,
                &ids,
                &ApTracking::new()
            ),
            Err(VirtualMachineError::ValueOutOfRange(bigint!(-1)))
        );
    }

    #[test]
    fn search_sorted_lower_not_int_n_elms() {
        let (mut vm, ids) = init_vm_ids(HashMap::from([(
            "n_elms".to_string(),
            MaybeRelocatable::from((1, 2)),
        )]));

        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(
                &mut vm_proxy,
                SEARCH_SORTED_LOWER_HINT,
                &ids,
                &ApTracking::new()
            ),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 2))
            ))
        );
    }

    #[test]
    fn search_sorted_lower_negative_n_elms() {
        let (mut vm, ids) = init_vm_ids(HashMap::from([(
            "n_elms".to_string(),
            MaybeRelocatable::Int(bigint!(-1)),
        )]));

        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(
                &mut vm_proxy,
                SEARCH_SORTED_LOWER_HINT,
                &ids,
                &ApTracking::new()
            ),
            Err(VirtualMachineError::ValueOutOfRange(bigint!(-1)))
        );
    }

    #[test]
    fn search_sorted_lower_empty_scope() {
        let (mut vm, ids) = init_vm_ids(HashMap::new());
        vm.exec_scopes = ExecutionScopes::new();

        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(
                &mut vm_proxy,
                SEARCH_SORTED_LOWER_HINT,
                &ids,
                &ApTracking::new()
            ),
            Ok(())
        );
    }

    #[test]
    fn search_sorted_lower_n_elms_gt_max_size() {
        let (mut vm, ids) = init_vm_ids(HashMap::new());
        vm.exec_scopes
            .assign_or_update_variable("find_element_max_size", PyValueType::BigInt(bigint!(1)));

        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(
                &mut vm_proxy,
                SEARCH_SORTED_LOWER_HINT,
                &ids,
                &ApTracking::new()
            ),
            Err(VirtualMachineError::FindElemMaxSize(bigint!(1), bigint!(2)))
        );
    }
}
