use crate::bigint;
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
        Some(array_ptr_addr),
        Some(elm_size_addr),
        Some(n_elms_addr),
        Some(index_addr),
        Some(key_addr),
    ) = (
        get_address_from_reference(array_ptr_ref, &vm.references, &vm.run_context, vm),
        get_address_from_reference(elm_size_ref, &vm.references, &vm.run_context, vm),
        get_address_from_reference(n_elms_ref, &vm.references, &vm.run_context, vm),
        get_address_from_reference(index_ref, &vm.references, &vm.run_context, vm),
        get_address_from_reference(key_ref, &vm.references, &vm.run_context, vm),
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
                        let found_key = match vm.memory.get(&array_ptr_addr.add_int_mod(
                            &(elm_size * find_element_index_value.clone()),
                            &vm.prime,
                        )?) {
                            Ok(Some(found_key)) => found_key,
                            Ok(None) => return Err(VirtualMachineError::FindElemNoFoundKey),
                            Err(e) => return Err(VirtualMachineError::MemoryError(e)),
                        };

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

                        let n_elms_iter: i32 = if let Some(n_elms_iter) = n_elms.to_i32() {
                            n_elms_iter
                        } else {
                            return Err(VirtualMachineError::OffsetExceeded(n_elms.clone()));
                        };

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
