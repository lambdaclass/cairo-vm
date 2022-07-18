use crate::vm::{vm_core::VirtualMachine, errors::vm_errors::VirtualMachineError, hints::hint_utils::get_address_from_reference};
use crate::types::relocatable::MaybeRelocatable;
use std::collections::HashMap;
use crate::bigint;
use num_integer::Integer;

pub fn find_element(vm: &mut VirtualMachine, ids: HashMap<String, BigInt>) -> Result<(), VirtualMachineError> {
    let (array_ptr_ref, elm_size_ref, n_elms_ref, index_ref, key_ref) = 
        if let (Some(array_ptr_ref), Some(elm_size_ref), Some(n_elms_ref), Some(index_ref), Some(key_ref)) = (
                ids.get("array_ptr"), ids.get("elm_size"), ids.get("n_elms"), ids.get("index"), ids.get("key"),
            ) {
            (array_ptr_ref, elm_size_ref, n_elms_ref, index_ref, key_ref)
        } else {
            return Err(VirtualMachineError::IncorrectIds(vec!["array_ptr", "elm_size", "n_elms", "index", "key"].iter().map(|s| s.to_string()).collect(), ids.into_keys().collect()));
        };

    let (array_ptr_addr, elm_size_addr, n_elms_addr, index_addr key_addr) = 
        if let (Some(array_ptr_addr), Some(elm_size_addr), Some(n_elms_addr), Some(index_addr), Some(key_addr) = (
                get_address_from_reference(array_ptr_ref, &vm.refrences, &vm.run_context, vm),
                get_address_from_reference(elm_size_ref, &vm.refrences, &vm.run_context, vm),
                get_address_from_reference(n_elms_ref, &vm.refrences, &vm.run_context, vm),
                get_address_from_reference(index_ref, &vm.refrences, &vm.run_context, vm),
                get_address_from_reference(key_ref, &vm.refrences, &vm.run_context, vm),
            ) {
            (array_ptr_addr, elm_size_addr, n_elms_addr, index_addr, key_addr)
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
        (Ok(_), Ok(Some(maybe_rel_elm_size)), Ok(Some(maybe_rel_n_elms)), Ok(Some(maybe_rel_index)) Ok(Some(maybe_rel_key))) => {
            for (name, builtin) in &vm.builtin_runners {
                //Check that range_check_builtin is present
                let builtin = match builtin.as_any().downcast_ref::<RangeCheckBuiltinRunner>() {
                    Some(b) => b,
                    None => return Err(VirtualMachineError::NoRangeCheckBuiltin),
                };

                if name == &"range_check".to_string() {
                    let elm_size = if let elm_size = MaybeRelocatable::Int(ref elm_size) = maybe_rel_elm_size {
                        elm_size
                    } else {
                        return Err(VirtualMachineError::ExpectedInteger(maybe_rel_elm_size));
                    };

                    if !elm_size.is_positive() {
                        return Err(VirtualMachineError::ValueOutOfRange(elm_size))
                    }

                    if let Some(find_element_idex) = vm.find_element_idex {
                        vm.find_element_index = None;
                        let found_key = vm.memory.get(array_addr.add_int_mod(elm_size * find_element_index)); 

                        if found_key != maybe_rel_key {
                            return Err(VirtualMachineError::InvalidIndex(find_element_index, maybe_rel_key, found_key);
                        }

                        return vm.memory.insert(&index_addr, &vm.find_element_index).map_err(VirtualMachineError::MemoryError);
                    } else {
                        let n_elms = if let n_elms = MaybeRelocatable::Int(ref n_elms) = maybe_rel_n_elms {
                            n_elms
                        } else {
                            return Err(VirtualMachineError::ExpectedInteger(maybe_rel_n_elms));
                        };

                        if n_elms.is_negative() {
                            return Err(VirtualMachineError::ValueOutOfRange(n_elms));
                        }

                        if let Some(find_element_max_size) = vm.find_element_max_size {
                            if n_elms > find_element_max_size {
                                return Err(VirtualMachineError::FindElemMaxSize(find_element_max_size, n_elems));
                            }
                        }

                        for i:BigInt in 0..n_elms {
                            if vm.memory.get(array_addr.add_int_mod(elm_size * i)) == maybe_rel_key {
                                return memory.insert(&index_addr, &MaybeRelocatable::Int(i)).map_err(VirtualMachineError::MemoryError);
                            }
                        }

                        return Err(VirtualMachineError::FindElemKeyNotFound(maybe_rel_key));
                    }
                    return vm.memory.insert(&index_addr, &...).map_err(VirtualMachineError::MemoryError);
                }
            }
            
            Err(VirtualMachineError::NoRangeCheckBuiltin);
        },
        _ => Err(VirtualMachineError::FailedToGetIds)
    }
}
