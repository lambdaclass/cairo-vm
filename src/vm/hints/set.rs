use crate::vm::{
    errors::vm_errors::VirtualMachineError,
    runners::builtin_runner::RangeCheckBuiltinRunner,
    vm_core::VirtualMachine,
};
use std::collections::HashMap;
use crate::vm::hints::hint_utils::get_address_from_reference;
use num_bigint::BigInt;

pub fn set_add(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    //Check that ids contains the reference id for each variable used by the hint
    let (is_elm_in_set_ref, index_ref, set_ptr_ref, elm_size_ref, elm_ptr_ref) = if let (
        Some(is_elm_in_set_ref),
        Some(index_ref),
        Some(set_ptr_ref),
        Some(elm_size_ref),
        Some(elm_ptr_ref),
    ) = (
        ids.get(&String::from("is_elm_in_set")),
        ids.get(&String::from("index")),
        ids.get(&String::from("set_ptr")),
        ids.get(&String::from("elm_size")),
        ids.get(&String::from("elm_ptr")),
    ) {
        (
            is_elm_in_set_ref,
            index_ref,
            set_ptr_ref,
            elm_size_ref,
            elm_ptr_ref,
        )
    } else {
        return Err(VirtualMachineError::IncorrectIds(
            vec![
                String::from("is_elm_in_set"),
                String::from("index"),
                String::from("set_ptr"),
                String::from("elm_size"),
                String::from("elm_ptr"),
            ],
            ids.into_keys().collect(),
        ));
    };
    //Check that each reference id corresponds to a value in the reference manager
    let (is_elm_in_set_addr, index_addr, set_ptr_addr, elm_size_addr, elm_ptr_addr) = if let (
        Some(is_elm_in_set_addr),
        Some(index_addr),
        Some(set_ptr_addr),
        Some(elm_size_addr),
        Some(elm_ptr_addr),
    ) = (
        get_address_from_reference(is_elm_in_set_ref, &vm.references, &vm.run_context, vm),
        get_address_from_reference(index_ref, &vm.references, &vm.run_context, vm),
        get_address_from_reference(set_ptr_ref, &vm.references, &vm.run_context, vm),
        get_address_from_reference(elm_size_ref, &vm.references, &vm.run_context, vm),
        get_address_from_reference(elm_ptr_ref, &vm.references, &vm.run_context, vm),
    ) {
        (
            is_elm_in_set_addr,
            index_addr,
            set_ptr_addr,
            elm_size_addr,
            elm_ptr_addr,
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
    ) {
        (
            Ok(Some(maybe_rel_is_elm_in_set)),
            Ok(Some(maybe_rel_index)),
            Ok(Some(maybe_rel_set_ptr)),
            Ok(Some(maybe_rel_elm_size)),
            Ok(Some(maybe_rel_elm_ptr)),
        ) => {
            for (name, builtin) in &vm.builtin_runners {
                //Check that range_check_builtin is present
                if name == &String::from("range_check") {
                    match builtin.as_any().downcast_ref::<RangeCheckBuiltinRunner>() {
                        Some(builtin) => {
                            // Main logic

                            /*
                            return match (
                                vm.memory
                                    .insert(&r_addr, &MaybeRelocatable::Int(r))
                                    .map_err(VirtualMachineError::MemoryError),
                                vm.memory
                                    .insert(&biased_q_addr, &biased_q)
                                    .map_err(VirtualMachineError::MemoryError),
                            ) {
                                (Ok(_), Ok(_)) => Ok(()),
                                (Err(e), _) | (_, Err(e)) => Err(e),
                            };*/
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
