use crate::hint_processor::hint_processor_definition::HintReference;
use crate::hint_processor::hint_processor_utils::bigint_to_usize;
use crate::hint_processor::hint_processor_utils::compute_addr_from_reference;
use crate::hint_processor::proxies::memory_proxy::MemoryProxy;
use crate::hint_processor::proxies::vm_proxy::VMProxy;
use crate::serde::deserialize_program::ApTracking;
use crate::types::relocatable::MaybeRelocatable;
use crate::types::relocatable::Relocatable;
use crate::vm::{context::run_context::RunContext, errors::vm_errors::VirtualMachineError};
use num_bigint::BigInt;
use std::collections::HashMap;

//Inserts value into the address of the given ids variable
pub fn insert_value_from_var_name(
    var_name: &str,
    value: impl Into<MaybeRelocatable>,
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let var_address = get_relocatable_from_var_name(var_name, vm_proxy, ids_data, ap_tracking)?;
    vm_proxy.memory.insert_value(&var_address, value)
}

//Inserts value into ap
pub fn insert_value_into_ap(
    memory: &mut MemoryProxy,
    run_context: &RunContext,
    value: impl Into<MaybeRelocatable>,
) -> Result<(), VirtualMachineError> {
    memory.insert_value(
        &(run_context
            .get_ap()
            .clone()
            .try_into()
            .map_err(VirtualMachineError::MemoryError)?),
        value,
    )
}

//Returns the Relocatable value stored in the given ids variable
pub fn get_ptr_from_var_name(
    var_name: &str,
    vm_proxy: &VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<Relocatable, VirtualMachineError> {
    let var_addr = get_relocatable_from_var_name(var_name, vm_proxy, ids_data, ap_tracking)?;
    //Add immediate if present in reference
    let hint_reference = ids_data
        .get(&String::from(var_name))
        .ok_or(VirtualMachineError::FailedToGetIds)?;
    if hint_reference.dereference {
        let value = vm_proxy.memory.get_relocatable(&var_addr)?;
        if let Some(immediate) = &hint_reference.immediate {
            let modified_value = value + bigint_to_usize(immediate)?;
            Ok(modified_value)
        } else {
            Ok(value.clone())
        }
    } else {
        Ok(var_addr)
    }
}

//Gets the address, as a MaybeRelocatable of the variable given by the ids name
pub fn get_address_from_var_name(
    var_name: &str,
    vm_proxy: &VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<MaybeRelocatable, VirtualMachineError> {
    Ok(MaybeRelocatable::from(compute_addr_from_reference(
        ids_data
            .get(var_name)
            .ok_or(VirtualMachineError::FailedToGetIds)?,
        vm_proxy.run_context,
        &vm_proxy.memory,
        ap_tracking,
    )?))
}

//Gets the address, as a Relocatable of the variable given by the ids name
pub fn get_relocatable_from_var_name(
    var_name: &str,
    vm_proxy: &VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<Relocatable, VirtualMachineError> {
    compute_addr_from_reference(
        ids_data
            .get(var_name)
            .ok_or(VirtualMachineError::FailedToGetIds)?,
        vm_proxy.run_context,
        &vm_proxy.memory,
        ap_tracking,
    )
}

//Gets the value of a variable name.
//If the value is an MaybeRelocatable::Int(Bigint) return &Bigint
//else raises Err
pub fn get_integer_from_var_name<'a>(
    var_name: &str,
    vm_proxy: &'a VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<&'a BigInt, VirtualMachineError> {
    let relocatable = get_relocatable_from_var_name(var_name, vm_proxy, ids_data, ap_tracking)?;
    vm_proxy.memory.get_integer(&relocatable)
}
