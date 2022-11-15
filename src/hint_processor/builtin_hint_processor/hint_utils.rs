use crate::hint_processor::hint_processor_definition::HintReference;
use crate::hint_processor::hint_processor_utils::bigint_to_usize;
use crate::hint_processor::hint_processor_utils::compute_addr_from_reference;
use crate::hint_processor::hint_processor_utils::get_integer_from_reference;
use crate::serde::deserialize_program::ApTracking;
use crate::types::relocatable::MaybeRelocatable;
use crate::types::relocatable::Relocatable;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use std::borrow::Cow;
use std::collections::HashMap;

//Inserts value into the address of the given ids variable
pub fn insert_value_from_var_name(
    var_name: &str,
    value: impl Into<MaybeRelocatable>,
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let var_address = get_relocatable_from_var_name(var_name, vm, ids_data, ap_tracking)?;
    vm.insert_value(&var_address, value)
}

//Inserts value into ap
pub fn insert_value_into_ap(
    vm: &mut VirtualMachine,
    value: impl Into<MaybeRelocatable>,
) -> Result<(), VirtualMachineError> {
    vm.insert_value(&vm.get_ap(), value)
}

//Returns the Relocatable value stored in the given ids variable
pub fn get_ptr_from_var_name(
    var_name: &str,
    vm: &VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<Relocatable, VirtualMachineError> {
    let var_addr = get_relocatable_from_var_name(var_name, vm, ids_data, ap_tracking)?;
    //Add immediate if present in reference
    let hint_reference = ids_data
        .get(&String::from(var_name))
        .ok_or(VirtualMachineError::FailedToGetIds)?;
    if hint_reference.dereference {
        let value = vm.get_relocatable(&var_addr)?;
        if let Some(immediate) = &hint_reference.immediate {
            let modified_value = value.as_ref() + bigint_to_usize(immediate)?;
            Ok(modified_value)
        } else {
            Ok(value.into_owned())
        }
    } else {
        Ok(var_addr)
    }
}

//Gets the address, as a MaybeRelocatable of the variable given by the ids name
pub fn get_address_from_var_name(
    var_name: &str,
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<MaybeRelocatable, VirtualMachineError> {
    Ok(MaybeRelocatable::from(compute_addr_from_reference(
        ids_data
            .get(var_name)
            .ok_or(VirtualMachineError::FailedToGetIds)?,
        vm,
        ap_tracking,
    )?))
}

//Gets the address, as a Relocatable of the variable given by the ids name
pub fn get_relocatable_from_var_name(
    var_name: &str,
    vm: &VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<Relocatable, VirtualMachineError> {
    compute_addr_from_reference(
        ids_data
            .get(var_name)
            .ok_or(VirtualMachineError::FailedToGetIds)?,
        vm,
        ap_tracking,
    )
}

//Gets the value of a variable name.
//If the value is an MaybeRelocatable::Int(Bigint) return &Bigint
//else raises Err
pub fn get_integer_from_var_name<'a>(
    var_name: &str,
    vm: &'a VirtualMachine,
    ids_data: &'a HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<Cow<'a, BigInt>, VirtualMachineError> {
    let reference = get_reference_from_var_name(var_name, ids_data)?;
    get_integer_from_reference(vm, reference, ap_tracking)
}

pub fn get_reference_from_var_name<'a>(
    var_name: &str,
    ids_data: &'a HashMap<String, HintReference>,
) -> Result<&'a HintReference, VirtualMachineError> {
    ids_data
        .get(var_name)
        .ok_or(VirtualMachineError::FailedToGetIds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bigint,
        hint_processor::hint_processor_definition::HintReference,
        relocatable,
        utils::test_utils::*,
        vm::{
            errors::memory_errors::MemoryError, vm_core::VirtualMachine, vm_memory::memory::Memory,
        },
    };
    use num_bigint::Sign;

    #[test]
    fn get_ptr_from_var_name_immediate_value() {
        let mut vm = vm!();
        vm.memory = memory![((1, 0), (0, 0))];
        let mut hint_ref = HintReference::new(0, 0, false, true);
        hint_ref.immediate = Some(bigint!(2));
        let ids_data = HashMap::from([("imm".to_string(), hint_ref)]);

        assert_eq!(
            get_ptr_from_var_name("imm", &mut vm, &ids_data, &ApTracking::new()),
            Ok(relocatable!(0, 2))
        );
    }
}
