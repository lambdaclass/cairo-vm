use crate::{
    hint_processor::{
        builtin_hint_processor::hint_utils::{get_integer_from_var_name, get_ptr_from_var_name},
        hint_processor_definition::HintReference,
    },
    serde::deserialize_program::ApTracking,
    vm::{
        errors::{hint_errors::HintError, vm_errors::VirtualMachineError},
        vm_core::VirtualMachine,
    },
};
use std::collections::HashMap;

pub fn verify_ecdsa_signature(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    let signature_r =
        get_integer_from_var_name("signature_r", vm, ids_data, ap_tracking)?.into_owned();
    let signature_s =
        get_integer_from_var_name("signature_s", vm, ids_data, ap_tracking)?.into_owned();
    let ecdsa_ptr = get_ptr_from_var_name("ecdsa_ptr", vm, ids_data, ap_tracking)?;
    let ecdsa_builtin = &mut vm.get_signature_builtin()?;
    ecdsa_builtin
        .add_signature(ecdsa_ptr, &(signature_r, signature_s))
        .map_err(VirtualMachineError::MemoryError)?;
    Ok(())
}
