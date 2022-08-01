use crate::{
    math_utils::div_mod,
    serde::deserialize_program::ApTracking,
    types::exec_scope::PyValueType,
    vm::{
        errors::vm_errors::VirtualMachineError,
        hints::secp::secp_utils::{pack_from_var_name, N},
        vm_core::VirtualMachine,
    },
};
use num_bigint::BigInt;
use std::collections::HashMap;

pub fn div_mod_n_packed_divmod(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a = pack_from_var_name("a", ids, vm, hint_ap_tracking)?;
    let b = pack_from_var_name("b", ids, vm, hint_ap_tracking)?;

    let value = div_mod(a, b, &*N);

    vm.exec_scopes
        .assign_or_update_variable("value", PyValueType::BigInt(value.clone()));
    vm.exec_scopes
        .assign_or_update_variable("res", PyValueType::BigInt(value));
    Ok(())
}
