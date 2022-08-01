use crate::{
    math_utils::{div_mod, safe_div},
    serde::deserialize_program::ApTracking,
    types::exec_scope::PyValueType,
    vm::{
        errors::vm_errors::VirtualMachineError,
        hints::{
            hint_utils::get_int_from_scope_ref,
            secp::secp_utils::{pack_from_var_name, N},
        },
        vm_core::VirtualMachine,
    },
};
use num_bigint::BigInt;
use std::collections::HashMap;

/* Implements hint:
from starkware.cairo.common.cairo_secp.secp_utils import N, pack
from starkware.python.math_utils import div_mod, safe_div

a = pack(ids.a, PRIME)
b = pack(ids.b, PRIME)
value = res = div_mod(a, b, N)
*/
pub fn div_mod_n_packed_divmod(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a = pack_from_var_name("a", ids, vm, hint_ap_tracking)?;
    let b = pack_from_var_name("b", ids, vm, hint_ap_tracking)?;

    let value = div_mod(a.clone(), b.clone(), &*N);

    vm.exec_scopes
        .assign_or_update_variable("a", PyValueType::BigInt(a));
    vm.exec_scopes
        .assign_or_update_variable("b", PyValueType::BigInt(b));
    vm.exec_scopes
        .assign_or_update_variable("value", PyValueType::BigInt(value.clone()));
    vm.exec_scopes
        .assign_or_update_variable("res", PyValueType::BigInt(value));
    Ok(())
}

// Implements hint:
// value = k = safe_div(res * b - a, N)
pub fn div_mod_n_safe_div(vm: &mut VirtualMachine) -> Result<(), VirtualMachineError> {
    let a = get_int_from_scope_ref(vm, "a")?.clone();
    let b = get_int_from_scope_ref(vm, "b")?.clone();
    let res = get_int_from_scope_ref(vm, "res")?;

    let k = safe_div(&(res * b - a), &*N)?;
    vm.exec_scopes
        .assign_or_update_variable("k", PyValueType::BigInt(k));
    Ok(())
}
