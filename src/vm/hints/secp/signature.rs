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

    let value = safe_div(&(res * b - a), &*N)?;

    vm.exec_scopes
        .assign_or_update_variable("value", PyValueType::BigInt(value));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bigint, bigint_str};
    use num_bigint::Sign;
    #[test]
    fn safe_div_fail() {
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );

        vm.exec_scopes
            .assign_or_update_variable("a", PyValueType::BigInt(bigint!(0_usize)));
        vm.exec_scopes
            .assign_or_update_variable("b", PyValueType::BigInt(bigint!(1_usize)));
        vm.exec_scopes
            .assign_or_update_variable("res", PyValueType::BigInt(bigint!(1_usize)));

        assert_eq!(Err(VirtualMachineError::SafeDivFail(bigint!(1_usize), bigint_str!(b"115792089237316195423570985008687907852837564279074904382605163141518161494337"))), div_mod_n_safe_div(&mut vm));
    }
}
