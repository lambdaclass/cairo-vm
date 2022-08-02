use crate::bigint;
use crate::math_utils::ec_double_slope;
use crate::serde::deserialize_program::ApTracking;
use crate::types::exec_scope::PyValueType;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::hint_utils::{
    get_integer_from_relocatable_plus_offset, get_relocatable_from_var_name,
};
use crate::vm::hints::secp::secp_utils::{pack, SECP_P};
use crate::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use num_integer::Integer;
use std::collections::HashMap;

/*
Implements hint:
%{
    from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack

    y = pack(ids.point.y, PRIME) % SECP_P
    # The modulo operation in python always returns a nonnegative number.
    value = (-y) % SECP_P
%}
*/
pub fn ec_negative(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    //ids.point
    let point_reloc = get_relocatable_from_var_name("point", ids, vm, hint_ap_tracking)?;

    //ids.point.y.d0
    let y_d0 = get_integer_from_relocatable_plus_offset(&point_reloc, 3, vm)?;
    //ids.point.y.d1
    let y_d1 = get_integer_from_relocatable_plus_offset(&point_reloc, 4, vm)?;
    //ids.point.y.d2
    let y_d2 = get_integer_from_relocatable_plus_offset(&point_reloc, 5, vm)?;

    let value = (-pack(y_d0, y_d1, y_d2, &vm.prime)).mod_floor(&SECP_P);

    vm.exec_scopes
        .assign_or_update_variable("value", PyValueType::BigInt(value));

    Ok(())
}

/*
Implements hint:
%{
    from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack
    from starkware.python.math_utils import ec_double_slope

    # Compute the slope.
    x = pack(ids.point.x, PRIME)
    y = pack(ids.point.y, PRIME)
    value = slope = ec_double_slope(point=(x, y), alpha=0, p=SECP_P)
%}
*/
pub fn compute_doubling_slope(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    //ids.point
    let point_reloc = get_relocatable_from_var_name("point", ids, vm, hint_ap_tracking)?;

    //ids.point.y.d0
    let x_d0 = get_integer_from_relocatable_plus_offset(&point_reloc, 0, vm)?;
    //ids.point.y.d1
    let x_d1 = get_integer_from_relocatable_plus_offset(&point_reloc, 1, vm)?;
    //ids.point.y.d2
    let x_d2 = get_integer_from_relocatable_plus_offset(&point_reloc, 2, vm)?;
    //ids.point.y.d0
    let y_d0 = get_integer_from_relocatable_plus_offset(&point_reloc, 3, vm)?;
    //ids.point.y.d1
    let y_d1 = get_integer_from_relocatable_plus_offset(&point_reloc, 4, vm)?;
    //ids.point.y.d2
    let y_d2 = get_integer_from_relocatable_plus_offset(&point_reloc, 5, vm)?;

    let value = ec_double_slope(
        (
            pack(x_d0, x_d1, x_d2, &vm.prime),
            pack(y_d0, y_d1, y_d2, &vm.prime),
        ),
        &bigint!(0),
        &SECP_P,
    );

    vm.exec_scopes
        .assign_or_update_variable("value", PyValueType::BigInt(value.clone()));

    vm.exec_scopes
        .assign_or_update_variable("slope", PyValueType::BigInt(value));

    Ok(())
}
