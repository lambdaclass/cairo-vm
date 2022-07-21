use crate::bigint;
use crate::serde::deserialize_program::ApTracking;
use crate::types::relocatable::MaybeRelocatable;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::hint_utils::{
    get_address_from_var_name, get_struct_field_from_struct_address,
};
use crate::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use num_traits::FromPrimitive;
use std::collections::HashMap;

/*
Implements hint:
%{
    sum_low = ids.a.low + ids.b.low
    ids.carry_low = 1 if sum_low >= ids.SHIFT else 0
    sum_high = ids.a.high + ids.b.high + ids.carry_low
    ids.carry_high = 1 if sum_high >= ids.SHIFT else 0
%}
*/
pub fn uint256_add(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let shift: BigInt = bigint!(2).pow(128);

    let a_addr = get_address_from_var_name("a", ids.clone(), vm, hint_ap_tracking)?;
    let b_addr = get_address_from_var_name("b", ids.clone(), vm, hint_ap_tracking)?;
    let carry_high_addr =
        get_address_from_var_name("carry_high", ids.clone(), vm, hint_ap_tracking)?;
    let carry_low_addr = get_address_from_var_name("carry_low", ids, vm, hint_ap_tracking)?;

    let a_low = get_struct_field_from_struct_address(&a_addr, 0, vm)?;
    let a_high = get_struct_field_from_struct_address(&a_addr, 1, vm)?;
    let b_low = get_struct_field_from_struct_address(&b_addr, 0, vm)?;
    let b_high = get_struct_field_from_struct_address(&b_addr, 1, vm)?;

    // Hint main logic
    // sum_low = ids.a.low + ids.b.low
    // ids.carry_low = 1 if sum_low >= ids.SHIFT else 0
    // sum_high = ids.a.high + ids.b.high + ids.carry_low
    // ids.carry_high = 1 if sum_high >= ids.SHIFT else 0

    let carry_low = if a_low + b_low >= shift {
        bigint!(1)
    } else {
        bigint!(0)
    };

    let carry_high = if a_high + b_high + carry_low.clone() >= shift {
        bigint!(1)
    } else {
        bigint!(0)
    };

    match (
        vm.memory
            .insert(&carry_high_addr, &MaybeRelocatable::from(carry_high)),
        vm.memory
            .insert(&carry_low_addr, &MaybeRelocatable::from(carry_low)),
    ) {
        (Ok(_), Ok(_)) => Ok(()),
        (Err(error), _) | (_, Err(error)) => Err(VirtualMachineError::MemoryError(error)),
    }
}
