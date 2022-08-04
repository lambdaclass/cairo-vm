use crate::{
    bigint,
    serde::deserialize_program::ApTracking,
    vm::{
        errors::vm_errors::VirtualMachineError,
        hints::hint_utils::{get_integer_from_var_name, get_ptr_from_var_name},
        vm_core::VirtualMachine,
    },
};
use num_bigint::BigInt;
use num_integer::Integer;
use std::collections::HashMap;
use std::ops::Shl;

/*
    Implements hint:
    %{
      segments.write_arg(ids.inputs, [ids.low % 2 ** 64, ids.low // 2 ** 64])
      segments.write_arg(ids.inputs + 2, [ids.high % 2 ** 64, ids.high // 2 ** 64])
    %}
*/
pub fn keccak_write_args(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let inputs_ptr = get_ptr_from_var_name("inputs", ids, vm, hint_ap_tracking)?;

    let low = get_integer_from_var_name("low", &ids, vm, hint_ap_tracking)?;
    let high = get_integer_from_var_name("high", &ids, vm, hint_ap_tracking)?;

    let low_args = [low.mod_floor(&bigint!(1).shl(64)), low / bigint!(1).shl(64)];
    let high_args = [
        high.mod_floor(&bigint!(1).shl(64)),
        high / bigint!(1).shl(64),
    ];

    vm.segments
        .write_arg(
            &mut vm.memory,
            &inputs_ptr,
            &low_args.to_vec(),
            Some(&vm.prime),
        )
        .map_err(VirtualMachineError::MemoryError)?;

    vm.segments
        .write_arg(
            &mut vm.memory,
            &inputs_ptr.add(2)?,
            &high_args.to_vec(),
            Some(&vm.prime),
        )
        .map_err(VirtualMachineError::MemoryError)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    //use super::*;

    #[test]
    fn keccak_write_args_valid_test() {}
}
