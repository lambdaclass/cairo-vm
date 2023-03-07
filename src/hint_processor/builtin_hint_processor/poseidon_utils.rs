use std::collections::HashMap;

use felt::Felt;
use num_traits::{One, Zero};

use crate::{
    hint_processor::hint_processor_definition::HintReference,
    serde::deserialize_program::ApTracking,
    vm::{errors::hint_errors::HintError, vm_core::VirtualMachine},
};

use super::hint_utils::{get_integer_from_var_name, insert_value_into_ap};

// Implements hint: "memory[ap] = to_felt_or_relocatable(ids.n >= 10)"
pub fn n_more_than_10(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    let n = get_integer_from_var_name("n", vm, ids_data, ap_tracking)?;

    let value = if n.as_ref() >= &Felt::from(10) {
        Felt::one()
    } else {
        Felt::zero()
    };
    insert_value_into_ap(vm, value)
}

// Implements hint: "memory[ap] = to_felt_or_relocatable(ids.n >= 2)"
pub fn n_more_than_2(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    let n = get_integer_from_var_name("n", vm, ids_data, ap_tracking)?;

    let value = if n.as_ref() >= &Felt::from(2) {
        Felt::one()
    } else {
        Felt::zero()
    };
    insert_value_into_ap(vm, value)
}
