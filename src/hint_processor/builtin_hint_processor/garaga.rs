use crate::stdlib::collections::HashMap;
use crate::stdlib::prelude::String;

use crate::{
    hint_processor::hint_processor_definition::HintReference,
    serde::deserialize_program::ApTracking,
    vm::{errors::hint_errors::HintError, vm_core::VirtualMachine},
};

use super::hint_utils::{get_integer_from_var_name, insert_value_from_var_name};

/// Implements hint:
/// ```python
/// x = ids.x,
/// ids.bit_length = x.bit_length()
/// ```
pub fn get_felt_bitlenght(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    let x = get_integer_from_var_name("x", vm, ids_data, ap_tracking)?;
    let bit_length = x.bits() as usize;
    insert_value_from_var_name("bit_length", bit_length, vm, ids_data, ap_tracking)
}
