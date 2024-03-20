use crate::hint_processor::hint_processor_definition::HintReference;
use crate::serde::deserialize_program::ApTracking;
use crate::stdlib::collections::HashMap;
use crate::vm::errors::hint_errors::HintError;
use crate::vm::vm_core::VirtualMachine;
use num_traits::ToPrimitive;

use super::hint_utils::{get_integer_from_var_name, get_ptr_from_var_name};
/* Implements Hint:
%{
    from starkware.cairo.lang.builtins.modulo.mod_builtin_runner import ModBuiltinRunner
    assert builtin_runners["add_mod_builtin"].instance_def.batch_size == 1
    assert builtin_runners["mul_mod_builtin"].instance_def.batch_size == 1

    ModBuiltinRunner.fill_memory(
        memory=memory,
        add_mod=(ids.add_mod_ptr.address_, builtin_runners["add_mod_builtin"], ids.add_mod_n),
        mul_mod=(ids.mul_mod_ptr.address_, builtin_runners["mul_mod_builtin"], ids.mul_mod_n),
    )
%}
*/
pub fn run_p_mod_circuit(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    // TODO: check batch size == 1 for both builtins
    let add_mod_ptr = get_ptr_from_var_name("add_mod_ptr", vm, ids_data, ap_tracking)?;
    let mul_mod_ptr = get_ptr_from_var_name("mul_mod_ptr", vm, ids_data, ap_tracking)?;
    let add_mod_n = get_integer_from_var_name("add_mod_n", vm, ids_data, ap_tracking)?
        .as_ref()
        .to_usize()
        .unwrap();
    let mul_mod_n = get_integer_from_var_name("mul_mod_n", vm, ids_data, ap_tracking)?
        .as_ref()
        .to_usize()
        .unwrap();
    vm.mod_builtin_fill_memory(
        Some((add_mod_ptr, add_mod_n)),
        Some((mul_mod_ptr, mul_mod_n)),
    )
    .map_err(HintError::Internal)
}
