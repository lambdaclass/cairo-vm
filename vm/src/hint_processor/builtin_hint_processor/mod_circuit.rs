use crate::serde::deserialize_program::Identifier;
use crate::stdlib::prelude::{Box, String};
use crate::types::errors::math_errors::MathError;
use crate::{
    hint_processor::hint_processor_definition::HintReference,
    serde::deserialize_program::ApTracking,
    stdlib::collections::HashMap,
    vm::{errors::hint_errors::HintError, vm_core::VirtualMachine},
};
use num_traits::ToPrimitive;

use super::hint_utils::{
    get_constant_from_scoped_name, get_integer_from_var_name, get_ptr_from_var_name,
};
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
    run_p_mod_circuit_inner(vm, ids_data, ap_tracking, 1)
}

/* Implements Hint:
    %{
        from starkware.cairo.lang.builtins.modulo.mod_builtin_runner import ModBuiltinRunner
        assert builtin_runners["add_mod_builtin"].instance_def.batch_size == ids.BATCH_SIZE
        assert builtin_runners["mul_mod_builtin"].instance_def.batch_size == ids.BATCH_SIZE

        ModBuiltinRunner.fill_memory(
            memory=memory,
            add_mod=(ids.add_mod_ptr.address_, builtin_runners["add_mod_builtin"], ids.add_mod_n),
            mul_mod=(ids.mul_mod_ptr.address_, builtin_runners["mul_mod_builtin"], ids.mul_mod_n),
        )
    %}
*/
#[allow(unused_variables)]
pub fn run_p_mod_circuit_with_large_batch_size(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    identifiers: &HashMap<String, Identifier>,
    accessible_scopes: &[String],
) -> Result<(), HintError> {
    let batch_size = get_constant_from_scoped_name("BATCH_SIZE", identifiers, accessible_scopes)?;
    let batch_size = batch_size
        .to_usize()
        .ok_or_else(|| MathError::Felt252ToUsizeConversion(Box::new(*batch_size)))?;
    run_p_mod_circuit_inner(vm, ids_data, ap_tracking, batch_size)
}

pub fn run_p_mod_circuit_inner(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    batch_size: usize,
) -> Result<(), HintError> {
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
        Some(batch_size),
    )
    .map_err(HintError::Internal)
}
