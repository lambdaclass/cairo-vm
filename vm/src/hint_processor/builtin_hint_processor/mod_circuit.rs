use crate::stdlib::prelude::String;
use crate::types::exec_scope::ExecutionScopes;
use crate::{
    hint_processor::hint_processor_definition::HintReference,
    serde::deserialize_program::ApTracking,
    stdlib::collections::HashMap,
    vm::{errors::hint_errors::HintError, vm_core::VirtualMachine},
    Felt252,
};
#[cfg(not(feature = "mod_builtin"))]
use crate::{stdlib::prelude::Box, types::errors::math_errors::MathError};
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
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
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
    _exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    #[cfg(not(feature = "mod_builtin"))]
    const LARGE_BATCH_SIZE_PATH: &str =
        "starkware.cairo.common.modulo.run_mod_p_circuit_with_large_batch_size.BATCH_SIZE";
    #[cfg(not(feature = "mod_builtin"))]
    let batch_size = constants
        .get(LARGE_BATCH_SIZE_PATH)
        .ok_or_else(|| HintError::MissingConstant(Box::new(LARGE_BATCH_SIZE_PATH)))?;
    #[cfg(not(feature = "mod_builtin"))]
    let batch_size = batch_size
        .to_usize()
        .ok_or_else(|| MathError::Felt252ToUsizeConversion(Box::new(*batch_size)))?;
    #[cfg(feature = "mod_builtin")]
    let batch_size = 8; // Hardcoded here as we are not importing from the common lib yet
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
