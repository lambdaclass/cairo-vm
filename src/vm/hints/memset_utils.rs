use crate::bigint;
use crate::serde::deserialize_program::ApTracking;
use crate::types::exec_scope::PyValueType;
use crate::types::relocatable::MaybeRelocatable;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::hint_utils::get_address_from_var_name;
use crate::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use num_traits::FromPrimitive;
use num_traits::Signed;
use std::collections::HashMap;

//  Implements hint:
//  %{ vm_enter_scope({'n': ids.n}) %}
pub fn memset_enter_scope(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let n_addr = get_address_from_var_name("n", ids, vm, hint_ap_tracking)?;

    match vm.memory.get(&n_addr) {
        Ok(Some(maybe_rel_n)) => {
            let n = if let MaybeRelocatable::Int(n) = maybe_rel_n {
                n
            } else {
                return Err(VirtualMachineError::ExpectedInteger(n_addr.clone()));
            };
            vm.exec_scopes.enter_scope(HashMap::from([(
                String::from("n"),
                PyValueType::BigInt(n.clone()),
            )]));

            Ok(())
        }
        _ => Err(VirtualMachineError::FailedToGetIds),
    }
}

/* Implements hint:
%{
    n -= 1
    ids.continue_loop = 1 if n > 0 else 0
%}
*/
pub fn memset_continue_loop(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let continue_loop_addr = get_address_from_var_name("continue_loop", ids, vm, hint_ap_tracking)?;

    // get `n` variable from vm scope
    let mut n = match vm.exec_scopes.get_local_variables() {
        Some(variables) => match variables.get("n") {
            Some(PyValueType::BigInt(n)) => n.clone(),
            _ => {
                return Err(VirtualMachineError::VariableNotInScopeError(String::from(
                    "n",
                )))
            }
        },
        None => return Err(VirtualMachineError::ScopeError),
    };

    // reassign `n` with `n - 1`
    vm.exec_scopes
        .assign_or_update_variable("n", PyValueType::BigInt(n - 1_i32));

    // get new value of `n`
    n = match vm.exec_scopes.get_local_variables() {
        Some(variables) => match variables.get("n") {
            Some(PyValueType::BigInt(n)) => n.clone(),
            _ => {
                return Err(VirtualMachineError::VariableNotInScopeError(String::from(
                    "n",
                )))
            }
        },
        None => return Err(VirtualMachineError::ScopeError),
    };

    // if it is positive, insert 1 in the address of `continue_loop`
    // else, insert 0
    if n.is_positive() {
        vm.memory
            .insert(&continue_loop_addr, &MaybeRelocatable::Int(bigint!(1)))
            .map_err(VirtualMachineError::MemoryError)
    } else {
        vm.memory
            .insert(&continue_loop_addr, &MaybeRelocatable::Int(bigint!(0)))
            .map_err(VirtualMachineError::MemoryError)
    }
}
