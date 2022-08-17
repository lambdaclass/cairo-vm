use crate::bigint;
use crate::serde::deserialize_program::ApTracking;
use crate::types::exec_scope::ExecutionScopesProxy;

use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::vm_core::VMProxy;
use num_bigint::BigInt;
use num_traits::Signed;
use std::any::Any;
use std::collections::HashMap;

use super::execute_hint::HintReference;
use super::hint_utils::get_integer_from_var_name;
use super::hint_utils::insert_value_from_var_name;

//  Implements hint:
//  %{ vm_enter_scope({'n': ids.n}) %}
pub fn memset_enter_scope(
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let n: Box<dyn Any> =
        Box::new(get_integer_from_var_name("n", &vm_proxy, ids_data, ap_tracking)?.clone());
    exec_scopes_proxy.enter_scope(HashMap::from([(String::from("n"), n)]));
    Ok(())
}

/* Implements hint:
%{
    n -= 1
    ids.continue_loop = 1 if n > 0 else 0
%}
*/
pub fn memset_continue_loop(
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    // get `n` variable from vm scope
    let n = exec_scopes_proxy.get_int_ref("n")?;
    // this variable will hold the value of `n - 1`
    let new_n = n - 1_i32;
    // if `new_n` is positive, insert 1 in the address of `continue_loop`
    // else, insert 0
    let should_continue = bigint!(new_n.is_positive() as i32);
    insert_value_from_var_name(
        "continue_loop",
        should_continue,
        vm_proxy,
        ids_data,
        ap_tracking,
    )?;
    // Reassign `n` with `n - 1`
    // we do it at the end of the function so that the borrow checker doesn't complain
    exec_scopes_proxy.insert_value("n", new_n);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::any_box;
    use crate::types::exec_scope::{get_exec_scopes_proxy, ExecutionScopes};
    use crate::utils::test_utils::*;
    use crate::vm::hints::execute_hint::{BuiltinHintExecutor, HintProcessorData};
    use crate::vm::vm_memory::memory::Memory;
    use crate::{
        types::relocatable::MaybeRelocatable,
        vm::{
            errors::memory_errors::MemoryError,
            hints::execute_hint::{get_vm_proxy, HintReference},
            vm_core::VirtualMachine,
        },
    };
    use num_bigint::Sign;

    static HINT_EXECUTOR: BuiltinHintExecutor = BuiltinHintExecutor {};
    use crate::types::hint_executor::HintExecutor;

    #[test]
    fn memset_enter_scope_valid() {
        let hint_code = "vm_enter_scope({'n': ids.n})";
        let mut vm = vm!();
        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        // insert ids into memory
        vm.memory = memory![((0, 1), 5)];
        let ids_data = ids_data!["n"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Create references
        vm.references = HashMap::from([(0, HintReference::new_simple(-2))]);
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert!(HINT_EXECUTOR
            .execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data))
            .is_ok());
    }

    #[test]
    fn memset_enter_scope_invalid() {
        let hint_code = "vm_enter_scope({'n': ids.n})";
        let mut vm = vm!();
        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        // insert ids.n into memory
        // insert a relocatable value in the address of ids.len so that it raises an error.
        vm.memory = memory![((0, 1), (0, 0))];
        let ids_data = ids_data!["n"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        // create references
        vm.references = HashMap::from([(0, HintReference::new_simple(-2))]);
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 1))
            ))
        );
    }

    #[test]
    fn memset_continue_loop_valid_continue_loop_equal_1() {
        let hint_code = "n -= 1\nids.continue_loop = 1 if n > 0 else 0";
        let mut vm = vm!();
        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        // initialize vm scope with variable `n` = 1
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("n", any_box!(bigint!(1)));
        // initialize ids.continue_loop
        // we create a memory gap so that there is None in (0, 0), the actual addr of continue_loop
        vm.memory = memory![((0, 1), 5)];
        let mut ids_data = ids_data!["continue_loop"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert!(HINT_EXECUTOR
            .execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data))
            .is_ok());

        // assert ids.continue_loop = 0
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
    }

    #[test]
    fn memset_continue_loop_valid_continue_loop_equal_5() {
        let hint_code = "n -= 1\nids.continue_loop = 1 if n > 0 else 0";
        let mut vm = vm!();
        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));

        // initialize vm scope with variable `n` = 5
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("n", any_box!(bigint!(5)));

        // initialize ids.continue_loop
        // we create a memory gap so that there is None in (0, 0), the actual addr of continue_loop
        vm.memory = memory![((0, 2), 5)];
        let mut ids = HashMap::<String, BigInt>::new();
        let mut ids_data = ids_data!["continue_loop"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert!(HINT_EXECUTOR
            .execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data))
            .is_ok());

        // assert ids.continue_loop = 1
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1))))
        );
    }

    #[test]
    fn memset_continue_loop_variable_not_in_scope_error() {
        let hint_code = "n -= 1\nids.continue_loop = 1 if n > 0 else 0";
        let mut vm = vm!();
        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));

        // we don't initialize `n` now:
        /*  vm.exec_scopes
        .assign_or_update_variable("n",  bigint!(1)));  */

        // initialize ids.continue_loop
        // we create a memory gap so that there is None in (0, 1), the actual addr of continue_loop
        vm.memory = memory![((0, 2), 5)];
        let ids_data = ids_data!["continue_loop"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
            Err(VirtualMachineError::VariableNotInScopeError(
                "n".to_string()
            ))
        );
    }

    #[test]
    fn memset_continue_loop_insert_error() {
        let hint_code = "n -= 1\nids.continue_loop = 1 if n > 0 else 0";
        let mut vm = vm!();
        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        // initialize with variable `n`
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("n", any_box!(bigint!(1)));
        // initialize ids.continue_loop
        // a value is written in the address so the hint cant insert value there
        vm.memory = memory![((0, 0), 5)];
        let ids_data = ids_data!["continue_loop"];
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((0, 1)),
                    MaybeRelocatable::from(bigint!(5)),
                    MaybeRelocatable::from(bigint!(0))
                )
            ))
        );
    }
}
