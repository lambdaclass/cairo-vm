use crate::bigint;
use crate::serde::deserialize_program::ApTracking;
use crate::types::exec_scope::PyValueType;
use crate::types::relocatable::MaybeRelocatable;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::hint_utils::get_address_from_var_name;
use crate::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use num_traits::Signed;
use std::collections::HashMap;

//  Implements hint:
//  %{ vm_enter_scope({'n': ids.n}) %}
pub fn memset_enter_scope(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
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
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let continue_loop_addr = get_address_from_var_name("continue_loop", ids, vm, hint_ap_tracking)?;

    // get `n` variable from vm scope

    // get `n` variable from vm scope
    let n = match vm
        .exec_scopes
        .get_local_variables()
        .ok_or(VirtualMachineError::ScopeError)?
        .get("n")
    {
        Some(PyValueType::BigInt(n)) => n,
        _ => {
            return Err(VirtualMachineError::VariableNotInScopeError(String::from(
                "n",
            )))
        }
    };

    // this variable will hold the value of `n - 1`
    let new_n = n - 1_i32;

    // if `new_n` is positive, insert 1 in the address of `continue_loop`
    // else, insert 0
    let should_continue = bigint!(new_n.is_positive() as i32);
    vm.memory
        .insert(&continue_loop_addr, &MaybeRelocatable::Int(should_continue))
        .map_err(VirtualMachineError::MemoryError)?;

    // Reassign `n` with `n - 1`
    // we do it at the end of the function so that the borrow checker doesn't complain
    vm.exec_scopes
        .assign_or_update_variable("n", PyValueType::BigInt(new_n));

    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        types::instruction::Register,
        vm::{
            errors::memory_errors::MemoryError,
            hints::execute_hint::{BuiltinHintExecutor, HintReference},
        },
    };
    use num_bigint::Sign;

    static HINT_EXECUTOR: BuiltinHintExecutor = BuiltinHintExecutor {};

    #[test]
    fn memset_enter_scope_valid() {
        let hint_code = "vm_enter_scope({'n': ids.n})";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));

        // insert ids.n into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("n"), bigint!(0));

        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -2,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);

        assert!(vm
            .hint_executor
            .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new())
            .is_ok());
    }

    #[test]
    fn memset_enter_scope_invalid() {
        let hint_code = "vm_enter_scope({'n': ids.n})";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));

        // insert ids.n into memory
        // insert a relocatable value in the address of ids.len so that it raises an error.
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from((0, 0)),
            )
            .unwrap();

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("n"), bigint!(0));

        // create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -2,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 1))
            ))
        );
    }

    #[test]
    fn memset_continue_loop_valid_continue_loop_equal_1() {
        let hint_code = "n -= 1\nids.continue_loop = 1 if n > 0 else 0";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));

        // initialize vm scope with variable `n` = 1
        vm.exec_scopes
            .assign_or_update_variable("n", PyValueType::BigInt(bigint!(1)));

        // initialize ids.continue_loop
        // we create a memory gap so that there is None in (0, 1), the actual addr of continue_loop
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("continue_loop"), bigint!(0));

        // create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -2,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);

        assert!(vm
            .hint_executor
            .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new())
            .is_ok());

        // assert ids.continue_loop = 0
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
    }

    #[test]
    fn memset_continue_loop_valid_continue_loop_equal_5() {
        let hint_code = "n -= 1\nids.continue_loop = 1 if n > 0 else 0";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));

        // initialize vm scope with variable `n` = 5
        vm.exec_scopes
            .assign_or_update_variable("n", PyValueType::BigInt(bigint!(5)));

        // initialize ids.continue_loop
        // we create a memory gap so that there is None in (0, 1), the actual addr of continue_loop
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("continue_loop"), bigint!(0));

        // create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -2,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);

        assert!(vm
            .hint_executor
            .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new())
            .is_ok());

        // assert ids.continue_loop = 1
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1))))
        );
    }

    #[test]
    fn memset_continue_loop_variable_not_in_scope_error() {
        let hint_code = "n -= 1\nids.continue_loop = 1 if n > 0 else 0";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);
        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));

        // we don't initialize `n` now:
        /*  vm.exec_scopes
        .assign_or_update_variable("n", PyValueType::BigInt(bigint!(1)));  */

        // initialize ids.continue_loop
        // we create a memory gap so that there is None in (0, 1), the actual addr of continue_loop
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("continue_loop"), bigint!(0));

        // create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -2,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::VariableNotInScopeError(
                "n".to_string()
            ))
        );
    }

    #[test]
    fn memset_continue_loop_insert_error() {
        let hint_code = "n -= 1\nids.continue_loop = 1 if n > 0 else 0";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
            &HINT_EXECUTOR,
        );

        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));

        // initialize with variable `n`
        vm.exec_scopes
            .assign_or_update_variable("n", PyValueType::BigInt(bigint!(1)));

        // initialize ids.continue_loop
        // a value is written in the address so the hint cant insert value there
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("continue_loop"), bigint!(0));

        // create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::FP,
                offset1: -2,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
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
