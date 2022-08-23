use crate::bigint;
use crate::serde::deserialize_program::ApTracking;
use crate::types::exec_scope::ExecutionScopesProxy;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::hint_utils::{get_relocatable_from_var_name, insert_value_from_var_name};
use crate::vm::hints::secp::secp_utils::split;
use crate::vm::hints::secp::secp_utils::BASE_86;
use crate::vm::vm_core::VMProxy;

use num_bigint::BigInt;
use std::collections::HashMap;

/*
Implements hint:
%{
    from starkware.cairo.common.cairo_secp.secp_utils import split

    segments.write_arg(ids.res.address_, split(value))
%}
*/

pub fn nondet_bigint3(
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids: &HashMap<String, usize>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let res_reloc = get_relocatable_from_var_name("res", ids, vm_proxy, hint_ap_tracking)?;
    let value = exec_scopes_proxy.get_int_ref("value")?;
    let arg: Vec<BigInt> = split(value)?.to_vec();
    vm_proxy
        .segments
        .write_arg(vm_proxy.memory, &res_reloc, &arg, Some(vm_proxy.prime))
        .map_err(VirtualMachineError::MemoryError)?;
    Ok(())
}

// Implements hint
// %{ ids.low = (ids.x.d0 + ids.x.d1 * ids.BASE) & ((1 << 128) - 1) %}
pub fn bigint_to_uint256(
    vm_proxy: &mut VMProxy,
    ids: &HashMap<String, usize>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let x_struct = get_relocatable_from_var_name("x", ids, vm_proxy, hint_ap_tracking)?;
    let d0 = vm_proxy.memory.get_integer(&x_struct)?;
    let d1 = vm_proxy.memory.get_integer(&(&x_struct + 1))?;
    let low = (d0 + d1 * &*BASE_86) & bigint!(u128::MAX);
    insert_value_from_var_name("low", low, ids, vm_proxy, hint_ap_tracking)
}

#[cfg(test)]
mod tests {
    use crate::vm::vm_core::VirtualMachine;
    use num_bigint::Sign;

    use super::*;
    use crate::types::exec_scope::{get_exec_scopes_proxy, ExecutionScopes, PyValueType};
    use crate::types::hint_executor::HintExecutor;
    use crate::utils::test_utils::*;
    use crate::vm::hints::execute_hint::get_vm_proxy;
    use crate::vm::runners::builtin_runner::RangeCheckBuiltinRunner;
    use crate::{
        bigint, bigint_str,
        types::relocatable::MaybeRelocatable,
        vm::hints::execute_hint::{BuiltinHintExecutor, HintReference},
    };

    static HINT_EXECUTOR: BuiltinHintExecutor = BuiltinHintExecutor {};

    #[test]
    fn run_nondet_bigint3_ok() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import split\n\nsegments.write_arg(ids.res.address_, split(value))";
        let mut vm = vm_with_range_check!();
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        // initialize vm scope with variable `n`
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable(
            "value",
            PyValueType::BigInt(bigint_str!(
                b"7737125245533626718119526477371252455336267181195264773712524553362"
            )),
        );
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 6));
        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 6));
        //Create ids
        let ids = ids!["res"];
        //Create references
        vm.references = HashMap::from([(0, HintReference::new_simple(5))]);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(
                vm_proxy,
                exec_scopes_proxy,
                hint_code,
                &ids,
                &ApTracking::default()
            ),
            Ok(())
        );
        //Check hint memory inserts
        check_memory![
            &vm.memory,
            ((1, 11), 773712524553362_u64),
            ((1, 12), 57408430697461422066401280_u128),
            ((1, 13), 1292469707114105_u64)
        ];
    }

    #[test]
    fn run_nondet_bigint3_value_not_in_scope() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import split\n\nsegments.write_arg(ids.res.address_, split(value))";
        let mut vm = vm_with_range_check!();
        // we don't initialize `value` now:
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 6));

        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 6));

        //Create ids
        let ids = ids!["res"];

        //Create references
        vm.references = HashMap::from([(0, HintReference::new_simple(5))]);

        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(
                vm_proxy,
                exec_scopes_proxy_ref!(),
                hint_code,
                &ids,
                &ApTracking::default()
            ),
            Err(VirtualMachineError::VariableNotInScopeError(
                "value".to_string()
            ))
        );
    }

    #[test]
    fn run_nondet_bigint3_split_error() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import split\n\nsegments.write_arg(ids.res.address_, split(value))";
        let mut vm = vm_with_range_check!();

        // initialize vm scope with variable `n`
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("value", PyValueType::BigInt(bigint!(-1)));
        let ids = ids!["res"];
        //Create references
        vm.references = HashMap::from([(0, HintReference::new_simple(5))]);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(
                vm_proxy,
                exec_scopes_proxy,
                hint_code,
                &ids,
                &ApTracking::default()
            ),
            Err(VirtualMachineError::SecpSplitNegative(bigint!(-1)))
        );
    }
}
