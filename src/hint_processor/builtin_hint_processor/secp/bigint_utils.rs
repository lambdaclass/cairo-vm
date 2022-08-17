use crate::bigint;
use crate::hint_processor::builtin_hint_processor::secp::secp_utils::split;
use crate::hint_processor::builtin_hint_processor::secp::secp_utils::BASE_86;
use crate::hint_processor::hint_processor_definition::HintReference;
use crate::hint_processor::hint_utils::{
    get_relocatable_from_var_name, insert_value_from_var_name,
};
use crate::serde::deserialize_program::ApTracking;
use crate::types::exec_scope::ExecutionScopesProxy;
use crate::vm::errors::vm_errors::VirtualMachineError;
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
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let res_reloc = get_relocatable_from_var_name("res", vm_proxy, ids_data, ap_tracking)?;
    let value = exec_scopes_proxy.get_int_ref("value")?;
    let arg: Vec<BigInt> = split(value)?.to_vec();
    vm_proxy
        .memory
        .write_arg(vm_proxy.segments, &res_reloc, &arg, Some(vm_proxy.prime))
        .map_err(VirtualMachineError::MemoryError)?;
    Ok(())
}

// Implements hint
// %{ ids.low = (ids.x.d0 + ids.x.d1 * ids.BASE) & ((1 << 128) - 1) %}
pub fn bigint_to_uint256(
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let x_struct = get_relocatable_from_var_name("x", vm_proxy, ids_data, ap_tracking)?;
    let d0 = vm_proxy.memory.get_integer(&x_struct)?;
    let d1 = vm_proxy.memory.get_integer(&(&x_struct + 1))?;
    let low = (d0 + d1 * &*BASE_86) & bigint!(u128::MAX);
    insert_value_from_var_name("low", low, vm_proxy, ids_data, ap_tracking)
}

#[cfg(test)]
mod tests {
    use crate::any_box;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
        get_vm_proxy, BuiltinHintProcessor, HintProcessorData,
    };
    use crate::hint_processor::hint_processor_definition::HintProcessor;
    use crate::vm::vm_core::VirtualMachine;
    use num_bigint::Sign;
    use std::any::Any;

    use super::*;
    use crate::types::exec_scope::{get_exec_scopes_proxy, ExecutionScopes};
    use crate::utils::test_utils::*;
    use crate::vm::runners::builtin_runner::RangeCheckBuiltinRunner;
    use crate::{bigint, bigint_str, types::relocatable::MaybeRelocatable};

    static HINT_EXECUTOR: BuiltinHintProcessor = BuiltinHintProcessor {};

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
            any_box!(bigint_str!(
                b"7737125245533626718119526477371252455336267181195264773712524553362"
            )),
        );
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 6));
        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 6));
        //Create hint_data
        let ids_data = HashMap::from([("res".to_string(), HintReference::new_simple(5))]);
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
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
        //Create hint_data
        let ids_data = HashMap::from([("res".to_string(), HintReference::new_simple(5))]);
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);

        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
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
        exec_scopes.assign_or_update_variable("value", any_box!(bigint!(-1)));
        //Create hint_data
        let ids_data = HashMap::from([("res".to_string(), HintReference::new_simple(5))]);
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::SecpSplitNegative(bigint!(-1)))
        );
    }
}
