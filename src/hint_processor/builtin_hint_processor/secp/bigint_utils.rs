use crate::bigint;
use crate::hint_processor::builtin_hint_processor::hint_utils::{
    get_relocatable_from_var_name, insert_value_from_var_name,
};
use crate::hint_processor::builtin_hint_processor::secp::secp_utils::split;
use crate::hint_processor::builtin_hint_processor::secp::secp_utils::BASE_86;
use crate::hint_processor::hint_processor_definition::HintReference;
use crate::serde::deserialize_program::ApTracking;
use crate::types::exec_scope::ExecutionScopes;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::vm_core::VirtualMachine;

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
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let res_reloc = get_relocatable_from_var_name("res", vm, ids_data, ap_tracking)?;
    let value = exec_scopes.get_int_ref("value")?;
    let arg: Vec<BigInt> = split(value)?.to_vec();
    vm.write_arg(&res_reloc, &arg)
        .map_err(VirtualMachineError::MemoryError)?;
    Ok(())
}

// Implements hint
// %{ ids.low = (ids.x.d0 + ids.x.d1 * ids.BASE) & ((1 << 128) - 1) %}
pub fn bigint_to_uint256(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let x_struct = get_relocatable_from_var_name("x", vm, ids_data, ap_tracking)?;
    let d0 = vm.get_integer(&x_struct)?;
    let d1 = vm.get_integer(&(&x_struct + 1))?;
    let low = (d0 + d1 * &*BASE_86) & bigint!(u128::MAX);
    insert_value_from_var_name("low", low, vm, ids_data, ap_tracking)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::any_box;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
        BuiltinHintProcessor, HintProcessorData,
    };
    use crate::hint_processor::hint_processor_definition::HintProcessor;
    use crate::types::exec_scope::ExecutionScopes;
    use crate::types::relocatable::Relocatable;
    use crate::utils::test_utils::*;
    use crate::vm::runners::builtin_runner::RangeCheckBuiltinRunner;
    use crate::vm::vm_core::VirtualMachine;
    use crate::{bigint, bigint_str, types::relocatable::MaybeRelocatable};
    use num_bigint::Sign;
    use std::any::Any;

    #[test]
    fn run_nondet_bigint3_ok() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import split\n\nsegments.write_arg(ids.res.address_, split(value))";
        let mut vm = vm_with_range_check!();
        add_segments!(vm, 3);
        // initialize vm scope with variable `n`
        let mut exec_scopes = scope![(
            "value",
            bigint_str!(b"7737125245533626718119526477371252455336267181195264773712524553362")
        )];
        //Initialize RubContext
        run_context!(vm, 0, 6, 6);
        //Create hint_data
        let ids_data = non_continuous_ids_data![("res", 5)];
        assert_eq!(run_hint!(vm, ids_data, hint_code, &mut exec_scopes), Ok(()));
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
        //Initialize RubContext
        run_context!(vm, 0, 6, 6);
        //Create hint_data
        let ids_data = non_continuous_ids_data![("res", 5)];
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
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
        let mut exec_scopes = scope![("value", bigint!(-1))];
        //Create hint_data
        let ids_data = non_continuous_ids_data![("res", 5)];
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, &mut exec_scopes),
            Err(VirtualMachineError::SecpSplitNegative(bigint!(-1)))
        );
    }
}
