use crate::bigint;
use crate::hint_processor::builtin_hint_processor::hint_utils::{
    insert_value_from_var_name, insert_value_into_ap,
};
use crate::hint_processor::builtin_hint_processor::secp::secp_utils::SECP_P;
use crate::hint_processor::hint_processor_definition::HintReference;
use crate::hint_processor::proxies::exec_scopes_proxy::ExecutionScopesProxy;
use crate::math_utils::div_mod;
use crate::serde::deserialize_program::ApTracking;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::Zero;
use std::collections::HashMap;

use super::secp_utils::pack_from_var_name;

/*
Implements hint:
%{
    from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack

    q, r = divmod(pack(ids.val, PRIME), SECP_P)
    assert r == 0, f"verify_zero: Invalid input {ids.val.d0, ids.val.d1, ids.val.d2}."
    ids.q = q % PRIME
%}
*/
pub fn verify_zero(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let val = pack_from_var_name("val", vm, ids_data, ap_tracking)?;
    let (q, r) = val.div_rem(&SECP_P);

    if !r.is_zero() {
        return Err(VirtualMachineError::SecpVerifyZero(val));
    }

    insert_value_from_var_name("q", q.mod_floor(vm.get_prime()), vm, ids_data, ap_tracking)
}

/*
Implements hint:
%{
    from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack

    value = pack(ids.x, PRIME) % SECP_P
%}
*/
pub fn reduce(
    vm: &mut VirtualMachine,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let value = pack_from_var_name("x", vm, ids_data, ap_tracking)?.mod_floor(&SECP_P);
    exec_scopes_proxy.insert_value("value", value);
    Ok(())
}

/*
Implements hint:
%{
    from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack

    x = pack(ids.x, PRIME) % SECP_P
%}
*/
pub fn is_zero_pack(
    vm: &mut VirtualMachine,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let x_packed = pack_from_var_name("x", vm, ids_data, ap_tracking)?;
    let x = x_packed.mod_floor(&SECP_P);
    exec_scopes_proxy.insert_value("x", x);
    Ok(())
}

/*
Implements hint:
in .cairo program
if nondet %{ x == 0 %} != 0:

On .json compiled program
"memory[ap] = to_felt_or_relocatable(x == 0)"
*/
pub fn is_zero_nondet(
    vm: &mut VirtualMachine,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
) -> Result<(), VirtualMachineError> {
    //Get `x` variable from vm scope
    let x = exec_scopes_proxy.get_int("x")?;

    let value = bigint!(x.is_zero() as usize);
    insert_value_into_ap(vm, value)
}

/*
Implements hint:
%{
    from starkware.cairo.common.cairo_secp.secp_utils import SECP_P
    from starkware.python.math_utils import div_mod

    value = x_inv = div_mod(1, x, SECP_P)
%}
*/
pub fn is_zero_assign_scope_variables(
    exec_scopes_proxy: &mut ExecutionScopesProxy,
) -> Result<(), VirtualMachineError> {
    //Get `x` variable from vm scope
    let x = exec_scopes_proxy.get_int("x")?;

    let value = div_mod(&bigint!(1), &x, &SECP_P);
    exec_scopes_proxy.insert_value("value", value.clone());
    exec_scopes_proxy.insert_value("x_inv", value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::any_box;
    use crate::bigint;
    use crate::bigint_str;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData;
    use crate::hint_processor::hint_processor_definition::HintProcessor;
    use crate::hint_processor::proxies::exec_scopes_proxy::get_exec_scopes_proxy;
    use crate::types::exec_scope::ExecutionScopes;
    use crate::types::relocatable::MaybeRelocatable;
    use crate::types::relocatable::Relocatable;
    use crate::utils::test_utils::*;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::vm::runners::builtin_runner::RangeCheckBuiltinRunner;
    use crate::vm::vm_core::VirtualMachine;
    use crate::vm::vm_memory::memory::Memory;
    use num_bigint::Sign;
    use std::any::Any;

    from_bigint_str![42];

    #[test]
    fn run_verify_zero_ok() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nq, r = divmod(pack(ids.val, PRIME), SECP_P)\nassert r == 0, f\"verify_zero: Invalid input {ids.val.d0, ids.val.d1, ids.val.d2}.\"\nids.q = q % PRIME";
        let mut vm = vm_with_range_check!();
        //Initialize run_context
        run_context!(vm, 0, 9, 9);
        //Create hint data
        let ids_data = non_continuous_ids_data![("val", -5), ("q", 0)];
        vm.memory = memory![((1, 4), 0), ((1, 5), 0), ((1, 6), 0)];
        //Execute the hint
        assert_eq!(run_hint!(vm, ids_data, hint_code), Ok(()));
        //Check hint memory inserts
        //ids.q
        check_memory![&vm.memory, ((1, 9), 0)];
    }

    #[test]
    fn run_verify_zero_error() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nq, r = divmod(pack(ids.val, PRIME), SECP_P)\nassert r == 0, f\"verify_zero: Invalid input {ids.val.d0, ids.val.d1, ids.val.d2}.\"\nids.q = q % PRIME";
        let mut vm = vm_with_range_check!();
        add_segments!(vm, 3);
        //Initialize run_context
        run_context!(vm, 0, 9, 9);
        //Create hint data
        let ids_data = non_continuous_ids_data![("val", -5), ("q", 0)];
        vm.memory = memory![((1, 4), 0), ((1, 5), 0), ((1, 6), 150)];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::SecpVerifyZero(bigint_str!(
                b"897946605976106752944343961220884287276604954404454400"
            ),))
        );
    }

    #[test]
    fn run_verify_zero_invalid_memory_insert() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nq, r = divmod(pack(ids.val, PRIME), SECP_P)\nassert r == 0, f\"verify_zero: Invalid input {ids.val.d0, ids.val.d1, ids.val.d2}.\"\nids.q = q % PRIME";
        let mut vm = vm_with_range_check!();
        add_segments!(vm, 3);

        //Initialize run_context
        run_context!(vm, 0, 9, 9);

        //Create hint data
        let ids_data = non_continuous_ids_data![("val", -5), ("q", 0)];
        vm.memory = memory![((1, 4), 0), ((1, 5), 0), ((1, 6), 0), ((1, 9), 55)];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((1, 9)),
                    MaybeRelocatable::from(bigint!(55)),
                    MaybeRelocatable::from(bigint!(0))
                )
            ))
        );
    }

    #[test]
    fn run_reduce_ok() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nvalue = pack(ids.x, PRIME) % SECP_P";
        let mut vm = vm_with_range_check!();
        add_segments!(vm, 3);

        //Initialize fp
        vm.run_context.fp = 25;

        //Create hint data
        let ids_data = non_continuous_ids_data![("x", -5)];

        vm.memory = memory![
            ((1, 20), (b"132181232131231239112312312313213083892150", 10)),
            ((1, 21), 10),
            ((1, 22), 10)
        ];

        let mut exec_scopes = ExecutionScopes::new();
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy),
            Ok(())
        );

        //Check 'value' is defined in the vm scope
        assert_eq!(
            exec_scopes_proxy.get_int("value"),
            Ok(bigint_str!(
                b"59863107065205964761754162760883789350782881856141750"
            ))
        );
    }

    #[test]
    fn run_reduce_error() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nvalue = pack(ids.x, PRIME) % SECP_P";
        let mut vm = vm_with_range_check!();
        add_segments!(vm, 3);

        //Initialize fp
        vm.run_context.fp = 25;

        //Create hint data
        let ids_data = HashMap::from([("x".to_string(), HintReference::new_simple(-5))]);
        //Skip ids.x values insert so the hint fails.
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 20))
            ))
        );
    }

    #[test]
    fn run_is_zero_pack_ok() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nx = pack(ids.x, PRIME) % SECP_P";
        let mut vm = vm_with_range_check!();

        //Initialize fp
        vm.run_context.fp = 15;

        //Create hint data
        let ids_data = HashMap::from([("x".to_string(), HintReference::new_simple(-5))]);
        //Insert ids.x.d0, ids.x.d1, ids.x.d2 into memory
        vm.memory = memory![
            ((1, 10), 232113757366008801543585_i128),
            ((1, 11), 232113757366008801543585_i128),
            ((1, 12), 232113757366008801543585_i128)
        ];

        let mut exec_scopes = ExecutionScopes::new();

        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy),
            Ok(())
        );

        //Check 'x' is defined in the vm scope
        check_scope!(
            exec_scopes_proxy,
            [(
                "x",
                bigint_str!(
                    b"1389505070847794345082847096905107459917719328738389700703952672838091425185"
                )
            )]
        );
    }

    #[test]
    fn run_is_zero_pack_error() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nx = pack(ids.x, PRIME) % SECP_P";
        let mut vm = vm_with_range_check!();

        //Initialize fp
        vm.run_context.fp = 15;

        //Create hint data
        let ids_data = HashMap::from([("x".to_string(), HintReference::new_simple(-5))]);

        //Skip ids.x.d0, ids.x.d1, ids.x.d2 inserts so the hints fails

        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 10))
            ))
        );
    }

    #[test]
    fn run_is_zero_nondet_ok_true() {
        let hint_code = "memory[ap] = to_felt_or_relocatable(x == 0)";
        let mut vm = vm_with_range_check!();

        //Initialize memory
        add_segments!(vm, 2);

        //Initialize ap
        vm.run_context.ap = 15;

        let mut exec_scopes = ExecutionScopes::new();
        //Initialize vm scope with variable `x`
        exec_scopes.assign_or_update_variable("x", any_box!(bigint!(0i32)));
        //Create hint data
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, HashMap::new(), hint_code, exec_scopes_proxy),
            Ok(())
        );

        //Check hint memory insert
        //memory[ap] = to_felt_or_relocatable(x == 0)
        check_memory!(&vm.memory, ((1, 15), 1));
    }

    #[test]
    fn run_is_zero_nondet_ok_false() {
        let hint_code = "memory[ap] = to_felt_or_relocatable(x == 0)";
        let mut vm = vm_with_range_check!();

        //Initialize memory
        add_segments!(vm, 2);

        //Initialize ap
        vm.run_context.ap = 15;

        //Initialize vm scope with variable `x`
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("x", any_box!(bigint!(123890i32)));

        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, HashMap::new(), hint_code, exec_scopes_proxy),
            Ok(())
        );

        //Check hint memory insert
        //memory[ap] = to_felt_or_relocatable(x == 0)
        check_memory!(&vm.memory, ((1, 15), 0));
    }

    #[test]
    fn run_is_zero_nondet_scope_error() {
        let hint_code = "memory[ap] = to_felt_or_relocatable(x == 0)";
        let mut vm = vm_with_range_check!();

        //Initialize memory
        add_segments!(vm, 2);

        //Initialize ap
        vm.run_context.ap = 15;

        //Skip `x` assignment

        //Execute the hint
        assert_eq!(
            run_hint!(vm, HashMap::new(), hint_code),
            Err(VirtualMachineError::VariableNotInScopeError(
                "x".to_string()
            ))
        );
    }

    #[test]
    fn run_is_zero_nondet_invalid_memory_insert() {
        let hint_code = "memory[ap] = to_felt_or_relocatable(x == 0)";
        let mut vm = vm_with_range_check!();

        //Insert a value in ap before the hint execution, so the hint memory insert fails
        vm.memory = memory![((1, 15), 55)];

        //Initialize ap
        vm.run_context.ap = 15;

        //Initialize vm scope with variable `x`
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("x", any_box!(bigint!(0)));
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, HashMap::new(), hint_code, exec_scopes_proxy),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from(vm.run_context.get_ap()),
                    MaybeRelocatable::from(bigint!(55i32)),
                    MaybeRelocatable::from(bigint!(1i32))
                )
            ))
        );
    }

    #[test]
    fn is_zero_assign_scope_variables_ok() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P\nfrom starkware.python.math_utils import div_mod\n\nvalue = x_inv = div_mod(1, x, SECP_P)";
        let mut vm = vm_with_range_check!();

        //Initialize vm scope with variable `x`
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable(
            "x",
            any_box!(bigint_str!(
                b"52621538839140286024584685587354966255185961783273479086367"
            )),
        );
        //Execute the hint
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, HashMap::new(), hint_code, exec_scopes_proxy),
            Ok(())
        );

        //Check 'value' is defined in the vm scope
        assert_eq!(
            exec_scopes_proxy.get_int("value"),
            Ok(bigint_str!(
                b"19429627790501903254364315669614485084365347064625983303617500144471999752609"
            ))
        );

        //Check 'x_inv' is defined in the vm scope
        assert_eq!(
            exec_scopes_proxy.get_int("x_inv"),
            Ok(bigint_str!(
                b"19429627790501903254364315669614485084365347064625983303617500144471999752609"
            ))
        );
    }

    #[test]
    fn is_zero_assign_scope_variables_scope_error() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P\nfrom starkware.python.math_utils import div_mod\n\nvalue = x_inv = div_mod(1, x, SECP_P)";
        let mut vm = vm_with_range_check!();
        //Skip `x` assignment
        //Execute the hint
        assert_eq!(
            run_hint!(vm, HashMap::new(), hint_code),
            Err(VirtualMachineError::VariableNotInScopeError(
                "x".to_string()
            ))
        );
    }
}
