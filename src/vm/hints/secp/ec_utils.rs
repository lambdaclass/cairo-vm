use crate::bigint;
use crate::math_utils::ec_double_slope;
use crate::serde::deserialize_program::ApTracking;
use crate::types::exec_scope::PyValueType;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::hint_utils::{
    get_integer_from_relocatable_plus_offset, get_relocatable_from_var_name,
};
use crate::vm::hints::secp::secp_utils::{pack, SECP_P};
use crate::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use num_integer::Integer;
use std::collections::HashMap;

/*
Implements hint:
%{
    from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack

    y = pack(ids.point.y, PRIME) % SECP_P
    # The modulo operation in python always returns a nonnegative number.
    value = (-y) % SECP_P
%}
*/
pub fn ec_negate(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    //ids.point
    let point_reloc = get_relocatable_from_var_name("point", ids, vm, hint_ap_tracking)?;

    //ids.point.y
    let (y_d0, y_d1, y_d2) = (
        get_integer_from_relocatable_plus_offset(&point_reloc, 3, vm)?,
        get_integer_from_relocatable_plus_offset(&point_reloc, 4, vm)?,
        get_integer_from_relocatable_plus_offset(&point_reloc, 5, vm)?,
    );
    let value = (-pack(y_d0, y_d1, y_d2, &vm.prime)).mod_floor(&SECP_P);

    vm.exec_scopes
        .assign_or_update_variable("value", PyValueType::BigInt(value));

    Ok(())
}

/*
Implements hint:
%{
    from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack
    from starkware.python.math_utils import ec_double_slope

    # Compute the slope.
    x = pack(ids.point.x, PRIME)
    y = pack(ids.point.y, PRIME)
    value = slope = ec_double_slope(point=(x, y), alpha=0, p=SECP_P)
%}
*/
pub fn compute_doubling_slope(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    //ids.point
    let point_reloc = get_relocatable_from_var_name("point", ids, vm, hint_ap_tracking)?;

    let (x_d0, x_d1, x_d2, y_d0, y_d1, y_d2) = (
        get_integer_from_relocatable_plus_offset(&point_reloc, 0, vm)?,
        get_integer_from_relocatable_plus_offset(&point_reloc, 1, vm)?,
        get_integer_from_relocatable_plus_offset(&point_reloc, 2, vm)?,
        get_integer_from_relocatable_plus_offset(&point_reloc, 3, vm)?,
        get_integer_from_relocatable_plus_offset(&point_reloc, 4, vm)?,
        get_integer_from_relocatable_plus_offset(&point_reloc, 5, vm)?,
    );

    let value = ec_double_slope(
        (
            pack(x_d0, x_d1, x_d2, &vm.prime),
            pack(y_d0, y_d1, y_d2, &vm.prime),
        ),
        &bigint!(0),
        &SECP_P,
    );

    vm.exec_scopes
        .assign_or_update_variable("value", PyValueType::BigInt(value.clone()));

    vm.exec_scopes
        .assign_or_update_variable("slope", PyValueType::BigInt(value));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint_str;
    use crate::types::instruction::Register;
    use crate::types::relocatable::MaybeRelocatable;
    use crate::utils::test_utils::*;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::vm::hints::execute_hint::{BuiltinHintExecutor, HintReference};
    use crate::vm::runners::builtin_runner::RangeCheckBuiltinRunner;
    use crate::vm::vm_memory::memory::Memory;

    static HINT_EXECUTOR: BuiltinHintExecutor = BuiltinHintExecutor {};

    #[test]
    fn run_ec_negate_ok() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\ny = pack(ids.point.y, PRIME) % SECP_P\n# The modulo operation in python always returns a nonnegative number.\nvalue = (-y) % SECP_P";
        let mut vm = VirtualMachine::new(
            VM_PRIME.clone(),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8i32), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );

        vm.memory = memory![((1, 3), 2645i32), ((1, 4), 454i32), ((1, 5), 206i32)];

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 8));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("point"), bigint!(0i32));

        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -8,
                offset2: 0,
                inner_dereference: false,
                immediate: None,
                ap_tracking_data: Some(ApTracking {
                    group: 1,
                    offset: 0,
                }),
            },
        )]);

        //Check 'value' is not defined in the vm scope
        assert_eq!(
            vm.exec_scopes.get_local_variables().unwrap().get("value"),
            None
        );

        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Ok(())
        );

        //Check 'value' is defined in the vm scope
        assert_eq!(
            vm.exec_scopes.get_local_variables().unwrap().get("value"),
            Some(&PyValueType::BigInt(bigint_str!(
                b"115792089237316195423569751828682367333329274433232027476421668138471189901786"
            )))
        );
    }

    #[test]
    fn run_compute_doubling_slope_ok() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\nfrom starkware.python.math_utils import ec_double_slope\n\n# Compute the slope.\nx = pack(ids.point.x, PRIME)\ny = pack(ids.point.y, PRIME)\nvalue = slope = ec_double_slope(point=(x, y), alpha=0, p=SECP_P)";
        let mut vm = VirtualMachine::new(
            VM_PRIME.clone(),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8i32), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );

        vm.memory = memory![
            ((1, 0), 614323u64),
            ((1, 1), 5456867u64),
            ((1, 2), 101208u64),
            ((1, 3), 773712524u64),
            ((1, 4), 77371252u64),
            ((1, 5), 5298795u64)
        ];

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 8));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("point"), bigint!(0i32));

        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -8,
                offset2: 0,
                inner_dereference: false,
                immediate: None,
                ap_tracking_data: Some(ApTracking {
                    group: 1,
                    offset: 0,
                }),
            },
        )]);

        //Check 'value' is not defined in the vm scope
        assert_eq!(
            vm.exec_scopes.get_local_variables().unwrap().get("value"),
            None
        );

        //Check 'slope' is not defined in the vm scope
        assert_eq!(
            vm.exec_scopes.get_local_variables().unwrap().get("slope"),
            None
        );

        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Ok(())
        );

        //Check 'value' is defined in the vm scope
        assert_eq!(
            vm.exec_scopes.get_local_variables().unwrap().get("value"),
            Some(&PyValueType::BigInt(bigint_str!(
                b"40442433062102151071094722250325492738932110061897694430475034100717288403728"
            )))
        );

        //Check 'slope' is defined in the vm scope
        assert_eq!(
            vm.exec_scopes.get_local_variables().unwrap().get("slope"),
            Some(&PyValueType::BigInt(bigint_str!(
                b"40442433062102151071094722250325492738932110061897694430475034100717288403728"
            )))
        );
    }
}
