use crate::bigint;
use crate::math_utils::{ec_double_slope, line_slope};
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

/*
Implements hint:
%{
    from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack
    from starkware.python.math_utils import line_slope

    # Compute the slope.
    x0 = pack(ids.point0.x, PRIME)
    y0 = pack(ids.point0.y, PRIME)
    x1 = pack(ids.point1.x, PRIME)
    y1 = pack(ids.point1.y, PRIME)
    value = slope = line_slope(point1=(x0, y0), point2=(x1, y1), p=SECP_P)
%}
*/
pub fn compute_slope(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    //ids.point0
    let point0_reloc = get_relocatable_from_var_name("point0", ids, vm, hint_ap_tracking)?;

    let (point0_x_d0, point0_x_d1, point0_x_d2, point0_y_d0, point0_y_d1, point0_y_d2) = (
        get_integer_from_relocatable_plus_offset(&point0_reloc, 0, vm)?,
        get_integer_from_relocatable_plus_offset(&point0_reloc, 1, vm)?,
        get_integer_from_relocatable_plus_offset(&point0_reloc, 2, vm)?,
        get_integer_from_relocatable_plus_offset(&point0_reloc, 3, vm)?,
        get_integer_from_relocatable_plus_offset(&point0_reloc, 4, vm)?,
        get_integer_from_relocatable_plus_offset(&point0_reloc, 5, vm)?,
    );

    //ids.point1
    let point1_reloc = get_relocatable_from_var_name("point1", ids, vm, hint_ap_tracking)?;

    let (point1_x_d0, point1_x_d1, point1_x_d2, point1_y_d0, point1_y_d1, point1_y_d2) = (
        get_integer_from_relocatable_plus_offset(&point1_reloc, 0, vm)?,
        get_integer_from_relocatable_plus_offset(&point1_reloc, 1, vm)?,
        get_integer_from_relocatable_plus_offset(&point1_reloc, 2, vm)?,
        get_integer_from_relocatable_plus_offset(&point1_reloc, 3, vm)?,
        get_integer_from_relocatable_plus_offset(&point1_reloc, 4, vm)?,
        get_integer_from_relocatable_plus_offset(&point1_reloc, 5, vm)?,
    );

    let value = line_slope(
        (
            pack(point0_x_d0, point0_x_d1, point0_x_d2, &vm.prime),
            pack(point0_y_d0, point0_y_d1, point0_y_d2, &vm.prime),
        ),
        (
            pack(point1_x_d0, point1_x_d1, point1_x_d2, &vm.prime),
            pack(point1_y_d0, point1_y_d1, point1_y_d2, &vm.prime),
        ),
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
    use crate::vm::hints::execute_hint::{execute_hint, HintReference};
    use crate::vm::runners::builtin_runner::RangeCheckBuiltinRunner;
    use crate::vm::vm_memory::memory::Memory;

    #[test]
    fn run_ec_negate_ok() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\ny = pack(ids.point.y, PRIME) % SECP_P\n# The modulo operation in python always returns a nonnegative number.\nvalue = (-y) % SECP_P".as_bytes();
        let mut vm = VirtualMachine::new(
            VM_PRIME.clone(),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );

        vm.memory = memory![((1, 3), 2645), ((1, 4), 454), ((1, 5), 206)];

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 8));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("point"), bigint!(0));

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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::new()),
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
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\nfrom starkware.python.math_utils import ec_double_slope\n\n# Compute the slope.\nx = pack(ids.point.x, PRIME)\ny = pack(ids.point.y, PRIME)\nvalue = slope = ec_double_slope(point=(x, y), alpha=0, p=SECP_P)".as_bytes();
        let mut vm = VirtualMachine::new(
            VM_PRIME.clone(),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );

        vm.memory = memory![
            ((1, 0), 614323),
            ((1, 1), 5456867),
            ((1, 2), 101208),
            ((1, 3), 773712524),
            ((1, 4), 77371252),
            ((1, 5), 5298795)
        ];

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 8));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("point"), bigint!(0));

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
            execute_hint(&mut vm, hint_code, ids, &ApTracking::new()),
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
