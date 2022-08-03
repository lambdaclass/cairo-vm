use crate::{
    bigint,
    serde::deserialize_program::ApTracking,
    types::exec_scope::PyValueType,
    vm::{
        errors::vm_errors::VirtualMachineError,
        hints::{
            hint_utils::{get_relocatable_from_var_name, insert_integer_from_var_name},
            secp::secp_utils::{split, BASE_86},
        },
        vm_core::VirtualMachine,
    },
};

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
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let res_reloc = get_relocatable_from_var_name("res", ids, vm, hint_ap_tracking)?;

    // get `value` variable from vm scope
    let value: &BigInt = match vm
        .exec_scopes
        .get_local_variables()
        .ok_or(VirtualMachineError::ScopeError)?
        .get("value")
    {
        Some(PyValueType::BigInt(value)) => value,
        _ => {
            return Err(VirtualMachineError::VariableNotInScopeError(String::from(
                "value",
            )))
        }
    };

    let arg: Vec<BigInt> = split(value)?.to_vec();

    vm.segments
        .write_arg(&mut vm.memory, &res_reloc, &arg, Some(&vm.prime))
        .map_err(VirtualMachineError::MemoryError)?;

    Ok(())
}

// Implements hint
// %{ ids.low = (ids.x.d0 + ids.x.d1 * ids.BASE) & ((1 << 128) - 1) %}
pub fn bigint_to_uint256(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let x_struct = get_relocatable_from_var_name("x", ids, vm, hint_ap_tracking)?;
    let d0 = vm.memory.get_integer(&x_struct)?;
    let d1 = vm.memory.get_integer(&(&x_struct + 1))?;
    let low = (d0 + d1 * &*BASE_86) & bigint!(u128::MAX);
    insert_integer_from_var_name("low", low, ids, vm, hint_ap_tracking)
}

#[cfg(test)]
mod tests {
    use num_bigint::Sign;

    use super::*;
    use crate::{
        bigint, bigint_str,
        types::{instruction::Register, relocatable::MaybeRelocatable},
        vm::{
            hints::execute_hint::{execute_hint, HintReference},
            runners::builtin_runner::RangeCheckBuiltinRunner,
        },
    };

    #[test]
    fn run_nondet_bigint3_ok() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import split\n\nsegments.write_arg(ids.res.address_, split(value))".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        // initialize vm scope with variable `n`
        vm.exec_scopes.assign_or_update_variable(
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("res"), bigint!(0));

        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::AP,
                offset1: 5,
                offset2: 0,
                inner_dereference: false,
                immediate: None,
                ap_tracking_data: Some(ApTracking {
                    group: 0,
                    offset: 0,
                }),
            },
        )]);

        //Create AP tracking
        let _ap_tracking = ApTracking {
            group: 0,
            offset: 0,
        };

        //Execute the hint

        //Create AP tracking
        let ap_tracking = ApTracking {
            group: 0,
            offset: 0,
        };

        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids, &ap_tracking), Ok(()));

        //Check hint memory inserts
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 11))),
            Ok(Some(&MaybeRelocatable::from(bigint_str!(
                b"773712524553362"
            ))))
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 12))),
            Ok(Some(&MaybeRelocatable::from(bigint_str!(
                b"57408430697461422066401280"
            ))))
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 13))),
            Ok(Some(&MaybeRelocatable::from(bigint_str!(
                b"1292469707114105"
            ))))
        );
    }

    #[test]
    fn run_nondet_bigint3_value_not_in_scope() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import split\n\nsegments.write_arg(ids.res.address_, split(value))".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        // we don't initialize `value` now:
        // vm.exec_scopes
        //     .assign_or_update_variable("value", PyValueType::BigInt(bigint_str!(
        //         b"7737125245533626718119526477371252455336267181195264773712524553362")));

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 6));

        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 6));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("res"), bigint!(0));

        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::AP,
                offset1: 5,
                offset2: 0,
                immediate: None,
                inner_dereference: false,
                ap_tracking_data: Some(ApTracking {
                    group: 0,
                    offset: 0,
                }),
            },
        )]);

        let ap_tracking = ApTracking {
            group: 0,
            offset: 0,
        };

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ap_tracking),
            Err(VirtualMachineError::VariableNotInScopeError(
                "value".to_string()
            ))
        );
    }

    #[test]
    fn run_nondet_bigint3_split_error() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import split\n\nsegments.write_arg(ids.res.address_, split(value))".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        // initialize vm scope with variable `n`
        vm.exec_scopes
            .assign_or_update_variable("value", PyValueType::BigInt(bigint!(-1)));
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("res"), bigint!(0));

        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
                register: Register::AP,
                offset1: 5,
                offset2: 0,
                immediate: None,
                inner_dereference: false,
                ap_tracking_data: Some(ApTracking {
                    group: 0,
                    offset: 0,
                }),
            },
        )]);

        let ap_tracking = ApTracking {
            group: 0,
            offset: 0,
        };

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ap_tracking),
            Err(VirtualMachineError::SecpSplitNegative(bigint!(-1)))
        );
    }
}
