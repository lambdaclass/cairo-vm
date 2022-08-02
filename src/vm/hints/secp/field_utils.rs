use crate::bigint_str;
use crate::serde::deserialize_program::ApTracking;
use crate::types::exec_scope::PyValueType;
use crate::types::relocatable::MaybeRelocatable;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::hint_utils::{get_address_from_var_name, get_relocatable_from_var_name};
use crate::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::Zero;
use std::collections::HashMap;

use crate::vm::hints::secp::secp_utils::pack;

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
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let q_address = get_address_from_var_name("q", ids, vm, hint_ap_tracking)?;
    let val_reloc = get_relocatable_from_var_name("val", ids, vm, hint_ap_tracking)?;

    let val_d0 = vm.memory.get_integer(&val_reloc)?;
    let val_d1 = vm.memory.get_integer(&(val_reloc.clone() + 1))?;
    let val_d2 = vm.memory.get_integer(&(val_reloc + 2))?;

    let pack = pack(val_d0, val_d1, val_d2, &vm.prime);

    //SECP_P = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
    let sec_p = bigint_str!(
        b"115792089237316195423570985008687907853269984665640564039457584007908834671663"
    );

    let (q, r) = pack.div_rem(&sec_p);

    if !r.is_zero() {
        return Err(VirtualMachineError::SecpVerifyZero(
            val_d0.clone(),
            val_d1.clone(),
            val_d2.clone(),
        ));
    }

    vm.memory
        .insert(&q_address, &MaybeRelocatable::from(q.mod_floor(&vm.prime)))
        .map_err(VirtualMachineError::MemoryError)
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
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let x_reloc = get_relocatable_from_var_name("x", ids, vm, hint_ap_tracking)?;

    let x_d0 = vm.memory.get_integer(&x_reloc)?;
    let x_d1 = vm.memory.get_integer(&(x_reloc.clone() + 1))?;
    let x_d2 = vm.memory.get_integer(&(x_reloc + 2))?;

    //SECP_P = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
    let sec_p = bigint_str!(
        b"115792089237316195423570985008687907853269984665640564039457584007908834671663"
    );

    let value = pack(x_d0, x_d1, x_d2, &vm.prime).mod_floor(&sec_p);

    vm.exec_scopes
        .assign_or_update_variable("value", PyValueType::BigInt(value));

    Ok(())
}

#[cfg(test)]
mod tests {
    use num_bigint::Sign;

    use super::*;
    use crate::bigint;
    use crate::types::instruction::Register;
    use crate::types::relocatable::MaybeRelocatable;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::vm::hints::execute_hint::{execute_hint, HintReference};
    use crate::vm::runners::builtin_runner::RangeCheckBuiltinRunner;
    use num_traits::FromPrimitive;

    #[test]
    fn run_verify_zero_ok() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nq, r = divmod(pack(ids.val, PRIME), SECP_P)\nassert r == 0, f\"verify_zero: Invalid input {ids.val.d0, ids.val.d1, ids.val.d2}.\"\nids.q = q % PRIME".as_bytes();
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

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 9));

        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 9));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("val"), bigint!(0));
        ids.insert(String::from("q"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    immediate: None,
                    ap_tracking_data: Some(ApTracking {
                        group: 1,
                        offset: 0,
                    }),
                },
            ),
            (
                1,
                HintReference {
                    register: Register::AP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                    immediate: None,
                    ap_tracking_data: Some(ApTracking {
                        group: 1,
                        offset: 0,
                    }),
                },
            ),
        ]);

        //Create AP tracking
        let ap_tracking = ApTracking {
            group: 1,
            offset: 0,
        };

        //Insert ids.val.d0 into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();

        //Insert ids.val.d1 into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 5)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();

        //Insert ids.val.d2 into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 6)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();

        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids, &ap_tracking), Ok(()));

        //Check hint memory inserts
        //ids.q
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 9))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
    }

    #[test]
    fn run_verify_zero_error() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nq, r = divmod(pack(ids.val, PRIME), SECP_P)\nassert r == 0, f\"verify_zero: Invalid input {ids.val.d0, ids.val.d1, ids.val.d2}.\"\nids.q = q % PRIME".as_bytes();
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

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 9));

        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 9));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("val"), bigint!(0));
        ids.insert(String::from("q"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    immediate: None,
                    ap_tracking_data: Some(ApTracking {
                        group: 1,
                        offset: 0,
                    }),
                },
            ),
            (
                1,
                HintReference {
                    register: Register::AP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                    immediate: None,
                    ap_tracking_data: Some(ApTracking {
                        group: 1,
                        offset: 0,
                    }),
                },
            ),
        ]);

        //Create AP tracking
        let ap_tracking = ApTracking {
            group: 1,
            offset: 0,
        };

        //Insert ids.val.d0 into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();

        //Insert ids.val.d1 into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 5)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();

        //Insert ids.val.d2 into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 6)),
                &MaybeRelocatable::from(bigint!(150)),
            )
            .unwrap();

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ap_tracking),
            Err(VirtualMachineError::SecpVerifyZero(
                bigint!(0),
                bigint!(0),
                bigint!(150)
            ))
        );
    }

    #[test]
    fn run_verify_zero_invalid_memory_insert() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nq, r = divmod(pack(ids.val, PRIME), SECP_P)\nassert r == 0, f\"verify_zero: Invalid input {ids.val.d0, ids.val.d1, ids.val.d2}.\"\nids.q = q % PRIME".as_bytes();
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

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 9));

        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 9));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("val"), bigint!(0));
        ids.insert(String::from("q"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    immediate: None,
                    ap_tracking_data: Some(ApTracking {
                        group: 1,
                        offset: 0,
                    }),
                },
            ),
            (
                1,
                HintReference {
                    register: Register::AP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                    immediate: None,
                    ap_tracking_data: Some(ApTracking {
                        group: 1,
                        offset: 0,
                    }),
                },
            ),
        ]);

        //Create AP tracking
        let ap_tracking = ApTracking {
            group: 1,
            offset: 0,
        };

        //Insert ids.val.d0 into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();

        //Insert ids.val.d1 into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 5)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();

        //Insert ids.val.d2 into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 6)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();

        // Insert ids.val.d2  before the hint execution, so the hint memory.insert fails
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 9)),
                &MaybeRelocatable::from(bigint!(55)),
            )
            .unwrap();

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ap_tracking),
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
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nvalue = pack(ids.x, PRIME) % SECP_P".as_bytes();
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

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 25));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("x"), bigint!(0));

        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -5,
                offset2: 0,
                inner_dereference: false,
                immediate: None,
                ap_tracking_data: Some(ApTracking {
                    group: 2,
                    offset: 0,
                }),
            },
        )]);

        //Insert ids.x.d0 into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 20)),
                &MaybeRelocatable::from(bigint_str!(b"132181232131231239112312312313213083892150")),
            )
            .unwrap();

        //Insert ids.x.d1 into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 21)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .unwrap();

        //Insert ids.x.d2 into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 22)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .unwrap();

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
                b"59863107065205964761754162760883789350782881856141750"
            )))
        );
    }

    #[test]
    fn run_reduce_error() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nvalue = pack(ids.x, PRIME) % SECP_P".as_bytes();
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

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 25));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("x"), bigint!(0));

        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -5,
                offset2: 0,
                inner_dereference: false,
                immediate: None,
                ap_tracking_data: Some(ApTracking {
                    group: 2,
                    offset: 0,
                }),
            },
        )]);

        //Skip ids.x values insert so the hint fails.
        // vm.memory
        //     .insert(
        //         &MaybeRelocatable::from((1, 20)),
        //         &MaybeRelocatable::from(bigint_str!(b"132181232131231239112312312313213083892150")),
        //     )
        //     .unwrap();

        //Check 'value' is not defined in the vm scope
        assert_eq!(
            vm.exec_scopes.get_local_variables().unwrap().get("value"),
            None
        );

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 20))
            ))
        );
    }
}
