use crate::bigint;
use crate::math_utils::div_mod;
use crate::serde::deserialize_program::ApTracking;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::hint_utils::{
    get_int_from_scope, insert_int_into_scope, insert_value_from_var_name, insert_value_into_ap,
};
use crate::vm::hints::secp::secp_utils::{pack_from_var_name, SECP_P};
use crate::vm::vm_core::VMProxy;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::Zero;
use std::collections::HashMap;

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
    vm_proxy: &mut VMProxy,
    ids: &HashMap<String, usize>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let val = pack_from_var_name("val", ids, vm_proxy, hint_ap_tracking)?;
    let (q, r) = val.div_rem(&SECP_P);

    if !r.is_zero() {
        return Err(VirtualMachineError::SecpVerifyZero(val.clone()));
    }

    insert_value_from_var_name(
        "q",
        q.mod_floor(vm_proxy.prime),
        ids,
        vm_proxy,
        hint_ap_tracking,
    )
}

/*
Implements hint:
%{
    from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack

    value = pack(ids.x, PRIME) % SECP_P
%}
*/
pub fn reduce(
    vm_proxy: &mut VMProxy,
    ids: &HashMap<String, usize>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let value = pack_from_var_name("x", ids, vm_proxy, hint_ap_tracking)?.mod_floor(&SECP_P);
    insert_int_into_scope(vm_proxy.exec_scopes, "value", value);
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
    vm_proxy: &mut VMProxy,
    ids: &HashMap<String, usize>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let x_packed = pack_from_var_name("x", ids, vm_proxy, hint_ap_tracking)?;
    let x = x_packed.mod_floor(&SECP_P);
    insert_int_into_scope(vm_proxy.exec_scopes, "x", x);
    Ok(())
}

/*
Implements hint:
in .cairo program
if nondet %{ x == 0 %} != 0:

On .json compiled program
"memory[ap] = to_felt_or_relocatable(x == 0)"
*/
pub fn is_zero_nondet(vm_proxy: &mut VMProxy) -> Result<(), VirtualMachineError> {
    //Get `x` variable from vm scope
    let x = get_int_from_scope(vm_proxy.exec_scopes, "x")?;

    let value = bigint!(x.is_zero() as usize);
    insert_value_into_ap(vm_proxy.memory, vm_proxy.run_context, value)
}

/*
Implements hint:
%{
    from starkware.cairo.common.cairo_secp.secp_utils import SECP_P
    from starkware.python.math_utils import div_mod

    value = x_inv = div_mod(1, x, SECP_P)
%}
*/
pub fn is_zero_assign_scope_variables(vm_proxy: &mut VMProxy) -> Result<(), VirtualMachineError> {
    //Get `x` variable from vm scope
    let x = get_int_from_scope(vm_proxy.exec_scopes, "x")?;

    let value = div_mod(&bigint!(1), &x, &SECP_P);
    insert_int_into_scope(vm_proxy.exec_scopes, "value", value.clone());
    insert_int_into_scope(vm_proxy.exec_scopes, "x_inv", value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint;
    use crate::bigint_str;
    use crate::types::exec_scope::PyValueType;
    use crate::types::instruction::Register;
    use crate::types::relocatable::MaybeRelocatable;
    use crate::utils::test_utils::*;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::vm::hints::execute_hint::BuiltinHintExecutor;
    use crate::vm::hints::execute_hint::{get_vm_proxy, HintReference};
    use crate::vm::runners::builtin_runner::RangeCheckBuiltinRunner;
    use crate::vm::vm_core::VirtualMachine;
    use crate::vm::vm_memory::memory::Memory;
    use num_bigint::Sign;

    static HINT_EXECUTOR: BuiltinHintExecutor = BuiltinHintExecutor {};
    use crate::types::hint_executor::HintExecutor;

    #[test]
    fn run_verify_zero_ok() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nq, r = divmod(pack(ids.val, PRIME), SECP_P)\nassert r == 0, f\"verify_zero: Invalid input {ids.val.d0, ids.val.d1, ids.val.d2}.\"\nids.q = q % PRIME";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 9));

        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 9));

        //Create ids
        let ids = ids!["val", "q"];

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
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
                    dereference: true,
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
        vm.memory = memory![((1, 4), 0), ((1, 5), 0), ((1, 6), 0)];
        //Execute the hint
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, hint_code, &ids, &ap_tracking),
            Ok(())
        );

        //Check hint memory inserts
        //ids.q
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 9))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
    }

    #[test]
    fn run_verify_zero_error() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nq, r = divmod(pack(ids.val, PRIME), SECP_P)\nassert r == 0, f\"verify_zero: Invalid input {ids.val.d0, ids.val.d1, ids.val.d2}.\"\nids.q = q % PRIME";
        let mut vm = vm_with_range_check!();
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 9));

        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 9));

        //Create ids
        let ids = ids!["val", "q"];

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
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
                    dereference: true,
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
        let mut vm_proxy = get_vm_proxy(&mut vm);
        //Execute the hint
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, hint_code, &ids, &ap_tracking),
            Err(VirtualMachineError::SecpVerifyZero(bigint_str!(
                b"897946605976106752944343961220884287276604954404454400"
            ),))
        );
    }

    #[test]
    fn run_verify_zero_invalid_memory_insert() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nq, r = divmod(pack(ids.val, PRIME), SECP_P)\nassert r == 0, f\"verify_zero: Invalid input {ids.val.d0, ids.val.d1, ids.val.d2}.\"\nids.q = q % PRIME";
        let mut vm = vm_with_range_check!();
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 9));

        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 9));

        //Create ids
        let ids = ids!["val", "q"];

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
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
                    dereference: true,
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

        // Insert ids.val.d2  before the hint execution, so the hint memory insert fails
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 9)),
                &MaybeRelocatable::from(bigint!(55)),
            )
            .unwrap();
        let mut vm_proxy = get_vm_proxy(&mut vm);
        //Execute the hint
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, hint_code, &ids, &ap_tracking),
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
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 25));

        //Create ids
        let ids = ids!["x"];

        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
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

        let mut vm_proxy = get_vm_proxy(&mut vm);
        //Execute the hint
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, hint_code, &ids, &ApTracking::new()),
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
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nvalue = pack(ids.x, PRIME) % SECP_P";
        let mut vm = vm_with_range_check!();
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 25));

        //Create ids
        let ids = ids!["x"];

        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
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
        let mut vm_proxy = get_vm_proxy(&mut vm);
        //Execute the hint
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, hint_code, &ids, &ApTracking::new()),
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
        vm.run_context.fp = MaybeRelocatable::from((1, 15));

        //Create ids
        let ids = ids!["x"];

        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
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

        //Insert ids.x.d0, ids.x.d1, ids.x.d2 into memory
        vm.memory = memory![
            ((1, 10), 232113757366008801543585_i128),
            ((1, 11), 232113757366008801543585_i128),
            ((1, 12), 232113757366008801543585_i128)
        ];

        //Check 'x' is not defined in the vm scope
        assert_eq!(vm.exec_scopes.get_local_variables().unwrap().get("x"), None);

        //Execute the hint
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, hint_code, &ids, &ApTracking::new()),
            Ok(())
        );

        //Check 'x' is defined in the vm scope
        assert_eq!(
            vm.exec_scopes.get_local_variables().unwrap().get("x"),
            Some(&PyValueType::BigInt(bigint_str!(
                b"1389505070847794345082847096905107459917719328738389700703952672838091425185"
            )))
        );
    }

    #[test]
    fn run_is_zero_pack_error() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nx = pack(ids.x, PRIME) % SECP_P";
        let mut vm = vm_with_range_check!();

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 15));

        //Create ids
        let mut ids = HashMap::<String, usize>::new();
        ids.insert(String::from("x"), 0);

        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                dereference: true,
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

        //Skip ids.x.d0, ids.x.d1, ids.x.d2 inserts so the hints fails
        // vm.memory = memory![
        //     ((1, 10), 232113757366008801543585_i128),
        //     ((1, 11), 232113757366008801543585_i128),
        //     ((1, 12), 232113757366008801543585_i128)
        // ];

        //Check 'x' is not defined in the vm scope
        assert_eq!(vm.exec_scopes.get_local_variables().unwrap().get("x"), None);

        //Execute the hint
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(&mut vm_proxy, hint_code, &ids, &ApTracking::new()),
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
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 15));

        //Initialize vm scope with variable `x`
        vm.exec_scopes
            .assign_or_update_variable("x", PyValueType::BigInt(bigint!(0i32)));

        //Execute the hint
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(
                &mut vm_proxy,
                hint_code,
                &HashMap::<String, usize>::new(),
                &ApTracking::new()
            ),
            Ok(())
        );

        //Check hint memory insert
        //memory[ap] = to_felt_or_relocatable(x == 0)
        assert_eq!(
            vm.memory.get(&vm.run_context.ap),
            Ok(Some(&MaybeRelocatable::from(bigint!(1i32))))
        );
    }

    #[test]
    fn run_is_zero_nondet_ok_false() {
        let hint_code = "memory[ap] = to_felt_or_relocatable(x == 0)";
        let mut vm = vm_with_range_check!();

        //Initialize memory
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 15));

        //Initialize vm scope with variable `x`
        vm.exec_scopes
            .assign_or_update_variable("x", PyValueType::BigInt(bigint!(123890i32)));

        //Execute the hint
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(
                &mut vm_proxy,
                hint_code,
                &HashMap::<String, usize>::new(),
                &ApTracking::new()
            ),
            Ok(())
        );

        //Check hint memory insert
        //memory[ap] = to_felt_or_relocatable(x == 0)
        assert_eq!(
            vm.memory.get(&vm.run_context.ap),
            Ok(Some(&MaybeRelocatable::from(bigint!(0i32))))
        );
    }

    #[test]
    fn run_is_zero_nondet_scope_error() {
        let hint_code = "memory[ap] = to_felt_or_relocatable(x == 0)";
        let mut vm = vm_with_range_check!();

        //Initialize memory
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 15));

        //Skip `x` assignment
        // vm.exec_scopes
        //     .assign_or_update_variable("x", PyValueType::BigInt(bigint!(123890)));

        //Execute the hint
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(
                &mut vm_proxy,
                hint_code,
                &HashMap::<String, usize>::new(),
                &ApTracking::new()
            ),
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
        vm.run_context.ap = MaybeRelocatable::from((1, 15));

        //Initialize vm scope with variable `x`
        vm.exec_scopes
            .assign_or_update_variable("x", PyValueType::BigInt(bigint!(0)));

        //Execute the hint
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(
                &mut vm_proxy,
                hint_code,
                &HashMap::<String, usize>::new(),
                &ApTracking::new()
            ),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    vm.run_context.ap,
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
        vm.exec_scopes.assign_or_update_variable(
            "x",
            PyValueType::BigInt(bigint_str!(
                b"52621538839140286024584685587354966255185961783273479086367"
            )),
        );

        //Execute the hint
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(
                &mut vm_proxy,
                hint_code,
                &HashMap::<String, usize>::new(),
                &ApTracking::new()
            ),
            Ok(())
        );

        //Check 'value' is defined in the vm scope
        assert_eq!(
            vm.exec_scopes.get_local_variables().unwrap().get("value"),
            Some(&PyValueType::BigInt(bigint_str!(
                b"19429627790501903254364315669614485084365347064625983303617500144471999752609"
            )))
        );

        //Check 'x_inv' is defined in the vm scope
        assert_eq!(
            vm.exec_scopes.get_local_variables().unwrap().get("x_inv"),
            Some(&PyValueType::BigInt(bigint_str!(
                b"19429627790501903254364315669614485084365347064625983303617500144471999752609"
            )))
        );
    }

    #[test]
    fn is_zero_assign_scope_variables_scope_error() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P\nfrom starkware.python.math_utils import div_mod\n\nvalue = x_inv = div_mod(1, x, SECP_P)";
        let mut vm = vm_with_range_check!();

        //Skip `x` assignment
        // vm.exec_scopes
        //     .assign_or_update_variable("x", PyValueType::BigInt(bigint_str!(b"52621538839140286024584685587354966255185961783273479086367")));

        //Execute the hint
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(
                &mut vm_proxy,
                hint_code,
                &HashMap::<String, usize>::new(),
                &ApTracking::new()
            ),
            Err(VirtualMachineError::VariableNotInScopeError(
                "x".to_string()
            ))
        );
    }
}
