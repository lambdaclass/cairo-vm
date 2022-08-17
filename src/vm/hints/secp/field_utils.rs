use crate::bigint;
use crate::math_utils::div_mod;
use crate::serde::deserialize_program::ApTracking;
use crate::types::exec_scope::ExecutionScopesProxy;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::execute_hint::HintReference;
use crate::vm::hints::hint_utils::{
    get_relocatable_from_var_name, insert_value_from_var_name, insert_value_into_ap,
};
use crate::vm::hints::secp::secp_utils::SECP_P;
use crate::vm::vm_core::VMProxy;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::Zero;
use std::collections::HashMap;

use super::secp_utils::{pack, pack_from_var_name};

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
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let val_reloc = get_relocatable_from_var_name("val", vm_proxy, ids_data, ap_tracking)?;

    let val_d0 = vm_proxy.memory.get_integer(&val_reloc)?;
    let val_d1 = vm_proxy.memory.get_integer(&(val_reloc.clone() + 1))?;
    let val_d2 = vm_proxy.memory.get_integer(&(val_reloc + 2))?;

    let pack = pack(val_d0, val_d1, val_d2, vm_proxy.prime);

    let (q, r) = pack.div_rem(&SECP_P);

    if !r.is_zero() {
        return Err(VirtualMachineError::SecpVerifyZero(
            val_d0.clone(),
            val_d1.clone(),
            val_d2.clone(),
        ));
    }
    insert_value_from_var_name(
        "q",
        q.mod_floor(vm_proxy.prime),
        vm_proxy,
        ids_data,
        ap_tracking,
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
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let value = pack_from_var_name("x", vm_proxy, ids_data, ap_tracking)?.mod_floor(&SECP_P);
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
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let x_reloc = get_relocatable_from_var_name("x", vm_proxy, ids_data, ap_tracking)?;

    let x_d0 = vm_proxy.memory.get_integer(&x_reloc)?;
    let x_d1 = vm_proxy.memory.get_integer(&(&x_reloc + 1))?;
    let x_d2 = vm_proxy.memory.get_integer(&(&x_reloc + 2))?;

    let x = (pack(x_d0, x_d1, x_d2, vm_proxy.prime)).mod_floor(&SECP_P);
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
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
) -> Result<(), VirtualMachineError> {
    //Get `x` variable from vm scope
    let x = exec_scopes_proxy.get_int("x")?;

    let value = bigint!(x.is_zero() as usize);
    insert_value_into_ap(&mut vm_proxy.memory, vm_proxy.run_context, value)
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
    use crate::types::exec_scope::get_exec_scopes_proxy;
    use crate::types::exec_scope::ExecutionScopes;
    use crate::types::instruction::Register;
    use crate::types::relocatable::MaybeRelocatable;
    use crate::utils::test_utils::*;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::vm::hints::execute_hint::BuiltinHintProcessor;
    use crate::vm::hints::execute_hint::HintProcessorData;
    use crate::vm::hints::execute_hint::{get_vm_proxy, HintReference};
    use crate::vm::runners::builtin_runner::RangeCheckBuiltinRunner;
    use crate::vm::vm_core::VirtualMachine;
    use crate::vm::vm_memory::memory::Memory;
    use num_bigint::Sign;
    use std::any::Any;

    static HINT_EXECUTOR: BuiltinHintProcessor = BuiltinHintProcessor {};
    use crate::types::hint_executor::HintProcessor;

    #[test]
    fn run_verify_zero_ok() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nq, r = divmod(pack(ids.val, PRIME), SECP_P)\nassert r == 0, f\"verify_zero: Invalid input {ids.val.d0, ids.val.d1, ids.val.d2}.\"\nids.q = q % PRIME";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 9));

        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 9));
        //Create hint data
        let ids_data = HashMap::from([
            (
                "val".to_string(),
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
                "q".to_string(),
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
        let hint_data = HintProcessorData {
            code: hint_code.to_string(),
            ap_tracking: ApTracking {
                group: 1,
                offset: 0,
            },
            ids_data,
        };
        vm.memory = memory![((1, 4), 0), ((1, 5), 0), ((1, 6), 0)];
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
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
        //Create hint data
        let ids_data = HashMap::from([
            (
                "val".to_string(),
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
                "q".to_string(),
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
        let hint_data = HintProcessorData {
            code: hint_code.to_string(),
            ap_tracking: ApTracking {
                group: 1,
                offset: 0,
            },
            ids_data,
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
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        //Execute the hint
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
            Err(VirtualMachineError::SecpVerifyZero(
                bigint!(0),
                bigint!(0),
                bigint!(150)
            ))
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

        //Create hint data
        let ids_data = HashMap::from([
            (
                "val".to_string(),
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
                "q".to_string(),
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
        let hint_data = HintProcessorData {
            code: hint_code.to_string(),
            ap_tracking: ApTracking {
                group: 1,
                offset: 0,
            },
            ids_data,
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
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        //Execute the hint
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
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

        //Create hint data
        let ids_data = HashMap::from([(
            "x".to_string(),
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
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);
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

        let mut exec_scopes = ExecutionScopes::new();
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        //Execute the hint
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
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
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 25));

        //Create hint data
        let ids_data = HashMap::from([(
            "x".to_string(),
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
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);

        //Skip ids.x values insert so the hint fails.
        // vm.memory
        //     .insert(
        //         &MaybeRelocatable::from((1, 20)),
        //         &MaybeRelocatable::from(bigint_str!(b"132181232131231239112312312313213083892150")),
        //     )
        //     .unwrap();

        let vm_proxy = &mut get_vm_proxy(&mut vm);
        //Execute the hint
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
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

        //Create hint data
        let ids_data = HashMap::from([(
            "x".to_string(),
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
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);

        //Insert ids.x.d0, ids.x.d1, ids.x.d2 into memory
        vm.memory = memory![
            ((1, 10), 232113757366008801543585_i128),
            ((1, 11), 232113757366008801543585_i128),
            ((1, 12), 232113757366008801543585_i128)
        ];

        let mut exec_scopes = ExecutionScopes::new();

        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Ok(())
        );

        //Check 'x' is defined in the vm scope
        assert_eq!(
            exec_scopes_proxy.get_int("x"),
            Ok(bigint_str!(
                b"1389505070847794345082847096905107459917719328738389700703952672838091425185"
            ))
        );
    }

    #[test]
    fn run_is_zero_pack_error() {
        let hint_code = "from starkware.cairo.common.cairo_secp.secp_utils import SECP_P, pack\n\nx = pack(ids.x, PRIME) % SECP_P";
        let mut vm = vm_with_range_check!();

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 15));

        //Create hint data
        let ids_data = HashMap::from([(
            "x".to_string(),
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
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), ids_data);

        //Skip ids.x.d0, ids.x.d1, ids.x.d2 inserts so the hints fails
        // vm.memory = memory![
        //     ((1, 10), 232113757366008801543585_i128),
        //     ((1, 11), 232113757366008801543585_i128),
        //     ((1, 12), 232113757366008801543585_i128)
        // ];

        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
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

        let mut exec_scopes = ExecutionScopes::new();
        //Initialize vm scope with variable `x`
        exec_scopes.assign_or_update_variable("x", any_box!(bigint!(0i32)));
        //Create hint data
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
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
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("x", any_box!(bigint!(123890i32)));
        //Create hint data
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
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
        // exec_scopes
        //     .assign_or_update_variable("x", bigint!(123890)));
        //Create hint data
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
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
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("x", any_box!(bigint!(0)));
        //Create hint data
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
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
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable(
            "x",
            any_box!(bigint_str!(
                b"52621538839140286024584685587354966255185961783273479086367"
            )),
        );
        //Create hint data
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
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
        // exec_scopes
        //     .assign_or_update_variable("x", bigint_str!(b"52621538839140286024584685587354966255185961783273479086367")));
        //Create hint data
        let hint_data = HintProcessorData::new_default(hint_code.to_string(), HashMap::new());
        //Execute the hint
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            HINT_EXECUTOR.execute_hint(vm_proxy, exec_scopes_proxy_ref!(), &any_box!(hint_data)),
            Err(VirtualMachineError::VariableNotInScopeError(
                "x".to_string()
            ))
        );
    }
}
