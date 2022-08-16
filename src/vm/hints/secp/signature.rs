use crate::{
    math_utils::{div_mod, safe_div},
    serde::deserialize_program::ApTracking,
    vm::{
        errors::vm_errors::VirtualMachineError,
        hints::{
            hint_utils::{
                get_int_ref_from_scope, get_integer_from_var_name, insert_int_into_scope,
            },
            secp::secp_utils::{pack_from_var_name, BETA, N, SECP_P},
        },
        vm_core::VMProxy,
    },
};
use num_bigint::BigInt;
use std::collections::HashMap;

/* Implements hint:
from starkware.cairo.common.cairo_secp.secp_utils import N, pack
from starkware.python.math_utils import div_mod, safe_div

a = pack(ids.a, PRIME)
b = pack(ids.b, PRIME)
value = res = div_mod(a, b, N)
*/
pub fn div_mod_n_packed_divmod(
    vm_proxy: &mut VMProxy,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a = pack_from_var_name("a", ids, vm_proxy, hint_ap_tracking)?;
    let b = pack_from_var_name("b", ids, vm_proxy, hint_ap_tracking)?;

    let value = div_mod(&a, &b, &N);
    insert_int_into_scope(vm_proxy.exec_scopes, "a", a);
    insert_int_into_scope(vm_proxy.exec_scopes, "b", b);
    insert_int_into_scope(vm_proxy.exec_scopes, "value", value.clone());
    insert_int_into_scope(vm_proxy.exec_scopes, "res", value);
    Ok(())
}

// Implements hint:
// value = k = safe_div(res * b - a, N)
pub fn div_mod_n_safe_div(vm_proxy: &mut VMProxy) -> Result<(), VirtualMachineError> {
    let a = get_int_ref_from_scope(vm_proxy.exec_scopes, "a")?;
    let b = get_int_ref_from_scope(vm_proxy.exec_scopes, "b")?;
    let res = get_int_ref_from_scope(vm_proxy.exec_scopes, "res")?;

    let value = safe_div(&(res * b - a), &N)?;

    insert_int_into_scope(vm_proxy.exec_scopes, "value", value);
    Ok(())
}

pub fn get_point_from_x(
    vm_proxy: &mut VMProxy,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let x_cube_int = pack_from_var_name("x_cube", ids, vm_proxy, hint_ap_tracking)? % &*SECP_P;
    let y_cube_int = (x_cube_int + &*BETA) % &*SECP_P;
    let mut y = y_cube_int.modpow(&((&*SECP_P + 1) / 4), &*SECP_P);

    let v = get_integer_from_var_name("v", ids, vm_proxy, hint_ap_tracking)?;
    if v % 2 != &y % 2 {
        y = -y % &*SECP_P;
    }
    insert_int_into_scope(vm_proxy.exec_scopes, "value", y);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bigint, bigint_str,
        types::{exec_scope::PyValueType, instruction::Register, relocatable::MaybeRelocatable},
        utils::test_utils::*,
        vm::{
            errors::memory_errors::MemoryError,
            hints::execute_hint::{get_vm_proxy, HintReference},
            vm_core::VirtualMachine,
            vm_memory::memory::Memory,
        },
    };
    use num_bigint::Sign;

    #[test]
    fn safe_div_ok() {
        let mut vm = vm!();

        vm.memory = memory![
            ((0, 0), 15),
            ((0, 1), 3),
            ((0, 2), 40),
            ((0, 3), 0),
            ((0, 4), 10),
            ((0, 5), 1)
        ];
        vm.run_context.fp = mayberelocatable!(0, 3);

        vm.references = HashMap::new();
        for i in 0..=3 {
            vm.references.insert(
                i,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: i as i32 - 3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            );
        }

        let ids: HashMap<String, BigInt> = HashMap::from([
            ("a".to_string(), bigint!(0_i32)),
            ("b".to_string(), bigint!(3_i32)),
        ]);
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(div_mod_n_packed_divmod(&mut vm_proxy, &ids, None), Ok(()));
        assert_eq!(div_mod_n_safe_div(&mut vm_proxy), Ok(()));
    }

    #[test]
    fn safe_div_fail() {
        let mut vm = vm!();

        vm.exec_scopes
            .assign_or_update_variable("a", PyValueType::BigInt(bigint!(0_usize)));
        vm.exec_scopes
            .assign_or_update_variable("b", PyValueType::BigInt(bigint!(1_usize)));
        vm.exec_scopes
            .assign_or_update_variable("res", PyValueType::BigInt(bigint!(1_usize)));

        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert_eq!(Err(VirtualMachineError::SafeDivFail(bigint!(1_usize), bigint_str!(b"115792089237316195423570985008687907852837564279074904382605163141518161494337"))), div_mod_n_safe_div(&mut vm_proxy));
    }

    #[test]
    fn get_point_from_x_ok() {
        let mut vm = vm!();
        vm.memory = memory![
            ((0, 0), 18),
            ((0, 1), 2147483647),
            ((0, 2), 2147483647),
            ((0, 3), 2147483647)
        ];
        vm.run_context.fp = mayberelocatable!(0, 1);

        vm.references = HashMap::new();
        for i in 0..=1 {
            vm.references.insert(
                i,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: i as i32 - 1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            );
        }

        let ids: HashMap<String, BigInt> = HashMap::from([
            ("v".to_string(), bigint!(0_i32)),
            ("x_cube".to_string(), bigint!(1_i32)),
        ]);
        let mut vm_proxy = get_vm_proxy(&mut vm);
        assert!(get_point_from_x(&mut vm_proxy, &ids, None).is_ok());
    }
}
