use crate::{
    bigint,
    math_utils::{div_mod, safe_div},
    serde::deserialize_program::ApTracking,
    types::exec_scope::ExecutionScopesProxy,
    vm::{
        errors::vm_errors::VirtualMachineError,
        hints::{
            hint_utils::get_integer_from_var_name,
            secp::secp_utils::{pack_from_var_name, BETA, N, SECP_P},
        },
        vm_core::VMProxy,
    },
};
use num_bigint::BigInt;
use num_integer::Integer;
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
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids: &HashMap<String, usize>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a = pack_from_var_name("a", ids, vm_proxy, hint_ap_tracking)?;
    let b = pack_from_var_name("b", ids, vm_proxy, hint_ap_tracking)?;

    let value = div_mod(&a, &b, &N);
    exec_scopes_proxy.insert_value("a", a);
    exec_scopes_proxy.insert_value("b", b);
    exec_scopes_proxy.insert_value("value", value.clone());
    exec_scopes_proxy.insert_value("res", value);
    Ok(())
}

// Implements hint:
// value = k = safe_div(res * b - a, N)
pub fn div_mod_n_safe_div(
    exec_scopes_proxy: &mut ExecutionScopesProxy,
) -> Result<(), VirtualMachineError> {
    let a = exec_scopes_proxy.get_int_ref("a")?;
    let b = exec_scopes_proxy.get_int_ref("b")?;
    let res = exec_scopes_proxy.get_int_ref("res")?;

    let value = safe_div(&(res * b - a), &N)?;

    exec_scopes_proxy.insert_value("value", value);
    Ok(())
}

pub fn get_point_from_x(
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids: &HashMap<String, usize>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let x_cube_int =
        pack_from_var_name("x_cube", ids, vm_proxy, hint_ap_tracking)?.mod_floor(&SECP_P);
    let y_cube_int = (x_cube_int + &*BETA).mod_floor(&SECP_P);
    let mut y = y_cube_int.modpow(&((&*SECP_P + 1) / 4), &*SECP_P);

    let v = get_integer_from_var_name("v", ids, vm_proxy, hint_ap_tracking)?;
    if v.mod_floor(&bigint!(2)) != y.mod_floor(&bigint!(2)) {
        y = (-y).mod_floor(&SECP_P);
    }
    exec_scopes_proxy.insert_value("value", y);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bigint, bigint_str,
        types::{
            exec_scope::{get_exec_scopes_proxy, ExecutionScopes},
            instruction::Register,
            relocatable::MaybeRelocatable,
        },
        utils::test_utils::*,
        vm::{
            errors::memory_errors::MemoryError,
            hints::execute_hint::{get_vm_proxy, HintReference},
            vm_core::VirtualMachine,
            vm_memory::memory::Memory,
        },
    };
    use num_bigint::{BigInt, Sign};

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

        let ids: HashMap<String, usize> =
            HashMap::from([("a".to_string(), 0), ("b".to_string(), 3)]);
        let mut exec_scopes = ExecutionScopes::new();
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            div_mod_n_packed_divmod(vm_proxy, exec_scopes_proxy, &ids, None),
            Ok(())
        );
        assert_eq!(div_mod_n_safe_div(exec_scopes_proxy), Ok(()));
    }

    #[test]
    fn safe_div_fail() {
        let mut exec_scopes = ExecutionScopes::new();
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        exec_scopes_proxy.insert_value("a", bigint!(0_usize));
        exec_scopes_proxy.insert_value("b", bigint!(1_usize));
        exec_scopes_proxy.insert_value("res", bigint!(1_usize));
        assert_eq!(Err(VirtualMachineError::SafeDivFail(bigint!(1_usize), bigint_str!(b"115792089237316195423570985008687907852837564279074904382605163141518161494337"))), div_mod_n_safe_div(exec_scopes_proxy));
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
        vm.run_context.fp = mayberelocatable!(0, 2);

        vm.references = references!(2);

        let ids: HashMap<String, usize> =
            HashMap::from([("v".to_string(), 0), ("x_cube".to_string(), 1)]);
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert!(get_point_from_x(vm_proxy, exec_scopes_proxy_ref!(), &ids, None).is_ok());
    }

    #[test]
    fn get_point_from_x_negative_y() {
        let mut vm = vm!();
        let mut exec_scopes = ExecutionScopes::new();
        vm.memory = memory![
            ((0, 0), 1),
            ((0, 1), 2147483647),
            ((0, 2), 2147483647),
            ((0, 3), 2147483647)
        ];
        vm.run_context.fp = mayberelocatable!(0, 2);

        vm.references = references!(2);

        let ids = ids!["v", "x_cube"];
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            get_point_from_x(vm_proxy, exec_scopes_proxy, &ids, None),
            Ok(())
        );
        assert_eq!(
            exec_scopes_proxy.get_int_ref("value"),
            Ok(&bigint_str!(
                b"94274691440067846579164151740284923997007081248613730142069408045642476712539"
            ))
        );
    }
}
