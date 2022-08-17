use crate::hint_processor::builtin_hint_processor::hint_utils::get_integer_from_var_name;
use crate::hint_processor::builtin_hint_processor::secp::secp_utils::pack_from_var_name;
use crate::hint_processor::hint_processor_definition::HintReference;
use crate::{
    math_utils::{div_mod, safe_div},
    serde::deserialize_program::ApTracking,
    types::exec_scope::ExecutionScopesProxy,
    vm::{errors::vm_errors::VirtualMachineError, vm_core::VMProxy},
};
use std::collections::HashMap;

use super::secp_utils::{BETA, N, SECP_P};

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
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let a = pack_from_var_name("a", vm_proxy, ids_data, ap_tracking)?;
    let b = pack_from_var_name("b", vm_proxy, ids_data, ap_tracking)?;

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
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let x_cube_int = pack_from_var_name("x_cube", vm_proxy, ids_data, ap_tracking)? % &*SECP_P;
    let y_cube_int = (x_cube_int + &*BETA) % &*SECP_P;
    let mut y = y_cube_int.modpow(&((&*SECP_P + 1) / 4), &*SECP_P);

    let v = get_integer_from_var_name("v", vm_proxy, ids_data, ap_tracking)?;
    if v % 2_i32 != &y % 2_i32 {
        y = -y % &*SECP_P;
    }
    exec_scopes_proxy.insert_value("value", y);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bigint, bigint_str,
        hint_processor::builtin_hint_processor::builtin_hint_processor_definition::get_vm_proxy,
        types::{
            exec_scope::{get_exec_scopes_proxy, ExecutionScopes},
            relocatable::MaybeRelocatable,
        },
        utils::test_utils::*,
        vm::{
            errors::memory_errors::MemoryError, vm_core::VirtualMachine, vm_memory::memory::Memory,
        },
    };
    use num_bigint::BigInt;
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
        let ids_data = HashMap::from([
            ("a".to_string(), HintReference::new_simple(-3)),
            ("b".to_string(), HintReference::new_simple(0)),
        ]);
        let mut exec_scopes = ExecutionScopes::new();
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            div_mod_n_packed_divmod(
                vm_proxy,
                exec_scopes_proxy,
                &ids_data,
                &ApTracking::default()
            ),
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
        vm.run_context.fp = mayberelocatable!(0, 1);
        let ids_data = HashMap::from([
            ("v".to_string(), HintReference::new_simple(-1)),
            ("x_cube".to_string(), HintReference::new_simple(0)),
        ]);
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert!(get_point_from_x(
            vm_proxy,
            exec_scopes_proxy_ref!(),
            &ids_data,
            &ApTracking::default()
        )
        .is_ok());
    }
}
