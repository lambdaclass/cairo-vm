use super::secp_utils::{BASE_86, BETA, N0, N1, N2, SECP_REM};
use crate::hint_processor::builtin_hint_processor::hint_utils::get_integer_from_var_name;
use crate::hint_processor::builtin_hint_processor::secp::secp_utils::pack_from_var_name;
use crate::hint_processor::hint_processor_definition::HintReference;
use crate::hint_processor::proxies::exec_scopes_proxy::ExecutionScopesProxy;
use crate::vm::vm_core::VirtualMachine;
use crate::{
    bigint,
    math_utils::{div_mod, safe_div},
    serde::deserialize_program::ApTracking,
    vm::errors::vm_errors::VirtualMachineError,
};
use num_bigint::BigInt;
use num_integer::Integer;
use std::collections::HashMap;
use std::ops::Shl;

/* Implements hint:
from starkware.cairo.common.cairo_secp.secp_utils import N, pack
from starkware.python.math_utils import div_mod, safe_div

a = pack(ids.a, PRIME)
b = pack(ids.b, PRIME)
value = res = div_mod(a, b, N)
*/
pub fn div_mod_n_packed_divmod(
    vm: &mut VirtualMachine,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    let a = pack_from_var_name("a", vm, ids_data, ap_tracking)?;
    let b = pack_from_var_name("b", vm, ids_data, ap_tracking)?;

    let n = {
        let base = constants
            .get(BASE_86)
            .ok_or(VirtualMachineError::MissingConstant(BASE_86))?;
        let n0 = constants
            .get(N0)
            .ok_or(VirtualMachineError::MissingConstant(N0))?;
        let n1 = constants
            .get(N1)
            .ok_or(VirtualMachineError::MissingConstant(N1))?;
        let n2 = constants
            .get(N2)
            .ok_or(VirtualMachineError::MissingConstant(N2))?;

        (n2 * base * base) | (n1 * base) | n0
    };

    let value = div_mod(&a, &b, &n);
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
    constants: &HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    let a = exec_scopes_proxy.get_int_ref("a")?;
    let b = exec_scopes_proxy.get_int_ref("b")?;
    let res = exec_scopes_proxy.get_int_ref("res")?;

    let n = {
        let base = constants
            .get(BASE_86)
            .ok_or(VirtualMachineError::MissingConstant(BASE_86))?;
        let n0 = constants
            .get(N0)
            .ok_or(VirtualMachineError::MissingConstant(N0))?;
        let n1 = constants
            .get(N1)
            .ok_or(VirtualMachineError::MissingConstant(N1))?;
        let n2 = constants
            .get(N2)
            .ok_or(VirtualMachineError::MissingConstant(N2))?;

        n2 * base * base + n1 * base + n0
    };

    let value = safe_div(&(res * b - a), &n)?;

    exec_scopes_proxy.insert_value("value", value);
    Ok(())
}

pub fn get_point_from_x(
    vm: &mut VirtualMachine,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    let beta = constants
        .get(BETA)
        .ok_or(VirtualMachineError::MissingConstant(BETA))?;
    let secp_p = bigint!(1).shl(256usize)
        - constants
            .get(SECP_REM)
            .ok_or(VirtualMachineError::MissingConstant(SECP_REM))?;

    let x_cube_int = pack_from_var_name("x_cube", vm, ids_data, ap_tracking)?.mod_floor(&secp_p);
    let y_cube_int = (x_cube_int + beta).mod_floor(&secp_p);
    let mut y = y_cube_int.modpow(&((&secp_p + 1) / 4), &secp_p);

    let v = get_integer_from_var_name("v", vm, ids_data, ap_tracking)?;
    if v.mod_floor(&bigint!(2)) != y.mod_floor(&bigint!(2)) {
        y = (-y).mod_floor(&secp_p);
    }
    exec_scopes_proxy.insert_value("value", y);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::any_box;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData;
    use crate::hint_processor::builtin_hint_processor::hint_code;
    use crate::hint_processor::hint_processor_definition::HintProcessor;
    use crate::hint_processor::proxies::exec_scopes_proxy::get_exec_scopes_proxy;
    use crate::{
        bigint, bigint_str,
        types::{exec_scope::ExecutionScopes, relocatable::MaybeRelocatable},
        utils::test_utils::*,
        vm::{
            errors::memory_errors::MemoryError, vm_core::VirtualMachine, vm_memory::memory::Memory,
        },
    };
    use num_bigint::BigInt;
    use num_bigint::Sign;
    use std::any::Any;

    #[test]
    fn safe_div_ok() {
        let hint_code = hint_code::DIV_MOD_N_PACKED_DIVMOD;
        let mut vm = vm!();

        vm.memory = memory![
            ((1, 0), 15),
            ((1, 1), 3),
            ((1, 2), 40),
            ((1, 3), 0),
            ((1, 4), 10),
            ((1, 5), 1)
        ];
        vm.run_context.fp = 3;
        let ids_data = non_continuous_ids_data![("a", -3), ("b", 0)];
        let mut exec_scopes = ExecutionScopes::new();
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        let constants = [
            (BASE_86, bigint!(1).shl(86)),
            (N0, bigint!(10428087374290690730508609u128)),
            (N1, bigint!(77371252455330678278691517u128)),
            (N2, bigint!(19342813113834066795298815u128)),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        assert_eq!(
            run_hint!(vm, ids_data, hint_code, exec_scopes_proxy, &constants),
            Ok(())
        );
        assert_eq!(div_mod_n_safe_div(exec_scopes_proxy, &constants), Ok(()));
    }

    #[test]
    fn safe_div_fail() {
        let mut exec_scopes = scope![("a", bigint!(0)), ("b", bigint!(1)), ("res", bigint!(1))];
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            Err(
                VirtualMachineError::SafeDivFail(
                    bigint!(1_usize),
                    bigint_str!(b"115792089237316195423570985008687907852837564279074904382605163141518161494337")
                )
            ),
            div_mod_n_safe_div(
                exec_scopes_proxy,
                &[
                    (BASE_86, bigint!(1).shl(86)),
                    (N0, bigint!(10428087374290690730508609u128)),
                    (N1, bigint!(77371252455330678278691517u128)),
                    (N2, bigint!(19342813113834066795298815u128)),
                ]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect()
            )
        );
    }

    #[test]
    fn get_point_from_x_ok() {
        let hint_code = hint_code::GET_POINT_FROM_X;
        let mut vm = vm!();
        vm.memory = memory![
            ((1, 0), 18),
            ((1, 1), 2147483647),
            ((1, 2), 2147483647),
            ((1, 3), 2147483647)
        ];
        vm.run_context.fp = 1;
        let ids_data = non_continuous_ids_data![("v", -1), ("x_cube", 0)];
        assert_eq!(
            run_hint!(
                vm,
                ids_data,
                hint_code,
                exec_scopes_proxy_ref!(),
                &[
                    (BETA, bigint!(7)),
                    (
                        SECP_REM,
                        bigint!(1).shl(32)
                            + bigint!(1).shl(9)
                            + bigint!(1).shl(8)
                            + bigint!(1).shl(7)
                            + bigint!(1).shl(6)
                            + bigint!(1).shl(4)
                            + bigint!(1)
                    ),
                ]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect()
            ),
            Ok(())
        )
    }

    #[test]
    fn get_point_from_x_negative_y() {
        let hint_code = hint_code::GET_POINT_FROM_X;
        let mut vm = vm!();
        let mut exec_scopes = ExecutionScopes::new();
        vm.memory = memory![
            ((1, 0), 1),
            ((1, 1), 2147483647),
            ((1, 2), 2147483647),
            ((1, 3), 2147483647)
        ];
        vm.run_context.fp = 2;

        let ids_data = ids_data!["v", "x_cube"];
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(
                vm,
                ids_data,
                hint_code,
                exec_scopes_proxy,
                &[
                    (BETA, bigint!(7)),
                    (
                        SECP_REM,
                        bigint!(1).shl(32)
                            + bigint!(1).shl(9)
                            + bigint!(1).shl(8)
                            + bigint!(1).shl(7)
                            + bigint!(1).shl(6)
                            + bigint!(1).shl(4)
                            + bigint!(1)
                    ),
                ]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect()
            ),
            Ok(())
        );

        check_scope!(
            exec_scopes_proxy,
            [(
                "value",
                bigint_str!(
            b"94274691440067846579164151740284923997007081248613730142069408045642476712539"
        )
            )]
        );
    }
}
