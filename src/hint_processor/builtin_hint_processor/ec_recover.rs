use super::secp::{bigint_utils::BigInt3, secp_utils::pack};
use crate::stdlib::{collections::HashMap, prelude::*};
use crate::{
    hint_processor::hint_processor_definition::HintReference,
    math_utils::div_mod,
    serde::deserialize_program::ApTracking,
    types::exec_scope::ExecutionScopes,
    vm::{errors::hint_errors::HintError, vm_core::VirtualMachine},
};
use num_integer::Integer;

/* Implements Hint:
%{
    from starkware.cairo.common.cairo_secp.secp_utils import pack
    from starkware.python.math_utils import div_mod, safe_div

    N = pack(ids.n, PRIME)
    x = pack(ids.x, PRIME) % N
    s = pack(ids.s, PRIME) % N,
    value = res = div_mod(x, s, N)
%}
 */
pub fn ec_recover_divmod_n_packed(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    let n = pack(BigInt3::from_var_name("n", vm, ids_data, ap_tracking)?);
    let x = pack(BigInt3::from_var_name("x", vm, ids_data, ap_tracking)?).mod_floor(&n);
    let s = pack(BigInt3::from_var_name("s", vm, ids_data, ap_tracking)?).mod_floor(&n);

    let value = div_mod(&x, &s, &n);
    exec_scopes.insert_value("value", value.clone());
    exec_scopes.insert_value("res", value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use num_bigint::BigInt;

    use super::*;
    use crate::hint_processor::builtin_hint_processor::hint_code;
    use crate::hint_processor::hint_processor_definition::HintReference;
    use crate::utils::test_utils::*;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::vm::vm_core::VirtualMachine;
    use crate::vm::vm_memory::memory::Memory;
    use crate::vm::vm_memory::memory_segments::MemorySegmentManager;
    use crate::{
        any_box,
        hint_processor::{
            builtin_hint_processor::builtin_hint_processor_definition::{
                BuiltinHintProcessor, HintProcessorData,
            },
            hint_processor_definition::HintProcessor,
        },
        types::{exec_scope::ExecutionScopes, relocatable::MaybeRelocatable},
    };

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn run_ec_recover_divmod_n_packed_ok() {
        let mut vm = vm!();
        let mut exec_scopes = ExecutionScopes::new();

        vm.run_context.fp = 8;
        let ids_data = non_continuous_ids_data![("n", -8), ("x", -5), ("s", -2)];

        vm.segments = segments![
            //n
            ((1, 0), 177),
            ((1, 1), 0),
            ((1, 2), 0),
            //x
            ((1, 3), 25),
            ((1, 4), 0),
            ((1, 5), 0),
            //s
            ((1, 6), 5),
            ((1, 7), 0),
            ((1, 8), 0)
        ];
        run_hint!(
            vm,
            ids_data,
            hint_code::EC_RECOVER_DIV_MOD_N_PACKED,
            &mut exec_scopes
        )
        .unwrap();
        //assert!(run_hint!(vm, ids_data, hint_code::DIV_MOD_N_PACKED_DIVMOD_CAIRO_N, &mut exec_scopes).is_ok());

        check_scope!(
            &exec_scopes,
            [("value", BigInt::from(5)), ("res", BigInt::from(5))]
        );
    }
}
