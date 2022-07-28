use crate::bigint_str;
use crate::serde::deserialize_program::ApTracking;
use crate::types::relocatable::MaybeRelocatable;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::hint_utils::{
    get_address_from_var_name, get_integer_from_relocatable_plus_offset,
    get_relocatable_from_var_name,
};
use crate::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::Zero;
use std::collections::HashMap;

use super::secp_utils::pack;

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
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let q_address = get_address_from_var_name("q", &ids, vm, hint_ap_tracking)?;
    let val_reloc = get_relocatable_from_var_name("val", &ids, vm, hint_ap_tracking)?;

    let val_d0 = get_integer_from_relocatable_plus_offset(&val_reloc, 0, vm)?;
    let val_d1 = get_integer_from_relocatable_plus_offset(&val_reloc, 1, vm)?;
    let val_d2 = get_integer_from_relocatable_plus_offset(&val_reloc, 2, vm)?;

    let pack = pack(val_d0, val_d1, val_d2, &vm.prime);

    // SECP_P = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
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
