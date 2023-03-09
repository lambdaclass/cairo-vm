use crate::stdlib::{
    collections::HashMap,
    prelude::*,
    borrow::Cow,
};
use crate::{
    hint_processor::{
        builtin_hint_processor::{
            hint_utils::{
                get_integer_from_var_name, get_relocatable_from_var_name,
            },
        },
        hint_processor_definition::HintReference,
    },
    serde::deserialize_program::ApTracking,
    vm::{errors::hint_errors::HintError, vm_core::VirtualMachine},
};
use felt::Felt;

#[derive(Debug, PartialEq)]
struct EcPoint<'a> {
    x: Cow<'a, Felt>,
    y: Cow<'a, Felt>,
}
impl EcPoint<'_> {
    fn from_var_name<'a>(
        name: &'a str,
        vm: &'a VirtualMachine,
        ids_data: &'a HashMap<String, HintReference>,
        ap_tracking: &'a ApTracking,
    ) -> Result<EcPoint<'a>, HintError> {
        // Get first addr of EcPoint struct
        let point_addr = get_relocatable_from_var_name(name, vm, ids_data, ap_tracking)?;
        Ok(EcPoint {
            x: vm.get_integer(point_addr).map_err(|_| {
                HintError::IdentifierHasNoMember(name.to_string(), "x".to_string())
            })?,
            y: vm.get_integer((point_addr + 1)?).map_err(|_| {
                HintError::IdentifierHasNoMember(name.to_string(), "x".to_string())
            })?,
        })
    }
}


// Implements hint: 
// from starkware.crypto.signature.signature import ALPHA, BETA, FIELD_PRIME
// from starkware.python.math_utils import random_ec_point
// from starkware.python.utils import to_bytes

// # Define a seed for random_ec_point that's dependent on all the input, so that:
// #   (1) The added point s is deterministic.
// #   (2) It's hard to choose inputs for which the builtin will fail.
// seed = b"".join(map(to_bytes, [ids.p.x, ids.p.y, ids.m, ids.q.x, ids.q.y]))
// ids.s.x, ids.s.y = random_ec_point(FIELD_PRIME, ALPHA, BETA, seed)

pub fn random_ec_point(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    let p = EcPoint::from_var_name("p", vm, ids_data, ap_tracking)?;
    let q = EcPoint::from_var_name("q", vm, ids_data, ap_tracking)?;
    let m = get_integer_from_var_name("m", vm, ids_data, ap_tracking)?;
    let bytes: Vec<u8>  = [p.x, p.y, m, q.x, q.y].iter().flat_map(|x| x.to_bytes_be()).collect();
    Ok(())
}