use core::ops::Shl;

use crate::hint_processor::builtin_hint_processor::hint_utils::get_integer_from_var_name;
use crate::stdlib::{collections::HashMap, prelude::*};
use crate::utils::CAIRO_PRIME;
use crate::vm::errors::hint_errors::HintError;
use felt::Felt252;
use lazy_static::lazy_static;
use num_traits::One;

use crate::{
    hint_processor::hint_processor_definition::HintReference,
    serde::deserialize_program::ApTracking, vm::vm_core::VirtualMachine,
};

use super::hint_utils::insert_value_from_var_name;

const ADDR_BOUND: &str = "starkware.starknet.common.storage.ADDR_BOUND";
lazy_static! {
    static ref HALF_PRIME: Felt252 = Felt252::from(&*CAIRO_PRIME / 2_u32);
}

/* Implements hint:
# Verify the assumptions on the relationship between 2**250, ADDR_BOUND and PRIME.
 ADDR_BOUND = ids.ADDR_BOUND % PRIME
 assert (2**250 < ADDR_BOUND <= 2**251) and (2 * 2**250 < PRIME) and (
         ADDR_BOUND * 2 > PRIME), \
     'normalize_address() cannot be used with the current constants.'
 ids.is_small = 1 if ids.addr < ADDR_BOUND else 0"
 */
pub(crate) fn normalize_address_set_is_small(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let addr_bound = constants
        .get(ADDR_BOUND)
        .ok_or(HintError::MissingConstant("ADDR_BOUND"))?;
    let addr = get_integer_from_var_name("addr", vm, ids_data, ap_tracking)?;
    if addr_bound <= &Felt252::one().shl(250_usize)
        || addr_bound > &Felt252::one().shl(251_usize)
        || addr_bound <= &*HALF_PRIME
    {
        return Err(HintError::AssertionFailed(format!(
            "assert (2**250 < {} <= 2**251) and (2 * 2**250 < PRIME) and (
             {} * 2 > PRIME); normalize_address() cannot be used with the current constants.",
            addr_bound, addr_bound
        )));
    }

    let is_small = Felt252::from((*addr < *addr_bound) as usize);
    insert_value_from_var_name("is_small", is_small, vm, ids_data, ap_tracking)
}

/* Implements Hint:
ids.is_250 = 1 if ids.addr < 2**250 else 0
 */
pub(crate) fn normalize_address_set_is_250(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    _constants: &HashMap<String, Felt252>,
) -> Result<(), HintError> {
    let addr = get_integer_from_var_name("addr", vm, ids_data, ap_tracking)?;
    let is_250 = Felt252::from((*addr < Felt252::one().shl(250_usize)) as usize);
    insert_value_from_var_name("is_250", is_250, vm, ids_data, ap_tracking)
}
