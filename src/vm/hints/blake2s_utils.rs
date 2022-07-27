use std::collections::HashMap;

use num_traits::ToPrimitive;

use super::blake2s_hash::blake2s_compress;
use super::hint_utils::get_ptr_from_var_name;
use crate::bigint_u64;
use crate::serde::deserialize_program::ApTracking;
use crate::types::relocatable::Relocatable;
use crate::vm::vm_core::VirtualMachine;
use crate::{
    types::relocatable::MaybeRelocatable,
    vm::{
        errors::vm_errors::VirtualMachineError,
        vm_memory::{memory::Memory, memory_segments::MemorySegmentManager},
    },
};
use num_bigint::BigInt;
use num_traits::FromPrimitive;

fn get_fixed_size_u64_array<const T: usize>(
    h_range: Vec<Option<&MaybeRelocatable>>,
) -> Result<[u64; T], VirtualMachineError> {
    let mut u64_vec = Vec::<u64>::new();
    for element in h_range {
        let mayberel = element.ok_or(VirtualMachineError::UnexpectMemoryGap)?;
        let num = if let MaybeRelocatable::Int(num) = mayberel {
            num
        } else {
            return Err(VirtualMachineError::ExpectedInteger(mayberel.clone()));
        };
        u64_vec.push(num.to_u64().ok_or(VirtualMachineError::BigintToU64Fail)?);
    }
    u64_vec
        .try_into()
        .map_err(|_| VirtualMachineError::FixedSizeArrayFail(T))
}

fn get_maybe_relocatable_array_from_u64(array: Vec<u64>) -> Vec<MaybeRelocatable> {
    let mut new_array = Vec::<MaybeRelocatable>::new();
    for element in array {
        new_array.push(MaybeRelocatable::from(bigint_u64!(element)));
    }
    new_array
}
/*Helper function for the Cairo blake2s() implementation.
Computes the blake2s compress function and fills the value in the right position.
output_ptr should point to the middle of an instance, right after initial_state, message, t, f,
which should all have a value at this point, and right before the output portion which will be
written by this function.*/
fn compute_blake2s_func(
    segments: &mut MemorySegmentManager,
    memory: &mut Memory,
    output_rel: Relocatable,
) -> Result<(), VirtualMachineError> {
    let output_ptr = MaybeRelocatable::RelocatableValue(output_rel);
    let h = get_fixed_size_u64_array::<8>(
        memory
            .get_range(&output_ptr.sub_usize_mod(26, None), 8)
            .map_err(VirtualMachineError::MemoryError)?,
    )?;
    let message = get_fixed_size_u64_array::<16>(
        memory
            .get_range(&output_ptr.sub_usize_mod(18, None), 16)
            .map_err(VirtualMachineError::MemoryError)?,
    )?;
    let t = memory
        .get_integer_from_maybe_relocatable(&output_ptr.sub_usize_mod(2, None))?
        .to_u64()
        .ok_or(VirtualMachineError::BigintToU64Fail)?;
    let f = memory
        .get_integer_from_maybe_relocatable(&output_ptr.sub_usize_mod(1, None))?
        .to_u64()
        .ok_or(VirtualMachineError::BigintToU64Fail)?;
    let new_state = get_maybe_relocatable_array_from_u64(blake2s_compress(h, message, t, 0, f, 0));
    segments
        .load_data(memory, &output_ptr, new_state)
        .map_err(VirtualMachineError::MemoryError)?;
    Ok(())
}

/* Implements hint:
   from starkware.cairo.common.cairo_blake2s.blake2s_utils import compute_blake2s_func
   compute_blake2s_func(segments=segments, output_ptr=ids.output)
*/
pub fn compute_blake2s(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let output = get_ptr_from_var_name("output", &ids, vm, hint_ap_tracking)?;
    compute_blake2s_func(&mut vm.segments, &mut vm.memory, output)
}
