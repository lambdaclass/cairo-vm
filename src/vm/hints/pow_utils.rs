use crate::bigint;
use crate::types::relocatable::MaybeRelocatable;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::hint_utils::get_address_from_reference;
use crate::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::FromPrimitive;
use std::collections::HashMap;

/*
Implements hint:
%{ ids.locs.bit = (ids.prev_locs.exp % PRIME) & 1 %}
*/
pub fn pow(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    println!("ids: {:?}:", ids);

    //Check that ids contains the reference id for the variables used by the hint
    let (prev_locs_ref, locs_ref) = if let (Some(prev_locs_ref), Some(locs_ref)) = (
        ids.get(&String::from("prev_locs")),
        ids.get(&String::from("locs")),
    ) {
        (prev_locs_ref, locs_ref)
    } else {
        return Err(VirtualMachineError::IncorrectIds(
            vec![String::from("prev_locs"), String::from("locs")],
            ids.into_keys().collect(),
        ));
    };

    // Get the addresses of the variables used in the hints
    let (prev_locs_addr, locs_addr) = if let (
        Some(MaybeRelocatable::RelocatableValue(prev_locs_addr)),
        Some(MaybeRelocatable::RelocatableValue(locs_addr)),
    ) = (
        get_address_from_reference(prev_locs_ref, &vm.references, &vm.run_context, vm),
        get_address_from_reference(locs_ref, &vm.references, &vm.run_context, vm),
    ) {
        (prev_locs_addr, locs_addr)
    } else {
        return Err(VirtualMachineError::FailedToGetIds);
    };

    println!("prev_locs_addr: {:?}", prev_locs_addr);
    println!("locs_addr: {:?}", locs_addr);

    let prev_locs_exp_addr =
        MaybeRelocatable::from((prev_locs_addr.segment_index, prev_locs_addr.offset + 4));
    match vm.memory.get(&prev_locs_exp_addr) {
        Ok(Some(MaybeRelocatable::Int(prev_locs_exp))) => {
            let locs_bit = prev_locs_exp.mod_floor(&vm.prime) & bigint!(1);
            println!("locs: {:?}", locs_bit);
            vm.memory
                .insert(
                    &MaybeRelocatable::RelocatableValue(locs_addr),
                    &MaybeRelocatable::Int(locs_bit),
                )
                .map_err(VirtualMachineError::MemoryError)?;
            Ok(())
        }
        Ok(Some(MaybeRelocatable::RelocatableValue(_))) => {
            Err(VirtualMachineError::ExpectedInteger(prev_locs_exp_addr))
        }
        Ok(None) => Err(VirtualMachineError::MemoryGet(prev_locs_exp_addr)),
        Err(memory_error) => Err(VirtualMachineError::MemoryError(memory_error)),
    }
}
