use num_bigint::BigInt;

use crate::{
    hint_processor::{
        hint_processor_definition::HintReference,
        hint_processor_utils::{apply_ap_tracking_correction, bigint_to_usize},
    },
    serde::deserialize_program::ApTracking,
    types::{
        instruction::Register,
        relocatable::{MaybeRelocatable, Relocatable},
    },
    vm::{
        context::run_context::RunContext, errors::vm_errors::VirtualMachineError,
        vm_core::VirtualMachine, vm_memory::memory::Memory,
    },
};

use super::pyrelocatable::*;

///Returns the Value given by a reference as an Option<MaybeRelocatable>
pub fn get_value_from_reference(
    vm: &VirtualMachine,
    hint_reference: &HintReference,
    ap_tracking: &ApTracking,
) -> Result<MaybeRelocatable, VirtualMachineError> {
    //First handle case on only immediate
    if let (None, Some(num)) = (
        hint_reference.register.as_ref(),
        hint_reference.immediate.as_ref(),
    ) {
        return Ok(MaybeRelocatable::from(num));
    }
    //Then calculate address
    let var_addr =
        compute_addr_from_reference(hint_reference, &vm.run_context, &vm.memory, ap_tracking)?;
    let value = if hint_reference.dereference {
        vm.memory.get(&var_addr)?
    } else {
        return Ok(MaybeRelocatable::from(var_addr));
    };
    match &value {
        Some(&MaybeRelocatable::RelocatableValue(ref rel)) => {
            if let Some(immediate) = &hint_reference.immediate {
                let modified_value = rel + bigint_to_usize(immediate)?;
                Ok(MaybeRelocatable::from(modified_value))
            } else {
                Ok(MaybeRelocatable::from(rel))
            }
        }
        Some(&MaybeRelocatable::Int(ref num)) => Ok(MaybeRelocatable::Int(num.clone())),
        None => Err(VirtualMachineError::FailedToGetIds),
    }
}

///Computes the memory address of the ids variable indicated by the HintReference as a Relocatable
pub fn compute_addr_from_reference(
    //Reference data of the ids variable
    hint_reference: &HintReference,
    run_context: &RunContext,
    memory: &Memory,
    //ApTracking of the Hint itself
    hint_ap_tracking: &ApTracking,
) -> Result<Relocatable, VirtualMachineError> {
    let base_addr = match hint_reference.register {
        //This should never fail
        Some(Register::FP) => run_context.get_fp(),
        Some(Register::AP) => {
            let var_ap_trackig = hint_reference
                .ap_tracking_data
                .as_ref()
                .ok_or(VirtualMachineError::NoneApTrackingData)?;

            let ap = run_context.get_ap();

            apply_ap_tracking_correction(&ap, var_ap_trackig, hint_ap_tracking)?
        }
        None => return Err(VirtualMachineError::NoRegisterInReference),
    };
    if hint_reference.offset1.is_negative()
        && base_addr.offset < hint_reference.offset1.abs() as usize
    {
        return Err(VirtualMachineError::FailedToGetIds);
    }
    if !hint_reference.inner_dereference {
        Ok(base_addr + hint_reference.offset1 + hint_reference.offset2)
    } else {
        let addr = base_addr + hint_reference.offset1;
        let dereferenced_addr = memory
            .get_relocatable(&addr)
            .map_err(|_| VirtualMachineError::FailedToGetIds)?;
        if let Some(imm) = &hint_reference.immediate {
            Ok(dereferenced_addr + bigint_to_usize(imm)?)
        } else {
            Ok(dereferenced_addr + hint_reference.offset2)
        }
    }
}

pub fn write_py_vec_args(
    memory: &mut Memory,
    ptr: &PyRelocatable,
    py_args: &[PyMaybeRelocatable],
    prime: &BigInt,
) -> Result<(), VirtualMachineError> {
    let ptr = ptr.to_relocatable();
    for (num, value) in py_args.iter().enumerate() {
        memory.insert(
            &(&ptr + num),
            &Into::<MaybeRelocatable>::into(value).mod_floor(prime)?,
        )?;
    }
    Ok(())
}
