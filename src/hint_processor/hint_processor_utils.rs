use num_bigint::BigInt;
use num_traits::ToPrimitive;

use crate::{
    serde::deserialize_program::ApTracking,
    types::{
        instruction::Register,
        relocatable::{MaybeRelocatable, Relocatable},
    },
    vm::{
        errors::vm_errors::VirtualMachineError,
        runners::builtin_runner::{BuiltinRunner, RangeCheckBuiltinRunner},
    },
};

use super::{hint_processor_definition::HintReference, proxies::vm_proxy::VMProxy};

///Inserts value into the address of the given ids variable
pub fn insert_value_from_reference(
    value: impl Into<MaybeRelocatable>,
    vm_proxy: &mut VMProxy,
    hint_reference: &HintReference,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let var_addr = compute_addr_from_reference(hint_reference, vm_proxy, ap_tracking)?;
    vm_proxy.insert_value(&var_addr, value)
}

///Returns the Integer value stored in the given ids variable
pub fn get_integer_from_reference<'a>(
    vm_proxy: &'a VMProxy,
    hint_reference: &'a HintReference,
    ap_tracking: &ApTracking,
) -> Result<&'a BigInt, VirtualMachineError> {
    // if the reference register is none, this means it is an immediate value and we
    // should return that value.
    if hint_reference.register.is_none() && hint_reference.immediate.is_some() {
        // safe tu unwrap here because it has been checked that immediate is not None.
        return Ok(hint_reference.immediate.as_ref().unwrap());
    }

    let var_addr = compute_addr_from_reference(hint_reference, vm_proxy, ap_tracking)?;
    vm_proxy.get_integer(&var_addr)
}

///Returns the Relocatable value stored in the given ids variable
pub fn get_ptr_from_reference(
    vm_proxy: &VMProxy,
    hint_reference: &HintReference,
    ap_tracking: &ApTracking,
) -> Result<Relocatable, VirtualMachineError> {
    let var_addr = compute_addr_from_reference(hint_reference, vm_proxy, ap_tracking)?;
    //Add immediate if present in reference
    if hint_reference.dereference {
        let value = vm_proxy.get_relocatable(&var_addr)?;
        if let Some(immediate) = &hint_reference.immediate {
            let modified_value = value + bigint_to_usize(immediate)?;
            Ok(modified_value)
        } else {
            Ok(value.clone())
        }
    } else {
        Ok(var_addr)
    }
}

///Computes the memory address of the ids variable indicated by the HintReference as a Relocatable
pub fn compute_addr_from_reference(
    //Reference data of the ids variable
    hint_reference: &HintReference,
    vm_proxy: &VMProxy,
    //ApTracking of the Hint itself
    hint_ap_tracking: &ApTracking,
) -> Result<Relocatable, VirtualMachineError> {
    let base_addr = match hint_reference.register {
        //This should never fail
        Some(Register::FP) => vm_proxy.get_fp(),
        Some(Register::AP) => {
            let var_ap_trackig = hint_reference
                .ap_tracking_data
                .as_ref()
                .ok_or(VirtualMachineError::NoneApTrackingData)?;

            apply_ap_tracking_correction(&vm_proxy.get_ap(), var_ap_trackig, hint_ap_tracking)?
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
        let dereferenced_addr = vm_proxy
            .memory
            .get_relocatable(&addr)
            .map_err(|_| VirtualMachineError::FailedToGetIds)?;
        if let Some(imm) = &hint_reference.immediate {
            Ok(dereferenced_addr + bigint_to_usize(imm)?)
        } else {
            Ok(dereferenced_addr + hint_reference.offset2)
        }
    }
}

fn apply_ap_tracking_correction(
    ap: &Relocatable,
    ref_ap_tracking: &ApTracking,
    hint_ap_tracking: &ApTracking,
) -> Result<Relocatable, VirtualMachineError> {
    // check that both groups are the same
    if ref_ap_tracking.group != hint_ap_tracking.group {
        return Err(VirtualMachineError::InvalidTrackingGroup(
            ref_ap_tracking.group,
            hint_ap_tracking.group,
        ));
    }
    let ap_diff = hint_ap_tracking.offset - ref_ap_tracking.offset;
    ap.sub(ap_diff)
}

//Tries to convert a BigInt value to usize
pub fn bigint_to_usize(bigint: &BigInt) -> Result<usize, VirtualMachineError> {
    bigint
        .to_usize()
        .ok_or(VirtualMachineError::BigintToUsizeFail)
}

///Tries to convert a BigInt value to u32
pub fn bigint_to_u32(bigint: &BigInt) -> Result<u32, VirtualMachineError> {
    bigint.to_u32().ok_or(VirtualMachineError::BigintToU32Fail)
}

///Returns a reference to the RangeCheckBuiltinRunner struct if range_check builtin is present
pub fn get_range_check_builtin(
    builtin_runners: &Vec<(String, Box<dyn BuiltinRunner>)>,
) -> Result<&RangeCheckBuiltinRunner, VirtualMachineError> {
    for (name, builtin) in builtin_runners {
        if name == &String::from("range_check") {
            if let Some(range_check_builtin) =
                builtin.as_any().downcast_ref::<RangeCheckBuiltinRunner>()
            {
                return Ok(range_check_builtin);
            };
        }
    }
    Err(VirtualMachineError::NoRangeCheckBuiltin)
}
