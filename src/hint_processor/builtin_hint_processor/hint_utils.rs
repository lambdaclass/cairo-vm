use crate::hint_processor::hint_processor_definition::HintReference;
use crate::hint_processor::proxies::memory_proxy::MemoryProxy;
use crate::hint_processor::proxies::vm_proxy::VMProxy;
use crate::relocatable;
use crate::serde::deserialize_program::ApTracking;
use crate::types::relocatable::Relocatable;
use crate::types::{instruction::Register, relocatable::MaybeRelocatable};
use crate::vm::runners::builtin_runner::BuiltinRunner;
use crate::vm::runners::builtin_runner::RangeCheckBuiltinRunner;
use crate::vm::{context::run_context::RunContext, errors::vm_errors::VirtualMachineError};
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use std::collections::HashMap;

//Inserts value into teh address of the given ids variable
pub fn insert_value_from_var_name(
    var_name: &str,
    value: impl Into<MaybeRelocatable>,
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let var_address = get_relocatable_from_var_name(var_name, vm_proxy, ids_data, ap_tracking)?;
    vm_proxy.memory.insert_value(&var_address, value)
}

//Inserts value into ap
pub fn insert_value_into_ap(
    memory: &mut MemoryProxy,
    run_context: &RunContext,
    value: impl Into<MaybeRelocatable>,
) -> Result<(), VirtualMachineError> {
    memory.insert_value(
        &(run_context
            .ap
            .clone()
            .try_into()
            .map_err(VirtualMachineError::MemoryError)?),
        value,
    )
}
//Tries to convert a BigInt value to usize
pub fn bigint_to_usize(bigint: &BigInt) -> Result<usize, VirtualMachineError> {
    bigint
        .to_usize()
        .ok_or(VirtualMachineError::BigintToUsizeFail)
}

//Tries to convert a BigInt value to U32
pub fn bigint_to_u32(bigint: &BigInt) -> Result<u32, VirtualMachineError> {
    bigint.to_u32().ok_or(VirtualMachineError::BigintToU32Fail)
}

//Returns a reference to the  RangeCheckBuiltinRunner struct if range_check builtin is present
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

//Returns the Relocatable value store in the given ids variable
pub fn get_ptr_from_var_name(
    var_name: &str,
    vm_proxy: &VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<Relocatable, VirtualMachineError> {
    let var_addr = get_relocatable_from_var_name(var_name, vm_proxy, ids_data, ap_tracking)?;
    //Add immediate if present in reference
    let hint_reference = ids_data
        .get(&String::from(var_name))
        .ok_or(VirtualMachineError::FailedToGetIds)?;
    if hint_reference.dereference {
        let value = vm_proxy.memory.get_relocatable(&var_addr)?;
        if let Some(immediate) = &hint_reference.immediate {
            let modified_value = relocatable!(
                value.segment_index,
                value.offset + bigint_to_usize(immediate)?
            );
            Ok(modified_value)
        } else {
            Ok(value.clone())
        }
    } else {
        Ok(var_addr)
    }
}

//Gets the address, as a MaybeRelocatable of the variable given by the ids name
pub fn get_address_from_var_name(
    var_name: &str,
    vm_proxy: &VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<MaybeRelocatable, VirtualMachineError> {
    compute_addr_from_reference(
        ids_data
            .get(var_name)
            .ok_or(VirtualMachineError::FailedToGetIds)?,
        vm_proxy.run_context,
        &vm_proxy.memory,
        ap_tracking,
    )
}

//Gets the address, as a Relocatable of the variable given by the ids name
pub fn get_relocatable_from_var_name(
    var_name: &str,
    vm_proxy: &VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<Relocatable, VirtualMachineError> {
    match get_address_from_var_name(var_name, vm_proxy, ids_data, ap_tracking)? {
        MaybeRelocatable::RelocatableValue(relocatable) => Ok(relocatable),
        address => Err(VirtualMachineError::ExpectedRelocatable(address)),
    }
}

//Gets the value of a variable name.
//If the value is an MaybeRelocatable::Int(Bigint) return &Bigint
//else raises Err
pub fn get_integer_from_var_name<'a>(
    var_name: &str,
    vm_proxy: &'a VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<&'a BigInt, VirtualMachineError> {
    let relocatable = get_relocatable_from_var_name(var_name, vm_proxy, ids_data, ap_tracking)?;
    vm_proxy.memory.get_integer(&relocatable)
}

fn apply_ap_tracking_correction(
    ap: &Relocatable,
    ref_ap_tracking: &ApTracking,
    hint_ap_tracking: &ApTracking,
) -> Result<MaybeRelocatable, VirtualMachineError> {
    // check that both groups are the same
    if ref_ap_tracking.group != hint_ap_tracking.group {
        return Err(VirtualMachineError::InvalidTrackingGroup(
            ref_ap_tracking.group,
            hint_ap_tracking.group,
        ));
    }
    let ap_diff = hint_ap_tracking.offset - ref_ap_tracking.offset;

    Ok(MaybeRelocatable::from((
        ap.segment_index,
        ap.offset - ap_diff,
    )))
}

///Computes the memory address indicated by the HintReference
fn compute_addr_from_reference(
    hint_reference: &HintReference,
    run_context: &RunContext,
    memory: &MemoryProxy,
    hint_ap_tracking: &ApTracking,
) -> Result<MaybeRelocatable, VirtualMachineError> {
    let base_addr = match hint_reference.register {
        Register::FP => run_context.fp.clone(),
        Register::AP => {
            if hint_reference.ap_tracking_data.is_none() {
                return Err(VirtualMachineError::NoneApTrackingData);
            }

            if let MaybeRelocatable::RelocatableValue(ref relocatable) = run_context.ap {
                apply_ap_tracking_correction(
                    relocatable,
                    // it is safe to call these unrwaps here, since it has been checked
                    // they are not None's
                    // this could be refactored to use pattern match but it will be
                    // unnecesarily verbose
                    hint_reference.ap_tracking_data.as_ref().unwrap(),
                    hint_ap_tracking,
                )?
            } else {
                return Err(VirtualMachineError::InvalidApValue(run_context.ap.clone()));
            }
        }
    };

    if let MaybeRelocatable::RelocatableValue(relocatable) = base_addr {
        if hint_reference.offset1.is_negative()
            && relocatable.offset < hint_reference.offset1.abs() as usize
        {
            return Err(VirtualMachineError::FailedToGetIds);
        }
        if !hint_reference.inner_dereference {
            return Ok(MaybeRelocatable::from((
                relocatable.segment_index,
                (relocatable.offset as i32 + hint_reference.offset1 + hint_reference.offset2)
                    as usize,
            )));
        } else {
            let addr = MaybeRelocatable::from((
                relocatable.segment_index,
                (relocatable.offset as i32 + hint_reference.offset1) as usize,
            ));

            match memory.get(&addr) {
                Ok(Some(&MaybeRelocatable::RelocatableValue(ref dereferenced_addr))) => {
                    if let Some(imm) = &hint_reference.immediate {
                        return Ok(MaybeRelocatable::from((
                            dereferenced_addr.segment_index,
                            dereferenced_addr.offset
                                + imm
                                    .to_usize()
                                    .ok_or(VirtualMachineError::BigintToUsizeFail)?,
                        )));
                    } else {
                        return Ok(MaybeRelocatable::from((
                            dereferenced_addr.segment_index,
                            (dereferenced_addr.offset as i32 + hint_reference.offset2) as usize,
                        )));
                    }
                }

                _none_or_error => return Err(VirtualMachineError::FailedToGetIds),
            }
        }
    }

    Err(VirtualMachineError::FailedToGetIds)
}
