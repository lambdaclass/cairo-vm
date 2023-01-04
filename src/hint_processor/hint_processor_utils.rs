use std::borrow::Cow;

use num_bigint::BigInt;
use num_traits::ToPrimitive;

use crate::{
    serde::deserialize_program::{ApTracking, OffsetValue},
    types::{
        instruction::Register,
        relocatable::{MaybeRelocatable, Relocatable},
    },
    vm::{
        errors::{hint_errors::HintError, vm_errors::VirtualMachineError},
        vm_core::VirtualMachine,
    },
};

use super::hint_processor_definition::HintReference;

///Inserts value into the address of the given ids variable
pub fn insert_value_from_reference(
    value: impl Into<MaybeRelocatable>,
    vm: &mut VirtualMachine,
    hint_reference: &HintReference,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    let var_addr = compute_addr_from_reference(hint_reference, vm, ap_tracking)?;
    vm.insert_value(&var_addr, value)
        .map_err(HintError::Internal)
}

///Returns the Integer value stored in the given ids variable
pub fn get_integer_from_reference<'a>(
    vm: &'a VirtualMachine,
    hint_reference: &'a HintReference,
    ap_tracking: &ApTracking,
) -> Result<Cow<'a, BigInt>, HintError> {
    // if the reference register is none, this means it is an immediate value and we
    // should return that value.

    if let (OffsetValue::Immediate(int_1), _) = (&hint_reference.offset1, &hint_reference.offset2) {
        return Ok(Cow::Borrowed(int_1));
    }

    let var_addr = compute_addr_from_reference(hint_reference, vm, ap_tracking)?;
    vm.get_integer(&var_addr).map_err(HintError::Internal)
}

///Returns the Relocatable value stored in the given ids variable
pub fn get_ptr_from_reference(
    vm: &VirtualMachine,
    hint_reference: &HintReference,
    ap_tracking: &ApTracking,
) -> Result<Relocatable, HintError> {
    let var_addr = compute_addr_from_reference(hint_reference, vm, ap_tracking)?;
    if hint_reference.dereference {
        Ok(vm.get_relocatable(&var_addr)?)
    } else {
        Ok(var_addr)
    }
}

///Returns the value given by a reference as an Option<MaybeRelocatable>
pub fn get_maybe_relocatable_from_reference(
    vm: &VirtualMachine,
    hint_reference: &HintReference,
    ap_tracking: &ApTracking,
) -> Result<MaybeRelocatable, HintError> {
    //First handle case on only immediate
    if let OffsetValue::Immediate(num) = &hint_reference.offset1 {
        return Ok(MaybeRelocatable::from(num));
    }
    //Then calculate address
    let var_addr = compute_addr_from_reference(hint_reference, vm, ap_tracking)?;
    let value = if hint_reference.dereference {
        vm.get_maybe(&var_addr)
            .map_err(|error| HintError::Internal(VirtualMachineError::MemoryError(error)))?
    } else {
        return Ok(MaybeRelocatable::from(var_addr));
    };

    value.ok_or(HintError::FailedToGetIds)
}

///Computes the memory address of the ids variable indicated by the HintReference as a Relocatable
pub fn compute_addr_from_reference(
    //Reference data of the ids variable
    hint_reference: &HintReference,
    vm: &VirtualMachine,
    //ApTracking of the Hint itself
    hint_ap_tracking: &ApTracking,
) -> Result<Relocatable, HintError> {
    let offset1 =
        if let OffsetValue::Reference(_register, _offset, _deref) = &hint_reference.offset1 {
            get_offset_value_reference(
                vm,
                hint_reference,
                hint_ap_tracking,
                &hint_reference.offset1,
            )?
            .get_relocatable()?
        } else {
            return Err(HintError::NoRegisterInReference);
        };

    match &hint_reference.offset2 {
        OffsetValue::Reference(_register, _offset, _deref) => {
            // Cant add two relocatable values
            // So OffSet2 must be Bigint
            let value = get_offset_value_reference(
                vm,
                hint_reference,
                hint_ap_tracking,
                &hint_reference.offset2,
            )?;

            Ok(offset1 + bigint_to_usize(value.get_int_ref()?)?)
        }
        OffsetValue::Value(value) => Ok(offset1 + *value),
        _ => Err(HintError::NoRegisterInReference),
    }
}

fn apply_ap_tracking_correction(
    ap: &Relocatable,
    ref_ap_tracking: &ApTracking,
    hint_ap_tracking: &ApTracking,
) -> Result<Relocatable, HintError> {
    // check that both groups are the same
    if ref_ap_tracking.group != hint_ap_tracking.group {
        return Err(HintError::InvalidTrackingGroup(
            ref_ap_tracking.group,
            hint_ap_tracking.group,
        ));
    }
    let ap_diff = hint_ap_tracking.offset - ref_ap_tracking.offset;
    ap.sub(ap_diff).map_err(HintError::Internal)
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

fn get_offset_value_reference(
    vm: &VirtualMachine,
    hint_reference: &HintReference,
    hint_ap_tracking: &ApTracking,
    offset_value: &OffsetValue,
) -> Result<MaybeRelocatable, HintError> {
    // let (register, offset , deref) = if let OffsetValue::Reference(register, offset ,deref ) = offset_value {
    //     (register, offset_value, deref)
    // } else {
    //      return Err(HintError::FailedToGetIds);
    // };
    let (register, offset, deref) = match offset_value {
        OffsetValue::Reference(register, offset, deref) => (register, offset, deref),
        _ => return Err(HintError::FailedToGetIds),
    };

    let base_addr = if register == &Register::FP {
        vm.get_fp()
    } else {
        let var_ap_trackig = hint_reference
            .ap_tracking_data
            .as_ref()
            .ok_or(HintError::NoneApTrackingData)?;

        apply_ap_tracking_correction(&vm.get_ap(), var_ap_trackig, hint_ap_tracking)?
    };

    if offset.is_negative() && base_addr.offset < offset.abs() as usize {
        return Err(HintError::FailedToGetIds);
    }

    if *deref {
        Ok(vm
            .get_maybe(&(base_addr + *offset))
            .map_err(|_| HintError::FailedToGetIds)?
            .ok_or(HintError::FailedToGetIds)?)
    } else {
        Ok((base_addr + *offset).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bigint, relocatable,
        utils::test_utils::*,
        vm::{
            errors::memory_errors::MemoryError, vm_core::VirtualMachine, vm_memory::memory::Memory,
        },
    };
    use num_bigint::Sign;

    #[test]
    fn get_integer_from_reference_with_immediate_value() {
        let mut vm = vm!();
        vm.memory = memory![((1, 0), 0)];
        let mut hint_ref = HintReference::new(0, 0, false, true);
        hint_ref.offset1 = OffsetValue::Immediate(bigint!(2));

        assert_eq!(
            get_integer_from_reference(&vm, &hint_ref, &ApTracking::new())
                .expect("Unexpected get integer fail")
                .into_owned(),
            bigint!(2)
        );
    }

    #[test]
    fn get_ptr_from_reference_short_path() {
        let mut vm = vm!();
        vm.memory = memory![((1, 0), (2, 0))];

        assert_eq!(
            get_ptr_from_reference(
                &vm,
                &HintReference::new(0, 0, false, false),
                &ApTracking::new()
            ),
            Ok(relocatable!(1, 0))
        );
    }

    #[test]
    fn get_ptr_from_reference_with_dereference() {
        let mut vm = vm!();
        vm.memory = memory![((1, 0), (3, 0))];

        assert_eq!(
            get_ptr_from_reference(
                &vm,
                &HintReference::new(0, 0, false, true),
                &ApTracking::new()
            ),
            Ok(relocatable!(3, 0))
        );
    }

    #[test]
    fn get_ptr_from_reference_with_dereference_and_imm() {
        let mut vm = vm!();
        vm.memory = memory![((1, 0), (4, 0))];
        let mut hint_ref = HintReference::new(0, 0, true, false);
        hint_ref.offset2 = OffsetValue::Value(2);

        assert_eq!(
            get_ptr_from_reference(&vm, &hint_ref, &ApTracking::new()),
            Ok(relocatable!(4, 2))
        );
    }

    #[test]
    fn compute_addr_from_reference_no_regiter_in_reference() {
        let mut vm = vm!();
        vm.memory = memory![((1, 0), (4, 0))];
        let mut hint_reference = HintReference::new(0, 0, false, false);
        hint_reference.offset1 = OffsetValue::Immediate(bigint!(2));

        assert_eq!(
            compute_addr_from_reference(&hint_reference, &vm, &ApTracking::new()),
            Err(HintError::NoRegisterInReference)
        );
    }

    #[test]
    fn compute_addr_from_reference_failed_to_get_ids() {
        let mut vm = vm!();
        vm.memory = memory![((1, 0), 4)];
        // vm.run_context.fp = -1;
        let mut hint_reference = HintReference::new(0, 0, false, false);
        hint_reference.offset1 = OffsetValue::Reference(Register::FP, -1, true);

        assert_eq!(
            compute_addr_from_reference(&hint_reference, &vm, &ApTracking::new()),
            Err(HintError::FailedToGetIds)
        );
    }

    #[test]
    fn tracking_correction_invalid_group() {
        let mut ref_ap_tracking = ApTracking::new();
        ref_ap_tracking.group = 1;
        let mut hint_ap_tracking = ApTracking::new();
        hint_ap_tracking.group = 2;

        assert_eq!(
            apply_ap_tracking_correction(&relocatable!(1, 0), &ref_ap_tracking, &hint_ap_tracking),
            Err(HintError::InvalidTrackingGroup(1, 2))
        );
    }
}
