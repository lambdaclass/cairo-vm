use self::trace_entry::TraceEntry;
use super::{
    decoding::decoder::decode_instruction, errors::vm_errors::VirtualMachineError,
    vm_memory::memory::Memory,
};
use crate::types::relocatable::{MaybeRelocatable, Relocatable};
use num_traits::ToPrimitive;
use std::borrow::Cow;

pub mod trace_entry;

/// Return the minimum and maximum values in the perm_range_check component.
pub fn get_perm_range_check_limits(
    trace: &[TraceEntry],
    memory: &Memory,
) -> Result<Option<(usize, usize)>, VirtualMachineError> {
    trace
        .iter()
        .try_fold(None, |offsets: Option<(usize, usize)>, trace| {
            let instruction = memory.get_integer(&trace.pc)?;
            let immediate =
                memory.get::<Relocatable>(&(trace.pc.segment_index, trace.pc.offset + 1).into())?;

            let instruction = instruction
                .to_i64()
                .ok_or(VirtualMachineError::InvalidInstructionEncoding)?;
            let immediate = immediate
                .map(|x| match x {
                    Cow::Borrowed(MaybeRelocatable::Int(value)) => Ok(value.clone()),
                    Cow::Owned(MaybeRelocatable::Int(value)) => Ok(value),
                    _ => Err(VirtualMachineError::ExpectedInteger(
                        (trace.pc.segment_index, trace.pc.offset + 1).into(),
                    )),
                })
                .transpose()?;

            let decoded_instruction = decode_instruction(instruction, immediate)?;
            let off0 = decoded_instruction
                .off0
                .to_usize()
                .ok_or(VirtualMachineError::BigintToUsizeFail)?;
            let off1 = decoded_instruction
                .off1
                .to_usize()
                .ok_or(VirtualMachineError::BigintToUsizeFail)?;
            let off2 = decoded_instruction
                .off2
                .to_usize()
                .ok_or(VirtualMachineError::BigintToUsizeFail)?;

            let min_value = off0.min(off1).min(off2);
            let max_value = off0.max(off1).max(off2);
            Ok(
                offsets.map_or(Some((min_value, max_value)), |(min_offset, max_offset)| {
                    Some((min_offset.min(min_value), max_offset.max(max_value)))
                }),
            )
        })
}
