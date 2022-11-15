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
) -> Result<Option<(isize, isize)>, VirtualMachineError> {
    trace
        .iter()
        .try_fold(None, |offsets: Option<(isize, isize)>, trace| {
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
                .to_isize()
                .ok_or(VirtualMachineError::BigintToUsizeFail)?;
            let off1 = decoded_instruction
                .off1
                .to_isize()
                .ok_or(VirtualMachineError::BigintToUsizeFail)?;
            let off2 = decoded_instruction
                .off2
                .to_isize()
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::bigint;
    use num_bigint::BigInt;

    /// Test that get_perm_range_check_limits() works as intended with an empty
    /// trace.
    #[test]
    fn get_perm_range_check_limits_empty_trace() {
        let trace = &[];
        let memory = Memory::new();

        assert_eq!(get_perm_range_check_limits(trace, &memory), Ok(None));
    }

    /// Test that get_perm_range_check_limits() works as intended with a single
    /// trace element.
    #[test]
    fn get_perm_range_check_limits_single_element() {
        let trace = &[TraceEntry {
            pc: (0, 0).into(),
            ap: (0, 0).into(),
            fp: (0, 0).into(),
        }];
        let mut memory = Memory::new();
        memory.data = vec![vec![Some(bigint!(0xFFFF_8000_0000u64).into())]];

        assert_eq!(
            get_perm_range_check_limits(trace, &memory),
            Ok(Some((-32768, 32767))),
        );
    }

    /// Test that get_perm_range_check_limits() works as intended with multiple
    /// trace elements.
    #[test]
    fn get_perm_range_check_limits_multiple_elements() {
        let trace = &[
            TraceEntry {
                pc: (0, 0).into(),
                ap: (0, 0).into(),
                fp: (0, 0).into(),
            },
            TraceEntry {
                pc: (0, 1).into(),
                ap: (0, 0).into(),
                fp: (0, 0).into(),
            },
            TraceEntry {
                pc: (0, 2).into(),
                ap: (0, 0).into(),
                fp: (0, 0).into(),
            },
        ];
        let mut memory = Memory::new();
        memory.data = vec![vec![
            Some(bigint!(0x80FF_8000_0530u64).into()),
            Some(bigint!(0xBFFF_8000_0620u64).into()),
            Some(bigint!(0x8FFF_8000_0750u64).into()),
        ]];

        assert_eq!(
            get_perm_range_check_limits(trace, &memory),
            Ok(Some((-31440, 16383))),
        );
    }
}
