use self::trace_entry::TraceEntry;
use super::{
    decoding::decoder::decode_offset, errors::vm_errors::VirtualMachineError,
    vm_memory::memory::Memory,
};
use num_traits::ToPrimitive;

pub mod trace_entry;

/// Return the minimum and maximum values in the perm_range_check component.
pub fn get_perm_range_check_limits(
    trace: &[TraceEntry],
    memory: &Memory,
) -> Result<Option<(isize, isize)>, VirtualMachineError> {
    trace
        .iter()
        .try_fold(None, |offsets: Option<(isize, isize)>, trace| {
            // We only care about offsets and, because this comes from an
            // executino trace, we can be sure it was a valid instruction.
            // So, only extract them with bit operations.
            let instr = memory
                .get_integer((0, trace.pc).into())?
                .to_i64()
                .ok_or(VirtualMachineError::InvalidInstructionEncoding)?;

            const OFF0_OFF: i64 = 0;
            const OFF1_OFF: i64 = 16;
            const OFF2_OFF: i64 = 32;
            const OFFX_MASK: i64 = 0xFFFF;

            let off0 = decode_offset(instr >> OFF0_OFF & OFFX_MASK);
            let off1 = decode_offset(instr >> OFF1_OFF & OFFX_MASK);
            let off2 = decode_offset(instr >> OFF2_OFF & OFFX_MASK);

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
    use crate::{
        types::relocatable::MaybeRelocatable, utils::test_utils::*,
        vm::errors::memory_errors::MemoryError,
    };
    use assert_matches::assert_matches;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    /// Test that get_perm_range_check_limits() works as intended with an empty
    /// trace.
    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn get_perm_range_check_limits_empty_trace() {
        let trace = &[];
        let memory = Memory::new();

        assert_matches!(get_perm_range_check_limits(trace, &memory), Ok(None));
    }

    /// Test that get_perm_range_check_limits() works as intended with a single
    /// trace element.
    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn get_perm_range_check_limits_single_element() {
        let trace = &[TraceEntry {
            pc: 0,
            ap: 0,
            fp: 0,
        }];

        let memory = memory![((0, 0), 0xFFFF_8000_0000_u64)];
        assert_matches!(
            get_perm_range_check_limits(trace, &memory),
            Ok(Some((-32768, 32767)))
        );
    }

    /// Test that get_perm_range_check_limits() works as intended with multiple
    /// trace elements.
    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn get_perm_range_check_limits_multiple_elements() {
        let trace = &[
            TraceEntry {
                pc: 0,
                ap: 0,
                fp: 0,
            },
            TraceEntry {
                pc: 1,
                ap: 0,
                fp: 0,
            },
            TraceEntry {
                pc: 2,
                ap: 0,
                fp: 0,
            },
        ];
        let memory = memory![
            ((0, 0), 0x80FF_8000_0530_u64),
            ((0, 1), 0xBFFF_8000_0620u64),
            ((0, 2), 0x8FFF_8000_0750u64)
        ];

        assert_matches!(
            get_perm_range_check_limits(trace, &memory),
            Ok(Some((-31440, 16383)))
        );
    }
}
