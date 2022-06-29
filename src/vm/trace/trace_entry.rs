///A trace entry for every instruction that was executed.
///Holds the register values before the instruction was executed.
use crate::types::relocatable::MaybeRelocatable;
use crate::vm::errors::trace_errors::TraceError;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq)]
pub struct TraceEntry {
    pub pc: MaybeRelocatable,
    pub ap: MaybeRelocatable,
    pub fp: MaybeRelocatable,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct RelocatedTraceEntry {
    pub ap: usize,
    pub fp: usize,
    pub pc: usize,
}

pub fn relocate_trace_register(
    value: MaybeRelocatable,
    relocation_table: &Vec<usize>,
) -> Result<usize, TraceError> {
    match value {
        MaybeRelocatable::Int(_num) => Err(TraceError::RegNotRelocatable),
        MaybeRelocatable::RelocatableValue(relocatable) => {
            if relocation_table.len() <= relocatable.segment_index {
                return Err(TraceError::NoRelocationFound);
            }
            Ok(relocation_table[relocatable.segment_index] + relocatable.offset)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint;
    use num_bigint::BigInt;
    use num_traits::FromPrimitive;

    #[test]
    fn relocate_relocatable_value() {
        let value = MaybeRelocatable::from((2, 7));
        let relocation_table = vec![1, 2, 5];
        assert_eq!(
            relocate_trace_register(value, &relocation_table).unwrap(),
            12
        );
    }

    #[test]
    fn relocate_int_value() {
        let value = MaybeRelocatable::from(bigint!(7));
        let relocation_table = vec![1, 2, 5];
        let error = relocate_trace_register(value, &relocation_table);
        assert_eq!(error, Err(TraceError::RegNotRelocatable));
    }

    #[test]
    fn relocate_relocatable_value_no_relocation() {
        let value = MaybeRelocatable::from((2, 7));
        let relocation_table = vec![1, 2];
        let error = relocate_trace_register(value, &relocation_table);
        assert_eq!(error, Err(TraceError::NoRelocationFound));
    }
}
