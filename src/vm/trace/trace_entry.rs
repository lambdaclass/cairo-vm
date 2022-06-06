///A trace entry for every instruction that was executed.
///Holds the register values before the instruction was executed.
use crate::types::relocatable::MaybeRelocatable;
#[derive(Debug, PartialEq)]
pub struct TraceEntry {
    pub pc: MaybeRelocatable,
    pub ap: MaybeRelocatable,
    pub fp: MaybeRelocatable,
}

#[derive(Debug, PartialEq)]
pub struct RelocatedTraceEntry {
    pub pc: usize,
    pub ap: usize,
    pub fp: usize,
}

pub fn relocate_trace_register(value: MaybeRelocatable, relocation_table: Vec<usize>) -> usize {
    match value {
        MaybeRelocatable::Int(_num) => panic!("Trace register must be relocatable"),
        MaybeRelocatable::RelocatableValue(relocatable) => {
            assert!(
                relocation_table.len() > relocatable.segment_index,
                "No relocation found for this segment"
            );
            relocation_table[relocatable.segment_index] + relocatable.offset
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
        assert_eq!(relocate_trace_register(value, relocation_table), 12);
    }

    #[test]
    #[should_panic]
    fn relocate_int_value() {
        let value = MaybeRelocatable::from(bigint!(7));
        let relocation_table = vec![1, 2, 5];
        relocate_trace_register(value, relocation_table);
    }

    #[test]
    #[should_panic]
    fn relocate_relocatable_value_no_relocation() {
        let value = MaybeRelocatable::from((2, 7));
        let relocation_table = vec![1, 2];
        relocate_trace_register(value, relocation_table);
    }
}
