///A trace entry for every instruction that was executed.
///Holds the register values before the instruction was executed.
use crate::vm::relocatable::MaybeRelocatable;

pub struct TraceEntry {
    pc: MaybeRelocatable,
    ap: MaybeRelocatable,
    fp: MaybeRelocatable,
}
