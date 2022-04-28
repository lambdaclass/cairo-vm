///A trace entry for every instruction that was executed.
///Holds the register values before the instruction was executed.
pub struct TraceEntry<T> {
    pc: T,
    ap: T,
    fp: T
}
