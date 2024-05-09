use serde::Serialize;

// TODO: check if the sizes are corect
#[derive(Serialize, Clone)]
pub struct MemoryAccess {
    pub(crate) dst: usize,
    pub(crate) op0: usize,
    pub(crate) op1: usize,
}
