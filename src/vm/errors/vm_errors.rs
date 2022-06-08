use std::fmt;

#[derive(Debug, PartialEq)]
#[allow(dead_code)]
pub enum VirtualMachineError {
    InvalidInstructionEncoding,
    InvalidDstReg(i64),
    InvalidOp0Reg(i64),
    InvalidOp1Reg(i64),
    ImmShouldBe1,
    UnknownOp0,
    InvalidFpUpdate,
    InvalidApUpdate(i64),
    InvalidPcUpdate(i64),
    UnconstrainedResAdd,
    UnconstrainedResJump,
    UnconstrainedResJumpRel,
    PureValue,
    InvalidRes(i64),
    InvalidOpcode(i64),
    RelocatableAdd,
    NotImplemented,
    DiffIndexSub,
}

impl fmt::Display for VirtualMachineError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            VirtualMachineError::InvalidInstructionEncoding => {
                write!(f, "Instruction should be an int. Found:")
            }
            VirtualMachineError::InvalidDstReg(n) => write!(f, "Invalid dst_register value: {}", n),
            VirtualMachineError::InvalidOp0Reg(n) => write!(f, "Invalid op0_register value: {}", n),
            VirtualMachineError::InvalidOp1Reg(n) => write!(f, "Invalid op1_register value: {}", n),
            VirtualMachineError::ImmShouldBe1 => {
                write!(f, "In immediate mode, off2 should be 1")
            }
            VirtualMachineError::UnknownOp0 => {
                write!(f, "op0 must be known in double dereference")
            }
            VirtualMachineError::InvalidFpUpdate => write!(f, "Invalid fp_update value"),
            VirtualMachineError::InvalidApUpdate(n) => write!(f, "Invalid ap_update value: {}", n),
            VirtualMachineError::InvalidPcUpdate(n) => write!(f, "Invalid pc_update value: {}", n),
            VirtualMachineError::UnconstrainedResAdd => {
                write!(f, "Res.UNCONSTRAINED cannot be used with ApUpdate.ADD")
            }
            VirtualMachineError::UnconstrainedResJump => {
                write!(f, "Res.UNCONSTRAINED cannot be used with PcUpdate.JUMP")
            }
            VirtualMachineError::UnconstrainedResJumpRel => {
                write!(f, "Res.UNCONSTRAINED cannot be used with PcUpdate.JUMP_REL")
            }
            VirtualMachineError::InvalidRes(n) => write!(f, "Invalid res value: {}", n),
            VirtualMachineError::InvalidOpcode(n) => write!(f, "Invalid res value: {}", n),
            VirtualMachineError::RelocatableAdd => {
                write!(f, "Cannot add two relocatable values")
            }
            VirtualMachineError::NotImplemented => write!(f, "This is not implemented"),
            VirtualMachineError::PureValue => Ok(()), //TODO
            VirtualMachineError::DiffIndexSub => write!(
                f,
                "Can only subtract two relocatable values of the same segment"
            ),
        }
    }
}
