use num_bigint::BigInt;
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
    UnconstrainedResAssertEq,
    DiffAssertValues(BigInt, BigInt),
    CantWriteReturnPc(BigInt, BigInt),
    CantWriteReturnFp(BigInt, BigInt),
    NoDst,
    PureValue,
    InvalidRes(i64),
    InvalidOpcode(i64),
    RelocatableAdd,
    OffsetExeeded(BigInt),
    NotImplemented,
    DiffIndexSub,
}

impl fmt::Display for VirtualMachineError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
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
            VirtualMachineError::UnconstrainedResAssertEq => {
                write!(f, "Res.UNCONSTRAINED cannot be used with Opcode.ASSERT_EQ")
            }
            VirtualMachineError::DiffAssertValues(res, dst) => write!(f, "ASSERT_EQ instruction failed; res:{} != dst:{}", res, dst),
            VirtualMachineError::CantWriteReturnPc(op0, ret_pc) => write!(f, "Call failed to write return-pc (inconsistent op0): {} != {}. Did you forget to increment ap?", op0, ret_pc),
            VirtualMachineError::CantWriteReturnFp(dst, ret_fp) => write!(f, "Call failed to write return-pc (inconsistent dst): {} != {}. Did you forget to increment ap?", dst, ret_fp),
            VirtualMachineError::NoDst => write!(f,  "Couldn't get or load dst"),
            VirtualMachineError::InvalidRes(n) => write!(f, "Invalid res value: {}", n),
            VirtualMachineError::InvalidOpcode(n) => write!(f, "Invalid res value: {}", n),
            VirtualMachineError::RelocatableAdd => {
                write!(f, "Cannot add two relocatable values")
            }
            VirtualMachineError::OffsetExeeded(n) => write!(f, "Offset {} exeeds maximum offset value", n),
            VirtualMachineError::NotImplemented => write!(f, "This is not implemented"),
            VirtualMachineError::PureValue => Ok(()),
            VirtualMachineError::DiffIndexSub => write!(
                f,
                "Can only subtract two relocatable values of the same segment"
            ),
        }
    }
}
