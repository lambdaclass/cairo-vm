use crate::vm::errors::memory_errors::MemoryError;
use num_bigint::BigInt;
use std::fmt;

use crate::types::relocatable::MaybeRelocatable;
use crate::vm::errors::runner_errors::RunnerError;

#[derive(Debug, PartialEq)]
pub enum VirtualMachineError {
    InvalidInstructionEncoding,
    InvalidDstReg(i64),
    InvalidOp0Reg(i64),
    InvalidOp1Reg(i64),
    ImmShouldBe1,
    UnknownOp0,
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
    InconsistentAutoDeduction(String, MaybeRelocatable, Option<MaybeRelocatable>),
    RunnerError(RunnerError),
    HintException(MaybeRelocatable),
    MemoryError(MemoryError),
    UnknownHinError(String),
    NoRangeCheckBuiltin,
    IncorrectIds(Vec<String>, Vec<String>),
    MemoryGet(MaybeRelocatable),
    ExpectedInteger(MaybeRelocatable),
    FailedToGetIds,
    NonLeFelt(BigInt, BigInt),
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
            VirtualMachineError::InconsistentAutoDeduction(builtin_name, expected_value, current_value) => {
                write!(f, "Inconsistent auto-deduction for builtin {}, expected {:?}, got {:?}", builtin_name, expected_value, current_value)
            },
            VirtualMachineError::RunnerError(runner_error) => runner_error.fmt(f),
            VirtualMachineError::HintException(address) => write!(f, "Got an exception while executing a hint at pc: {:?}", address),
            VirtualMachineError::MemoryError(memory_error) => memory_error.fmt(f),
            VirtualMachineError::UnknownHinError(hint_code) => write!(f, "Unknown Hint: {:?}", hint_code),
            VirtualMachineError::NoRangeCheckBuiltin => {
                write!(f, "Expected range_check builtin to be present")
            },
            VirtualMachineError::IncorrectIds(expected, existing) => {
                write!(f, "Expected ids to contain {:?}, got: {:?}", expected, existing)
            },
            VirtualMachineError::MemoryGet(addr) => {
                write!(f, "Failed to retrieve value from address {:?}", addr)
            },
            VirtualMachineError::ExpectedInteger(addr) => {
                write!(f, "Expected integer at address {:?}", addr)
            },
            VirtualMachineError::FailedToGetIds => {
                write!(f, "Failed to get ids from memory")
            },
            VirtualMachineError::NonLeFelt(a, b) => {
                write!(f, "Assertion failed, {}, is not less or equal to {}", a, b)
            },
        }
    }
}
