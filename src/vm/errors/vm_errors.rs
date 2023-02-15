use crate::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::errors::{
        exec_scope_errors::ExecScopeError, hint_errors::HintError, memory_errors::MemoryError,
        runner_errors::RunnerError, trace_errors::TraceError,
    },
};
use felt::Felt;
use num_bigint::{BigInt, BigUint};
use std::error::Error;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VirtualMachineError {
    #[error("Instruction should be an int")]
    InvalidInstructionEncoding,
    #[error("Invalid op1_register value: {0}")]
    InvalidOp1Reg(i64),
    #[error("In immediate mode, off2 should be 1")]
    ImmShouldBe1,
    #[error("op0 must be known in double dereference")]
    UnknownOp0,
    #[error("Invalid ap_update value: {0}")]
    InvalidApUpdate(i64),
    #[error("Invalid pc_update value: {0}")]
    InvalidPcUpdate(i64),
    #[error("Res.UNCONSTRAINED cannot be used with ApUpdate.ADD")]
    UnconstrainedResAdd,
    #[error("Res.UNCONSTRAINED cannot be used with PcUpdate.JUMP")]
    UnconstrainedResJump,
    #[error("Res.UNCONSTRAINED cannot be used with PcUpdate.JUMP_REL")]
    UnconstrainedResJumpRel,
    #[error("Res.UNCONSTRAINED cannot be used with Opcode.ASSERT_EQ")]
    UnconstrainedResAssertEq,
    #[error("Couldn't compute operand {0} at address {1}")]
    FailedToComputeOperands(String, Relocatable),
    #[error("An ASSERT_EQ instruction failed: {0} != {1}.")]
    DiffAssertValues(MaybeRelocatable, MaybeRelocatable),
    #[error("Call failed to write return-pc (inconsistent op0): {0} != {1}. Did you forget to increment ap?")]
    CantWriteReturnPc(MaybeRelocatable, MaybeRelocatable),
    #[error("Call failed to write return-fp (inconsistent dst): {0} != {1}. Did you forget to increment ap?")]
    CantWriteReturnFp(MaybeRelocatable, MaybeRelocatable),
    #[error("Couldn't get or load dst")]
    NoDst,
    #[error("Pure Value Error")]
    PureValue,
    #[error("Invalid res value: {0}")]
    InvalidRes(i64),
    #[error("Invalid opcode value: {0}")]
    InvalidOpcode(i64),
    #[error("Cannot add two relocatable values")]
    RelocatableAdd,
    #[error("Offset {0} exceeds maximum offset value")]
    OffsetExceeded(Felt),
    #[error("This is not implemented")]
    NotImplemented,
    #[error("Can only subtract two relocatable values of the same segment")]
    DiffIndexSub,
    #[error("Inconsistent auto-deduction for builtin {0}, expected {1}, got {2:?}")]
    InconsistentAutoDeduction(&'static str, MaybeRelocatable, MaybeRelocatable),
    #[error(transparent)]
    RunnerError(#[from] RunnerError),
    #[error("Invalid hint encoding at pc: {0}")]
    InvalidHintEncoding(MaybeRelocatable),
    #[error(transparent)]
    MemoryError(#[from] MemoryError),
    #[error("Expected range_check builtin to be present")]
    NoRangeCheckBuiltin,
    #[error("Expected ecdsa builtin to be present")]
    NoSignatureBuiltin,
    #[error("Failed to retrieve value from address {0}")]
    MemoryGet(MaybeRelocatable),
    #[error("Expected integer at address {0}")]
    ExpectedInteger(MaybeRelocatable),
    #[error("Expected relocatable at address {0}")]
    ExpectedRelocatable(MaybeRelocatable),
    #[error("Value: {0} should be positive")]
    ValueNotPositive(Felt),
    #[error("Div out of range: 0 < {0} <= {1}")]
    OutOfValidRange(Felt, Felt),
    #[error("Failed to compare {0} and {1}, cant compare a relocatable to an integer value")]
    DiffTypeComparison(MaybeRelocatable, MaybeRelocatable),
    #[error("Failed to compare {0} and  {1}, cant compare two relocatable values of different segment indexes")]
    DiffIndexComp(Relocatable, Relocatable),
    #[error("Couldn't convert BigInt to usize")]
    BigintToUsizeFail,
    #[error("Couldn't convert BigInt to u64")]
    BigintToU64Fail,
    #[error("Couldn't convert BigInt to u32")]
    BigintToU32Fail,
    #[error("Couldn't convert usize to u32")]
    NoneInMemoryRange,
    #[error("Couldn't convert usize to u32")]
    UsizeToU32Fail,
    #[error("Can't calculate the square root of negative number: {0})")]
    SqrtNegative(Felt),
    #[error("{0} is not divisible by {1}")]
    SafeDivFail(Felt, Felt),
    #[error("{0} is not divisible by {1}")]
    SafeDivFailBigInt(BigInt, BigInt),
    #[error("{0} is not divisible by {1}")]
    SafeDivFailBigUint(BigUint, BigUint),
    #[error("{0} is not divisible by {1}")]
    SafeDivFailU32(u32, u32),
    #[error("Attempted to divide by zero")]
    SafeDivFailUsize(usize, usize),
    #[error("Attempted to divide by zero")]
    DividedByZero,
    #[error("Failed to calculate the square root of: {0})")]
    FailedToGetSqrt(BigUint),
    #[error("Expected integer, found: {0:?}")]
    ExpectedIntAtRange(Option<MaybeRelocatable>),
    #[error("Could not convert slice to array")]
    SliceToArrayError,
    #[error("Failed to compile hint: {0}")]
    CompileHintFail(String),
    #[error("op1_addr is Op1Addr.IMM, but no immediate was given")]
    NoImm,
    #[error("Cant substract {0} from offset {1}, offsets cant be negative")]
    CantSubOffset(usize, usize),
    #[error("Execution reached the end of the program. Requested remaining steps: {0}.")]
    EndOfProgram(usize),
    #[error(transparent)]
    TracerError(#[from] TraceError),
    #[error(transparent)]
    MainScopeError(#[from] ExecScopeError),
    #[error("Current run is not finished")]
    RunNotFinished,
    #[error("Invalid argument count, expected {0} but got {1}")]
    InvalidArgCount(usize, usize),
    #[error("Couldn't parse prime: {0}")]
    CouldntParsePrime(String),
    #[error("{0}, {1}")]
    ErrorMessageAttribute(String, Box<VirtualMachineError>),
    #[error("Got an exception while executing a hint: {1}")]
    Hint(usize, Box<HintError>),
    #[error("Unexpected Failure")]
    Unexpected,
    #[error("Out of bounds access to builtin segment")]
    OutOfBoundsBuiltinSegmentAccess,
    #[error("Out of bounds access to program segment")]
    OutOfBoundsProgramSegmentAccess,
    #[error("Negative builtin base")]
    NegBuiltinBase,
    #[error("Security Error: Invalid Memory Value: temporary address not relocated: {0}")]
    InvalidMemoryValueTemporaryAddress(Relocatable),
    #[error(transparent)]
    Other(Box<dyn Error>),
}
