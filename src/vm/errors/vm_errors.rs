use crate::types::relocatable::{MaybeRelocatable, Relocatable};
use crate::vm::errors::memory_errors::MemoryError;
use crate::vm::errors::runner_errors::RunnerError;
use num_bigint::BigInt;
use thiserror::Error;

use super::exec_scope_errors::ExecScopeError;

#[derive(Debug, PartialEq, Error)]
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
    #[error("Res.UNCONSTRAINED cannot be used with ApUpdate.ADD")]
    UnconstrainedResJump,
    #[error("Res.UNCONSTRAINED cannot be used with PcUpdate.JUMP")]
    UnconstrainedResJumpRel,
    #[error("Res.UNCONSTRAINED cannot be used with Opcode.ASSERT_EQ")]
    UnconstrainedResAssertEq,
    #[error("ASSERT_EQ instruction failed; res:{0} != dst:{1}")]
    DiffAssertValues(BigInt, BigInt),
    #[error("Call failed to write return-pc (inconsistent op0): {0} != {1}. Did you forget to increment ap?")]
    CantWriteReturnPc(BigInt, BigInt),
    #[error("Call failed to write return-fc (inconsistent op0): {0} != {1}. Did you forget to increment ap?")]
    CantWriteReturnFp(BigInt, BigInt),
    #[error("")]
    NoDst,
    #[error("")]
    PureValue,
    #[error("")]
    InvalidRes(i64),
    #[error("")]
    InvalidOpcode(i64),
    #[error("")]
    RelocatableAdd,
    #[error("")]
    OffsetExceeded(BigInt),
    #[error("")]
    NotImplemented,
    #[error("")]
    DiffIndexSub,
    #[error("")]
    InconsistentAutoDeduction(String, MaybeRelocatable, Option<MaybeRelocatable>),
    #[error("")]
    RunnerError(RunnerError),
    #[error("")]
    InvalidHintEncoding(MaybeRelocatable),
    #[error("")]
    MemoryError(MemoryError),
    #[error("")]
    NoRangeCheckBuiltin,
    #[error("")]
    IncorrectIds(Vec<String>, Vec<String>),
    #[error("")]
    MemoryGet(MaybeRelocatable),
    #[error("")]
    ExpectedInteger(MaybeRelocatable),
    #[error("")]
    ExpectedRelocatable(MaybeRelocatable),
    #[error("")]
    ExpectedRelocatableAtAddr(MaybeRelocatable),
    #[error("")]
    FailedToGetIds,
    #[error("")]
    NonLeFelt(BigInt, BigInt),
    #[error("")]
    OutOfValidRange(BigInt, BigInt),
    #[error("")]
    FailedToGetReference(BigInt),
    #[error("")]
    ValueOutOfRange(BigInt),
    #[error("")]
    ValueNotPositive(BigInt),
    #[error("")]
    UnknownHint(String),
    #[error("")]
    ValueOutsideValidRange(BigInt),
    #[error("")]
    SplitIntNotZero,
    #[error("")]
    SplitIntLimbOutOfRange(BigInt),
    #[error("")]
    DiffTypeComparison(MaybeRelocatable, MaybeRelocatable),
    #[error("")]
    AssertNotEqualFail(MaybeRelocatable, MaybeRelocatable),
    #[error("")]
    DiffIndexComp(Relocatable, Relocatable),
    #[error("")]
    ValueOutside250BitRange(BigInt),
    #[error("")]
    SqrtNegative(BigInt),
    #[error("")]
    SafeDivFail(BigInt, BigInt),
    #[error("")]
    DividedByZero,
    #[error("")]
    FailedToGetSqrt(BigInt),
    #[error("")]
    AssertNotZero(BigInt, BigInt),
    #[error("")]
    MainScopeError(ExecScopeError),
    #[error("")]
    ScopeError,
    #[error("")]
    VariableNotInScopeError(String),
    #[error("")]
    CantCreateDictionaryOnTakenSegment(usize),
    #[error("")]
    NoDictTracker(usize),
    #[error("")]
    NoValueForKey(BigInt),
    #[error("")]
    AssertLtFelt(BigInt, BigInt),
    #[error("")]
    FindElemMaxSize(BigInt, BigInt),
    #[error("")]
    InvalidIndex(BigInt, BigInt, BigInt),
    #[error("")]
    KeyNotFound,
    #[error("")]
    NoneApTrackingData,
    #[error("")]
    InvalidTrackingGroup(usize, usize),
    #[error("")]
    InvalidApValue(MaybeRelocatable),
    #[error("")]
    NoInitialDict,
    #[error("")]
    NoKeyInAccessIndices(BigInt),
    #[error("")]
    EmptyAccessIndices,
    #[error("")]
    EmptyCurrentAccessIndices,
    #[error("")]
    CurrentAccessIndicesNotEmpty,
    #[error("")]
    WrongPrevValue(BigInt, BigInt, BigInt),
    #[error("")]
    NumUsedAccessesAssertFail(BigInt, usize, BigInt),
    #[error("")]
    KeysNotEmpty,
    #[error("")]
    EmptyKeys,
    #[error("")]
    PtrDiffNotDivisibleByDictAccessSize,
    #[error("")]
    SquashDictMaxSizeExceeded(BigInt, BigInt),
    #[error("")]
    NAccessesTooBig(BigInt),
    #[error("")]
    BigintToUsizeFail,
    #[error("")]
    BigintToU64Fail,
    #[error("")]
    BigintToU32Fail,
    #[error("")]
    UsortOutOfRange(u64, BigInt),
    #[error("")]
    UnexpectedPositionsDictFail,
    #[error("")]
    PositionsNotFound,
    #[error("")]
    PositionsLengthNotZero,
    #[error("")]
    CouldntPopPositions,
    #[error("")]
    LastPosNotFound,
    #[error("")]
    InvalidSetRange(MaybeRelocatable, MaybeRelocatable),
    #[error("")]
    UnexpectMemoryGap,
    #[error("")]
    FixedSizeArrayFail(usize),
    #[error("")]
    AssertionFailed(String),
    #[error("")]
    MismatchedDictPtr(Relocatable, Relocatable),
    #[error("")]
    SecpSplitNegative(BigInt),
    #[error("")]
    SecpSplitutOfRange(BigInt),
    #[error("")]
    SecpVerifyZero(BigInt),
    #[error("")]
    CantSubOffset(usize, usize),
    #[error("")]
    KeccakMaxSize(BigInt, BigInt),
    #[error("")]
    InvalidWordSize(BigInt),
    #[error("")]
    InvalidKeccakInputLength(BigInt),
    #[error("")]
    NoneInMemoryRange,
    #[error("")]
    ExpectedIntAtRange(Option<MaybeRelocatable>),
    #[error("")]
    IdNotFound(String),
    #[error("")]
    InvalidKeccakStateSizeFelts(usize),
    #[error("")]
    InvalidBlockSize(usize),
    #[error("")]
    SliceToArrayError,
}
