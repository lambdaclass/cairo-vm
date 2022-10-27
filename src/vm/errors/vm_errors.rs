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
    #[error("Res.UNCONSTRAINED cannot be used with PcUpdate.JUMP")]
    UnconstrainedResJump,
    #[error("Res.UNCONSTRAINED cannot be used with PcUpdate.JUMP_REL")]
    UnconstrainedResJumpRel,
    #[error("Res.UNCONSTRAINED cannot be used with Opcode.ASSERT_EQ")]
    UnconstrainedResAssertEq,
    #[error("ASSERT_EQ instruction failed; res:{0} != dst:{1}")]
    DiffAssertValues(BigInt, BigInt),
    #[error("Call failed to write return-pc (inconsistent op0): {0:?} != {1:?}. Did you forget to increment ap?")]
    CantWriteReturnPc(MaybeRelocatable, MaybeRelocatable),
    #[error("Call failed to write return-fp (inconsistent dst): {0:?} != {1:?}. Did you forget to increment ap?")]
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
    #[error("Offset {0} exeeds maximum offset value")]
    OffsetExceeded(BigInt),
    #[error("This is not implemented")]
    NotImplemented,
    #[error("Can only subtract two relocatable values of the same segment")]
    DiffIndexSub,
    #[error("Inconsistent auto-deduction for builtin {0}, expected {1:?}, got {2:?}")]
    InconsistentAutoDeduction(String, MaybeRelocatable, Option<MaybeRelocatable>),
    #[error(transparent)]
    RunnerError(#[from] RunnerError),
    #[error("Invalid hint encoding at pc: {0:?}")]
    InvalidHintEncoding(MaybeRelocatable),
    #[error(transparent)]
    MemoryError(#[from] MemoryError),
    #[error("Expected range_check builtin to be present")]
    NoRangeCheckBuiltin,
    #[error("Failed to retrieve value from address {0:?}")]
    MemoryGet(MaybeRelocatable),
    #[error("Expected integer at address {0:?}")]
    ExpectedInteger(MaybeRelocatable),
    #[error("Expected relocatable at address {0:?}")]
    ExpectedRelocatable(MaybeRelocatable),
    #[error("Failed to get ids for hint execution")]
    FailedToGetIds,
    #[error("Assertion failed, {0}, is not less or equal to {1}")]
    NonLeFelt(BigInt, BigInt),
    #[error("Div out of range: 0 < {0} <= {1}")]
    OutOfValidRange(BigInt, BigInt),
    #[error("Assertion failed, 0 <= ids.a % PRIME < range_check_builtin.bound \n a = {0:?} is out of range")]
    ValueOutOfRange(BigInt),
    #[error("Value: {0} should be positive")]
    ValueNotPositive(BigInt),
    #[error("Unknown Hint: {0}")]
    UnknownHint(String),
    #[error("Value: {0} is outside valid range")]
    ValueOutsideValidRange(BigInt),
    #[error("split_int(): value is out of range")]
    SplitIntNotZero,
    #[error("split_int(): Limb {0} is out of range.")]
    SplitIntLimbOutOfRange(BigInt),
    #[error("Failed to compare {0:?} and {1:?}, cant compare a relocatable to an integer value")]
    DiffTypeComparison(MaybeRelocatable, MaybeRelocatable),
    #[error("assert_not_equal failed: {0:?} =  {1:?}")]
    AssertNotEqualFail(MaybeRelocatable, MaybeRelocatable),
    #[error("Failed to compare {0:?} and  {1:?}, cant compare two relocatable values of different segment indexes")]
    DiffIndexComp(Relocatable, Relocatable),
    #[error("Value: {0} is outside of the range [0, 2**250)")]
    ValueOutside250BitRange(BigInt),
    #[error("Can't calculate the square root of negative number: {0})")]
    SqrtNegative(BigInt),
    #[error("{0} is not divisible by {1}")]
    SafeDivFail(BigInt, BigInt),
    #[error("Attempted to devide by zero")]
    DividedByZero,
    #[error("Failed to calculate the square root of: {0})")]
    FailedToGetSqrt(BigInt),
    #[error("Assertion failed, {0} % {1} is equal to 0")]
    AssertNotZero(BigInt, BigInt),
    #[error(transparent)]
    MainScopeError(#[from] ExecScopeError),
    #[error("Failed to get scope variables")]
    ScopeError,
    #[error("Variable {0} not present in current execution scope")]
    VariableNotInScopeError(String),
    #[error("DictManagerError: Tried to create tracker for a dictionary on segment: {0} when there is already a tracker for a dictionary on this segment")]
    CantCreateDictionaryOnTakenSegment(isize),
    #[error("Dict Error: No dict tracker found for segment {0}")]
    NoDictTracker(isize),
    #[error("ict Error: No value found for key: {0}")]
    NoValueForKey(BigInt),
    #[error("Assertion failed, a = {0} % PRIME is not less than b = {1} % PRIME")]
    AssertLtFelt(BigInt, BigInt),
    #[error("find_elem() can only be used with n_elms <= {0}.\nGot: n_elms = {1}")]
    FindElemMaxSize(BigInt, BigInt),
    #[error(
        "Invalid index found in find_element_index. Index: {0}.\nExpected key: {1}, found_key {2}"
    )]
    InvalidIndex(BigInt, BigInt, BigInt),
    #[error("Found Key is None")]
    KeyNotFound,
    #[error("AP tracking data is None; could not apply correction to address")]
    NoneApTrackingData,
    #[error("Tracking groups should be the same, got {0} and {1}")]
    InvalidTrackingGroup(usize, usize),
    #[error("Expected relocatable for ap, got {0:?}")]
    InvalidApValue(MaybeRelocatable),
    #[error("Dict Error: Tried to create a dict whithout an initial dict")]
    NoInitialDict,
    #[error("squash_dict_inner fail: couldnt find key {0} in accesses_indices")]
    NoKeyInAccessIndices(BigInt),
    #[error("squash_dict_inner fail: local accessed_indices is empty")]
    EmptyAccessIndices,
    #[error("squash_dict_inner fail: local current_accessed_indices is empty")]
    EmptyCurrentAccessIndices,
    #[error("squash_dict_inner fail: local current_accessed_indices not empty, loop ended with remaining unaccounted elements")]
    CurrentAccessIndicesNotEmpty,
    #[error("Dict Error: Got the wrong value for dict_update, expected value: {0}, got: {1} for key: {2}")]
    WrongPrevValue(BigInt, BigInt, BigInt),
    #[error("squash_dict_inner fail: Number of used accesses:{0} doesnt match the lengh: {1} of the access_indices at key: {2}")]
    NumUsedAccessesAssertFail(BigInt, usize, BigInt),
    #[error("squash_dict_inner fail: local keys is not empty")]
    KeysNotEmpty,
    #[error("squash_dict_inner fail: No keys left but remaining_accesses > 0")]
    EmptyKeys,
    #[error("squash_dict fail: Accesses array size must be divisible by DictAccess.SIZE")]
    PtrDiffNotDivisibleByDictAccessSize,
    #[error("squash_dict() can only be used with n_accesses<={0}. ' \nGot: n_accesses={1}")]
    SquashDictMaxSizeExceeded(BigInt, BigInt),
    #[error("squash_dict fail: n_accesses: {0} is too big to be converted into an iterator")]
    NAccessesTooBig(BigInt),
    #[error("Couldn't convert BigInt to usize")]
    BigintToUsizeFail,
    #[error("Couldn't convert BigInt to u64")]
    BigintToU64Fail,
    #[error("Couldn't convert BigInt to u32")]
    BigintToU32Fail,
    #[error("usort() can only be used with input_len<={0}. Got: input_len={1}.")]
    UsortOutOfRange(u64, BigInt),
    #[error("unexpected usort fail: positions_dict or key value pair not found")]
    UnexpectedPositionsDictFail,
    #[error("unexpected verify multiplicity fail: positions not found")]
    PositionsNotFound,
    #[error("unexpected verify multiplicity fail: positions length != 0")]
    PositionsLengthNotZero,
    #[error("unexpected verify multiplicity fail: couldn't pop positions")]
    CouldntPopPositions,
    #[error("unexpected verify multiplicity fail: last_pos not found")]
    LastPosNotFound,
    #[error("Set starting point {0:?} is bigger it's ending point {1:?}")]
    InvalidSetRange(MaybeRelocatable, MaybeRelocatable),
    #[error("Failed to construct a fixed size array of size: {0}")]
    FixedSizeArrayFail(usize),
    #[error("{0}")]
    AssertionFailed(String),
    #[error("Wrong dict pointer supplied. Got {0:?}, expected {1:?}.")]
    MismatchedDictPtr(Relocatable, Relocatable),
    #[error("Integer must be postive or zero, got: {0}")]
    SecpSplitNegative(BigInt),
    #[error("Integer: {0} out of range")]
    SecpSplitutOfRange(BigInt),
    #[error("verify_zero: Invalid input {0}")]
    SecpVerifyZero(BigInt),
    #[error("Cant substract {0} from offset {1}, offsets cant be negative")]
    CantSubOffset(usize, usize),
    #[error("unsafe_keccak() can only be used with length<={0}. Got: length={1}")]
    KeccakMaxSize(BigInt, BigInt),
    #[error("Invalid word size: {0}")]
    InvalidWordSize(BigInt),
    #[error("Invalid input length, Got: length={0}")]
    InvalidKeccakInputLength(BigInt),
    #[error("None value was found in memory range cell")]
    NoneInMemoryRange,
    #[error("Expected integer, found: {0:?}")]
    ExpectedIntAtRange(Option<MaybeRelocatable>),
    #[error("Expected size to be in the range from [0, 100), got: {0}")]
    InvalidKeccakStateSizeFelts(BigInt),
    #[error("Expected size to be in range from [0, 10), got: {0}")]
    InvalidBlockSize(BigInt),
    #[error("Could not convert slice to array")]
    SliceToArrayError,
    #[error("HintProcessor failed retrieve the compiled data necessary for hint execution")]
    WrongHintData,
    #[error("Failed to compile hint: {0}")]
    CompileHintFail(String),
    #[error("op1_addr is Op1Addr.IMM, but no immediate given")]
    NoImm,
    #[error("Tried to compute an address but there was no register in the reference.")]
    NoRegisterInReference,
    #[error("Couldn't compute operands")]
    FailedToComputeOperands,
    #[error("Custom Hint Error: {0}")]
    CustomHint(String),
    #[error("Missing constant: {0}")]
    MissingConstant(&'static str),
    #[error("Fail to get constants for hint execution")]
    FailedToGetConstant,
}
