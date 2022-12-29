use num_bigint::BigInt;
use thiserror::Error;

use crate::types::relocatable::{MaybeRelocatable, Relocatable};

use super::{exec_scope_errors::ExecScopeError, vm_errors::VirtualMachineError};

#[derive(Debug, PartialEq, Error)]
pub enum HintError {
    #[error("HintProcessor failed retrieve the compiled data necessary for hint execution")]
    WrongHintData,
    #[error("Failed to get ids for hint execution")]
    FailedToGetIds,
    #[error("Tried to compute an address but there was no register in the reference.")]
    NoRegisterInReference,
    #[error("Custom Hint Error: {0}")]
    CustomHint(String),
    #[error("Missing constant: {0}")]
    MissingConstant(&'static str),
    #[error("Fail to get constants for hint execution")]
    FailedToGetConstant,
    #[error("Arc too big, {0} must be <= {1} and {2} <= {3}")]
    ArcTooBig(BigInt, BigInt, BigInt, BigInt),
    #[error("Excluded is supposed to be 2, got {0}")]
    ExcludedNot2(BigInt),
    #[error("Value: {0} is outside of the range [0, 2**250)")]
    ValueOutside250BitRange(BigInt),
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
    #[error("find_element() can only be used with n_elms <= {0}.\nGot: n_elms = {1}")]
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
    #[error("Expected relocatable for ap, got {0}")]
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
    #[error(transparent)]
    Internal(#[from] VirtualMachineError),
    #[error("Couldn't convert BigInt to usize")]
    BigintToUsizeFail,
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
    #[error("Set's starting point {0} is bigger it's ending point {1}")]
    InvalidSetRange(MaybeRelocatable, MaybeRelocatable),
    #[error("Failed to construct a fixed size array of size: {0}")]
    FixedSizeArrayFail(usize),
    #[error("{0}")]
    AssertionFailed(String),
    #[error("Wrong dict pointer supplied. Got {0}, expected {1}.")]
    MismatchedDictPtr(Relocatable, Relocatable),
    #[error("Integer must be postive or zero, got: {0}")]
    SecpSplitNegative(BigInt),
    #[error("Integer: {0} out of range")]
    SecpSplitutOfRange(BigInt),
    #[error("verify_zero: Invalid input {0}")]
    SecpVerifyZero(BigInt),
    #[error("unsafe_keccak() can only be used with length<={0}. Got: length={1}")]
    KeccakMaxSize(BigInt, BigInt),
    #[error("Invalid word size: {0}")]
    InvalidWordSize(BigInt),
    #[error("Invalid input length, Got: length={0}")]
    InvalidKeccakInputLength(BigInt),
    #[error(transparent)]
    FromScopeError(#[from] ExecScopeError),
    #[error("assert_not_equal failed: {0} =  {1}")]
    AssertNotEqualFail(MaybeRelocatable, MaybeRelocatable),
    #[error("split_int(): value is out of range")]
    SplitIntNotZero,
    #[error("split_int(): Limb {0} is out of range.")]
    SplitIntLimbOutOfRange(BigInt),
    #[error("Expected size to be in the range from [0, 100), got: {0}")]
    InvalidKeccakStateSizeFelts(BigInt),
    #[error("Expected size to be in range from [0, 10), got: {0}")]
    InvalidBlockSize(BigInt),
    #[error("Couldn't convert BigInt to u32")]
    BigintToU32Fail,
    #[error("Value of of range {0}")]
    ValueOutOfRange(BigInt),
    #[error("Assertion failed, 0 <= ids.a % PRIME < range_check_builtin.bound \n a = {0} is out of range")]
    AssertNNValueOutOfRange(BigInt),
    #[error("Assertion failed, {0} % {1} is equal to 0")]
    AssertNotZero(BigInt, BigInt),
    #[error("Div out of range: 0 < {0} <= {1}")]
    OutOfValidRange(BigInt, BigInt),
    #[error("Value: {0} is outside valid range")]
    ValueOutsideValidRange(BigInt),
    #[error("Assertion failed, {0}, is not less or equal to {1}")]
    NonLeFelt(BigInt, BigInt),
    #[error("Unknown Hint: {0}")]
    UnknownHint(String),
}
