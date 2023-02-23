use felt::Felt;
use num_bigint::{BigInt, BigUint};
use thiserror::Error;

use crate::types::relocatable::{MaybeRelocatable, Relocatable};

#[derive(Debug, Error, PartialEq)]
pub enum MathError {
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
    // Relocatable Operations
    #[error("Cant convert felt: {0} to Relocatable")]
    FeltToRelocatable(Felt),
    #[error("Operation failed: {0} - {1}, offsets cant be negative")]
    RelocatableSubNegOffset(Relocatable, usize),
    #[error("Operation failed: {0} + {1}, maximum offset value exceeded")]
    RelocatableAddOffsetExceeded(Relocatable, Felt),
    #[error("Operation failed: {0} + {1}, cant add two relocatable values")]
    RelocatableAdd(Relocatable, Relocatable),
    #[error("Operation failed: {0} - {1}, cant substract two relocatable values with different segment indexes")]
    RelocatableSubDiffIndex(Relocatable, Relocatable),
    #[error(
        "Operation failed: {0}.divmod({1}, divmod can only be performed between two integer values"
    )]
    DivModWrongType(MaybeRelocatable, MaybeRelocatable),
    #[error("Operation failed {0} - {1}, cant substract a relocatable value from an integer")]
    SubRelocatableFromInt(Felt, Relocatable),
    // Type conversions
    #[error("Conversion to i32 failed for Felt {0}")]
    FeltToI32Conversion(Felt),
    #[error("Conversion to u32 failed for Felt {0}")]
    FeltToU32Conversion(Felt),
    #[error("Conversion to usize failed for Felt {0}")]
    FeltToUsizeConversion(Felt),
    #[error("Conversion to u64 failed for Felt {0}")]
    FeltToU64Conversion(Felt),
}
