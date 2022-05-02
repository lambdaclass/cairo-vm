use num_bigint::BigInt;
use crate::vm::vm_core::VirtualMachineError;
use std::ops::Add;
use std::ops::Rem;
use std::ops::Sub;

pub struct Relocatable {
    pub segment_index: BigInt,
    pub offset: BigInt
}

pub enum MaybeRelocatable {
    RelocatableValue(Relocatable),
    Int(BigInt)
}

impl Add<BigInt> for MaybeRelocatable {
    type Output = Result<MaybeRelocatable, VirtualMachineError>;
    fn add(self, other: BigInt) -> Result<MaybeRelocatable, VirtualMachineError> {
        if let MaybeRelocatable::Int(num) = self{
            return Ok(MaybeRelocatable::Int(num + other));
        }
        return Err(VirtualMachineError::NotImplementedError);
    }
}
impl Add<MaybeRelocatable> for MaybeRelocatable {
    type Output = Result<MaybeRelocatable, VirtualMachineError>;
    fn add(self, other: MaybeRelocatable) -> Result<MaybeRelocatable, VirtualMachineError> {
        match (self, other) {
            (MaybeRelocatable::Int(num_a), MaybeRelocatable::Int(num_b)) => return Ok(MaybeRelocatable::Int(num_a + num_b)),
            (MaybeRelocatable::RelocatableValue(_), MaybeRelocatable::RelocatableValue(_)) => return Err(VirtualMachineError::RelocatableAddError),
            _ => return Err(VirtualMachineError::NotImplementedError),
        };
    }
}
impl Rem<BigInt> for MaybeRelocatable {
    type Output = MaybeRelocatable;
    fn rem(self, other: BigInt) -> MaybeRelocatable {
        match self {
            MaybeRelocatable::Int(num) => MaybeRelocatable::Int(num % other),
            MaybeRelocatable::RelocatableValue(value) => MaybeRelocatable::RelocatableValue(Relocatable{segment_index: value.segment_index, offset: value.offset % other}),
        }
    }
}

impl Sub<MaybeRelocatable> for MaybeRelocatable {
    type Output = Result<MaybeRelocatable, VirtualMachineError>;
    fn sub(self, other: MaybeRelocatable) -> Result<MaybeRelocatable, VirtualMachineError> {
        match (self, other) {
            (MaybeRelocatable::Int(num_a), MaybeRelocatable::Int(num_b)) => return Ok(MaybeRelocatable::Int(num_a - num_b)),
            (MaybeRelocatable::RelocatableValue(rel_a), MaybeRelocatable::RelocatableValue(rel_b)) => {
                if rel_a.segment_index == rel_b.segment_index {
                    return Ok(MaybeRelocatable::RelocatableValue(Relocatable{segment_index: rel_a.segment_index, offset: rel_a.offset - rel_b.offset}));
                }
                return Err(VirtualMachineError::DiffIndexSubError);
            },
            _ => return Err(VirtualMachineError::NotImplementedError),
        };
    }
}
