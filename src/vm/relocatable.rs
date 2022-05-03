use crate::vm::vm_core::VirtualMachineError;
use num_bigint::BigInt;
use num_traits::FromPrimitive;
use std::ops::Add;
use std::ops::Rem;
use std::ops::Sub;

#[derive(Eq, Hash, PartialEq, Clone)]
pub struct Relocatable {
    pub segment_index: BigInt,
    pub offset: BigInt,
}

#[derive(Eq, Hash, PartialEq, Clone)]
pub enum MaybeRelocatable {
    RelocatableValue(Relocatable),
    Int(BigInt),
}

impl Add<BigInt> for MaybeRelocatable {
    type Output = Result<MaybeRelocatable, VirtualMachineError>;
    fn add(self, other: BigInt) -> Result<MaybeRelocatable, VirtualMachineError> {
        if let MaybeRelocatable::Int(num) = self {
            return Ok(MaybeRelocatable::Int(num + other));
        }
        return Err(VirtualMachineError::NotImplementedError);
    }
}
impl Add<MaybeRelocatable> for MaybeRelocatable {
    type Output = Result<MaybeRelocatable, VirtualMachineError>;
    fn add(self, other: MaybeRelocatable) -> Result<MaybeRelocatable, VirtualMachineError> {
        match (self, other) {
            (MaybeRelocatable::Int(num_a), MaybeRelocatable::Int(num_b)) => {
                return Ok(MaybeRelocatable::Int(num_a + num_b))
            }
            (MaybeRelocatable::RelocatableValue(_), MaybeRelocatable::RelocatableValue(_)) => {
                return Err(VirtualMachineError::RelocatableAddError)
            }
            _ => return Err(VirtualMachineError::NotImplementedError),
        };
    }
}
impl Rem<BigInt> for MaybeRelocatable {
    type Output = MaybeRelocatable;
    fn rem(self, other: BigInt) -> MaybeRelocatable {
        match self {
            MaybeRelocatable::Int(num) => MaybeRelocatable::Int(num % other),
            MaybeRelocatable::RelocatableValue(value) => {
                MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: value.segment_index,
                    offset: value.offset % other,
                })
            }
        }
    }
}

impl Sub<MaybeRelocatable> for MaybeRelocatable {
    type Output = Result<MaybeRelocatable, VirtualMachineError>;
    fn sub(self, other: MaybeRelocatable) -> Result<MaybeRelocatable, VirtualMachineError> {
        match (self, other) {
            (MaybeRelocatable::Int(num_a), MaybeRelocatable::Int(num_b)) => {
                return Ok(MaybeRelocatable::Int(num_a - num_b))
            }
            (
                MaybeRelocatable::RelocatableValue(rel_a),
                MaybeRelocatable::RelocatableValue(rel_b),
            ) => {
                if rel_a.segment_index == rel_b.segment_index {
                    return Ok(MaybeRelocatable::RelocatableValue(Relocatable {
                        segment_index: rel_a.segment_index,
                        offset: rel_a.offset - rel_b.offset,
                    }));
                }
                return Err(VirtualMachineError::DiffIndexSubError);
            }
            _ => return Err(VirtualMachineError::NotImplementedError),
        };
    }
}

impl MaybeRelocatable {
    /// Returns the immediate adress (Current Address + 1)
    pub fn imm_address(&self) -> Result<MaybeRelocatable, VirtualMachineError> {
        if let &MaybeRelocatable::Int(ref value) = self {
            let mut num = Clone::clone(value);
            num = BigInt::from_i32(1).unwrap() + num;
            return Ok(MaybeRelocatable::Int(num));
        } else {
            return Err(VirtualMachineError::NotImplementedError);
        };
    }
    ///Adds a number to the address, then performs mod prime if prime is given
    pub fn add_num_addr(
        &self,
        other: BigInt,
        prime: Option<BigInt>,
    ) -> Result<MaybeRelocatable, VirtualMachineError> {
        if let &MaybeRelocatable::Int(ref value) = self {
            let mut num = Clone::clone(value);
            num = other + num;
            if let Some(num_prime) = prime {
                num = num % num_prime;
            }
            return Ok(MaybeRelocatable::Int(num));
        } else {
            return Err(VirtualMachineError::NotImplementedError);
        };
    }

    ///Adds a number to the address, then performs mod prime if prime is given
    pub fn add_addr(
        &self,
        other: MaybeRelocatable,
        prime: Option<BigInt>,
    ) -> Result<MaybeRelocatable, VirtualMachineError> {
        match (self, other) {
            (&MaybeRelocatable::Int(ref num_a_ref), MaybeRelocatable::Int(num_b)) => {
                let num_a = Clone::clone(num_a_ref);
                if let Some(num_prime) = prime {
                    return Ok(MaybeRelocatable::Int((num_a + num_b) % num_prime));
                }
                return Ok(MaybeRelocatable::Int(num_a + num_b));
            }
            (&MaybeRelocatable::RelocatableValue(_), MaybeRelocatable::RelocatableValue(_)) => {
                return Err(VirtualMachineError::RelocatableAddError)
            }
            _ => return Err(VirtualMachineError::NotImplementedError),
        };
    }
    pub fn sub_addr(
        &self,
        other: &MaybeRelocatable,
    ) -> Result<MaybeRelocatable, VirtualMachineError> {
        match (self, other) {
            (&MaybeRelocatable::Int(ref num_a_ref), &MaybeRelocatable::Int(ref num_b_ref)) => {
                let num_a = Clone::clone(num_a_ref);
                let num_b = Clone::clone(num_b_ref);
                return Ok(MaybeRelocatable::Int(num_a - num_b));
            }
            (
                MaybeRelocatable::RelocatableValue(rel_a),
                MaybeRelocatable::RelocatableValue(rel_b),
            ) => {
                if rel_a.segment_index == rel_b.segment_index {
                    return Ok(MaybeRelocatable::RelocatableValue(Relocatable {
                        segment_index: rel_a.segment_index.clone(),
                        offset: rel_a.offset.clone() - rel_b.offset.clone(),
                    }));
                }
                return Err(VirtualMachineError::DiffIndexSubError);
            }
            _ => return Err(VirtualMachineError::NotImplementedError),
        };
    }
}
