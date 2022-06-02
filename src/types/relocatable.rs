use crate::vm::vm_core::VirtualMachineError;
use num_bigint::BigInt;
use num_traits::ToPrimitive;

#[derive(Eq, Hash, PartialEq, Clone, Debug)]
pub struct Relocatable {
    pub segment_index: usize,
    pub offset: usize,
}

#[derive(Eq, Hash, PartialEq, Clone, Debug)]
pub enum MaybeRelocatable {
    RelocatableValue(Relocatable),
    Int(BigInt),
}

impl From<(usize, usize)> for Relocatable {
    fn from(index_offset: (usize, usize)) -> Self {
        Relocatable {
            segment_index: index_offset.0,
            offset: index_offset.1,
        }
    }
}

impl From<(usize, usize)> for MaybeRelocatable {
    fn from(index_offset: (usize, usize)) -> Self {
        MaybeRelocatable::RelocatableValue(Relocatable::from(index_offset))
    }
}

impl From<BigInt> for MaybeRelocatable {
    fn from(num: BigInt) -> Self {
        MaybeRelocatable::Int(num)
    }
}

impl MaybeRelocatable {
    ///Adds a bigint to self, then performs mod prime
    pub fn add_int_mod(&self, other: BigInt, prime: BigInt) -> MaybeRelocatable {
        match *self {
            MaybeRelocatable::Int(ref value) => {
                let mut num = Clone::clone(value);
                num = (other + num) % prime;
                MaybeRelocatable::Int(num)
            }
            MaybeRelocatable::RelocatableValue(ref rel) => {
                let mut new_offset = rel.offset.clone() + other;
                new_offset %= prime;
                MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: rel.segment_index.clone(),
                    //TODO: check this unwrap
                    offset: new_offset.to_usize().unwrap(),
                })
            }
        }
    }
    ///Adds a usize to self, then performs mod prime if prime is given
    pub fn add_usize_mod(&self, other: usize, prime: Option<BigInt>) -> MaybeRelocatable {
        match *self {
            MaybeRelocatable::Int(ref value) => {
                let mut num = Clone::clone(value);
                num = other + num;
                if let Some(num_prime) = prime {
                    num %= num_prime;
                }
                MaybeRelocatable::Int(num)
            }
            MaybeRelocatable::RelocatableValue(ref rel) => {
                let new_offset = rel.offset.clone() + other;
                MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: rel.segment_index.clone(),
                    offset: new_offset,
                })
            }
        }
    }

    ///Adds a MaybeRelocatable to self, then performs mod prime
    /// Cant add two relocatable values
    pub fn add_mod(
        &self,
        other: MaybeRelocatable,
        prime: BigInt,
    ) -> Result<MaybeRelocatable, VirtualMachineError> {
        match (self, other) {
            (&MaybeRelocatable::Int(ref num_a_ref), MaybeRelocatable::Int(num_b)) => {
                let num_a = Clone::clone(num_a_ref);
                return Ok(MaybeRelocatable::Int((num_a + num_b) % prime));
            }
            (&MaybeRelocatable::RelocatableValue(_), MaybeRelocatable::RelocatableValue(_)) => {
                Err(VirtualMachineError::RelocatableAdd)
            }
            (&MaybeRelocatable::RelocatableValue(ref rel), MaybeRelocatable::Int(num)) => {
                let new_offset: BigInt = num + rel.offset % prime;
                return Ok(MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: rel.segment_index.clone(),
                    //TODO check this unwrap
                    offset: new_offset.to_usize().unwrap(),
                }));
            }
            (&MaybeRelocatable::Int(ref num_ref), MaybeRelocatable::RelocatableValue(rel)) => {
                let new_offset: BigInt = num_ref.clone() + rel.offset % prime;
                return Ok(MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: rel.segment_index,
                    //TODO check this unwrap
                    offset: new_offset.to_usize().unwrap(),
                }));
            }
        }
    }
    ///Substracts two MaybeRelocatable values and returns the result as a MaybeRelocatable value.
    /// Only values of the same type may be substracted.
    /// Relocatable values can only be substracted if they belong to the same segment.
    pub fn sub(&self, other: &MaybeRelocatable) -> Result<MaybeRelocatable, VirtualMachineError> {
        match (self, other) {
            (&MaybeRelocatable::Int(ref num_a_ref), &MaybeRelocatable::Int(ref num_b_ref)) => {
                let num_a = Clone::clone(num_a_ref);
                let num_b = Clone::clone(num_b_ref);
                Ok(MaybeRelocatable::Int(num_a - num_b))
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
                Err(VirtualMachineError::DiffIndexSub)
            }
            _ => Err(VirtualMachineError::NotImplemented),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint;
    use crate::relocatable;
    use crate::vm::vm_core::VirtualMachineError;
    use num_bigint::BigInt;
    use num_bigint::Sign;
    use num_traits::FromPrimitive;

    #[test]
    fn add_bigint_to_int() {
        let addr = MaybeRelocatable::Int(BigInt::from_i32(7).unwrap());
        let added_addr = addr.add_int_mod(BigInt::from_i32(2).unwrap(), bigint!(17));
        if let MaybeRelocatable::Int(num) = added_addr {
            assert_eq!(num, BigInt::from_i32(9).unwrap());
        } else {
            assert!(false);
        }
    }

    fn add_usize_to_int() {
        let addr = MaybeRelocatable::Int(BigInt::from_i32(7).unwrap());
        let added_addr = addr.add_usize_mod(2, Some(bigint!(17)));
        if let MaybeRelocatable::Int(num) = added_addr {
            assert_eq!(num, BigInt::from_i32(9).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn add_bigint_to_relocatable() {
        let addr = MaybeRelocatable::RelocatableValue(relocatable!(7, 65));
        let added_addr = addr.add_int_mod(BigInt::from_i32(2).unwrap(), bigint!(17));
        if let MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index,
            offset,
        }) = added_addr
        {
            assert_eq!(offset, 67);
            assert_eq!(segment_index, 7);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn add_usize_to_relocatable() {
        let addr = MaybeRelocatable::RelocatableValue(relocatable!(7, 65));
        let added_addr = addr.add_int_mod(BigInt::from_i32(2).unwrap(), bigint!(17));
        if let MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index,
            offset,
        }) = added_addr
        {
            assert_eq!(offset, 67);
            assert_eq!(segment_index, 7);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn add_bigint_to_int_prime_mod() {
        let addr = MaybeRelocatable::Int(BigInt::new(
            Sign::Plus,
            vec![
                43680, 0, 0, 0, 0, 0, 0, 2013265920, 4294967289, 4294967295, 4294967295,
                4294967295, 4294967295, 4294967295, 4294967295, 1048575,
            ],
        ));
        let added_addr = addr.add_int_mod(
            BigInt::from_i32(1).unwrap(),
            BigInt::new(
                Sign::Plus,
                vec![
                    4294967089, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295,
                    4294967295, 67108863,
                ],
            ),
        );
        if let MaybeRelocatable::Int(num) = added_addr {
            assert_eq!(num, BigInt::from_i32(4).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn add_bigint_to_relocatable_prime() {
        let addr = MaybeRelocatable::RelocatableValue(relocatable!(1, 9));
        let added_addr = addr.add_int_mod(
            BigInt::new(
                Sign::Plus,
                vec![
                    4294967089, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295,
                    4294967295, 67108863,
                ],
            ),
            BigInt::new(
                Sign::Plus,
                vec![
                    4294967089, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295,
                    4294967295, 67108863,
                ],
            ),
        );
        assert_eq!(
            MaybeRelocatable::RelocatableValue(relocatable!(1, 9)),
            added_addr
        );
    }

    #[test]
    fn add_int_to_int() {
        let addr_a = &MaybeRelocatable::Int(BigInt::from_i32(7).unwrap());
        let addr_b = MaybeRelocatable::Int(BigInt::from_i32(17).unwrap());
        let added_addr = addr_a.add_mod(addr_b, bigint!(17));
        assert_eq!(Ok(MaybeRelocatable::Int(bigint!(24))), added_addr);
    }

    #[test]
    fn add_int_to_int_prime() {
        let addr_a = &MaybeRelocatable::Int(BigInt::new(
            Sign::Plus,
            vec![
                43680, 0, 0, 0, 0, 0, 0, 2013265920, 4294967289, 4294967295, 4294967295,
                4294967295, 4294967295, 4294967295, 4294967295, 1048575,
            ],
        ));
        let addr_b = MaybeRelocatable::Int(BigInt::from_i32(17).unwrap());
        let added_addr = addr_a.add_mod(
            addr_b,
            BigInt::new(
                Sign::Plus,
                vec![
                    4294967089, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295,
                    4294967295, 67108863,
                ],
            ),
        );
        assert_eq!(Ok(MaybeRelocatable::Int(bigint!(20))), added_addr);
    }

    #[test]
    fn add_relocatable_to_relocatable_should_fail() {
        let addr_a = &MaybeRelocatable::RelocatableValue(relocatable!(7, 5));
        let addr_b = MaybeRelocatable::RelocatableValue(relocatable!(7, 10));
        let added_addr = addr_a.add_mod(addr_b, bigint!(17));
        assert_eq!(Err(VirtualMachineError::RelocatableAdd), added_addr);
    }

    #[test]
    fn add_int_to_relocatable() {
        let addr_a = &MaybeRelocatable::RelocatableValue(relocatable!(7, 7));
        let addr_b = MaybeRelocatable::Int(BigInt::from_i32(10).unwrap());
        let added_addr = addr_a.add_mod(addr_b, bigint!(17));
        assert_eq!(
            Ok(MaybeRelocatable::RelocatableValue(relocatable!(17, 7))),
            added_addr
        );
    }

    #[test]
    fn add_relocatable_to_int() {
        let addr_a = &MaybeRelocatable::Int(BigInt::from_i32(10).unwrap());
        let addr_b = MaybeRelocatable::RelocatableValue(relocatable!(7, 7));
        let added_addr = addr_a.add_mod(addr_b, bigint!(21));
        assert_eq!(
            Ok(MaybeRelocatable::RelocatableValue(relocatable!(17, 7))),
            added_addr
        );
    }

    #[test]
    fn add_int_to_relocatable_prime() {
        let addr_a = &MaybeRelocatable::RelocatableValue(relocatable!(7, 14));
        let addr_b = MaybeRelocatable::Int(BigInt::new(
            Sign::Plus,
            vec![
                4294967089, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295,
                67108863,
            ],
        ));
        let added_addr = addr_a.add_mod(
            addr_b,
            BigInt::new(
                Sign::Plus,
                vec![
                    4294967089, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295,
                    4294967295, 67108863,
                ],
            ),
        );
        assert_eq!(
            Ok(MaybeRelocatable::RelocatableValue(relocatable!(7, 14))),
            added_addr
        );
    }

    #[test]
    fn sub_int_from_int() {
        let addr_a = &MaybeRelocatable::Int(BigInt::from_i32(7).unwrap());
        let addr_b = &MaybeRelocatable::Int(BigInt::from_i32(5).unwrap());
        let sub_addr = addr_a.sub(addr_b);
        assert_eq!(Ok(MaybeRelocatable::Int(bigint!(2))), sub_addr);
    }

    #[test]
    fn sub_relocatable_from_relocatable__same_offset() {
        let addr_a = &MaybeRelocatable::RelocatableValue(relocatable!(7, 17));
        let addr_b = &MaybeRelocatable::RelocatableValue(relocatable!(7, 7));
        let sub_addr = addr_a.sub(addr_b);
        assert_eq!(
            Ok(MaybeRelocatable::RelocatableValue(relocatable!(10, 7))),
            sub_addr
        );
    }

    #[test]
    fn sub_relocatable_from_relocatable_diff_offset() {
        let addr_a = &MaybeRelocatable::RelocatableValue(relocatable!(7, 17));
        let addr_b = &MaybeRelocatable::RelocatableValue(relocatable!(8, 7));
        let sub_addr = addr_a.sub(addr_b);
        assert_eq!(Err(VirtualMachineError::DiffIndexSub), sub_addr);
    }

    #[test]
    fn sub_int_addr_ref_from_relocatable_addr_ref() {
        let addr_a = &MaybeRelocatable::RelocatableValue(relocatable!(7, 17));
        let addr_b = &MaybeRelocatable::Int(BigInt::from_i32(5).unwrap());
        let sub_addr = addr_a.sub(addr_b);
        assert_eq!(Err(VirtualMachineError::NotImplemented), sub_addr);
    }
}
