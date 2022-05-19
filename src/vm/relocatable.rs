use crate::vm::vm_core::VirtualMachineError;
use num_bigint::BigInt;
use std::ops::Add;
use std::ops::Rem;
use std::ops::Sub;

#[derive(Eq, Hash, PartialEq, Clone, Debug)]
pub struct Relocatable {
    pub segment_index: BigInt,
    pub offset: BigInt,
}

#[derive(Eq, Hash, PartialEq, Clone, Debug)]
pub enum MaybeRelocatable {
    RelocatableValue(Relocatable),
    Int(BigInt),
}

impl Add<BigInt> for MaybeRelocatable {
    type Output = MaybeRelocatable;
    fn add(self, other: BigInt) -> MaybeRelocatable {
        match self {
            MaybeRelocatable::Int(num) => MaybeRelocatable::Int(num + other),
            MaybeRelocatable::RelocatableValue(Relocatable {
                segment_index,
                offset,
            }) => MaybeRelocatable::RelocatableValue(Relocatable {
                segment_index,
                offset: offset + other,
            }),
        }
    }
}

impl Add<MaybeRelocatable> for MaybeRelocatable {
    type Output = Result<MaybeRelocatable, VirtualMachineError>;
    fn add(self, other: MaybeRelocatable) -> Result<MaybeRelocatable, VirtualMachineError> {
        match (self, other) {
            (MaybeRelocatable::Int(num_a), MaybeRelocatable::Int(num_b)) => {
                Ok(MaybeRelocatable::Int(num_a + num_b))
            }
            (MaybeRelocatable::RelocatableValue(_), MaybeRelocatable::RelocatableValue(_)) => {
                Err(VirtualMachineError::RelocatableAddError)
            }
            (
                MaybeRelocatable::Int(num),
                MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index,
                    offset,
                }),
            ) => Ok(MaybeRelocatable::RelocatableValue(Relocatable {
                segment_index,
                offset: offset + num,
            })),
            (
                MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index,
                    offset,
                }),
                MaybeRelocatable::Int(num),
            ) => Ok(MaybeRelocatable::RelocatableValue(Relocatable {
                segment_index,
                offset: offset + num,
            })),
        }
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
                Err(VirtualMachineError::DiffIndexSubError)
            }
            _ => Err(VirtualMachineError::NotImplementedError),
        }
    }
}

impl MaybeRelocatable {
    ///Adds a number to the address, then performs mod prime if prime is given
    pub fn add_num_addr(&self, other: BigInt, prime: Option<BigInt>) -> MaybeRelocatable {
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
                let mut new_offset = rel.offset.clone() + other;
                if let Some(num_prime) = prime {
                    new_offset %= num_prime;
                }
                MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: rel.segment_index.clone(),
                    offset: new_offset,
                })
            }
        }
    }

    ///Adds a number to the address, then performs mod prime if prime is given
    /// Cant add two relocatable values
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
                Ok(MaybeRelocatable::Int(num_a + num_b))
            }
            (&MaybeRelocatable::RelocatableValue(_), MaybeRelocatable::RelocatableValue(_)) => {
                Err(VirtualMachineError::RelocatableAddError)
            }
            (&MaybeRelocatable::RelocatableValue(ref rel), MaybeRelocatable::Int(num)) => {
                if let Some(num_prime) = prime {
                    return Ok(MaybeRelocatable::RelocatableValue(Relocatable {
                        segment_index: rel.segment_index.clone(),
                        offset: (rel.offset.clone() + num) % num_prime,
                    }));
                }
                Ok(MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: rel.segment_index.clone(),
                    offset: rel.offset.clone() + num,
                }))
            }
            (&MaybeRelocatable::Int(ref num_ref), MaybeRelocatable::RelocatableValue(rel)) => {
                if let Some(num_prime) = prime {
                    return Ok(MaybeRelocatable::RelocatableValue(Relocatable {
                        segment_index: rel.segment_index,
                        offset: (rel.offset + num_ref.clone()) % num_prime,
                    }));
                }
                Ok(MaybeRelocatable::RelocatableValue(Relocatable {
                    segment_index: rel.segment_index,
                    offset: rel.offset + num_ref.clone(),
                }))
            }
        }
    }
    ///Substracts two MaybeRelocatable values and returns the result as a MaybeRelocatable value.
    /// Only values of the same type may be substracted.
    /// Relocatable values can only be substracted if they belong to the same segment.
    pub fn sub_addr(
        &self,
        other: &MaybeRelocatable,
    ) -> Result<MaybeRelocatable, VirtualMachineError> {
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
                        segment_index: rel_a.segment_index.clone(),
                        offset: rel_a.offset.clone() - rel_b.offset.clone(),
                    }));
                }
                Err(VirtualMachineError::DiffIndexSubError)
            }
            _ => Err(VirtualMachineError::NotImplementedError),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::vm_core::VirtualMachineError;
    use num_bigint::BigInt;
    use num_bigint::Sign;
    use num_traits::FromPrimitive;

    ///Tests for MaybeRelocatable functions

    #[test]
    fn add_num_to_int_addr() {
        let addr = MaybeRelocatable::Int(BigInt::from_i32(7).unwrap());
        let added_addr = addr + (BigInt::from_i32(2).unwrap());
        if let MaybeRelocatable::Int(num) = added_addr {
            assert_eq!(num, BigInt::from_i32(9).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn add_num_to_relocatable_addr() {
        let addr = MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(7).unwrap(),
            offset: BigInt::from_i32(65).unwrap(),
        });
        let added_addr = addr + BigInt::from_i32(2).unwrap();
        if let MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index,
            offset,
        }) = added_addr
        {
            assert_eq!(offset, BigInt::from_i32(67).unwrap());
            assert_eq!(segment_index, BigInt::from_i32(7).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn add_int_addr_to_int_addr() {
        let addr_a = MaybeRelocatable::Int(BigInt::from_i32(7).unwrap());
        let addr_b = MaybeRelocatable::Int(BigInt::from_i32(17).unwrap());
        let added_addr = addr_a + addr_b;
        if let Ok(MaybeRelocatable::Int(num)) = added_addr {
            assert_eq!(num, BigInt::from_i32(24).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn add_relocatable_addr_to_relocatable_addr_should_fail() {
        let addr_a = MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(7).unwrap(),
            offset: BigInt::from_i32(5).unwrap(),
        });
        let addr_b = MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(7).unwrap(),
            offset: BigInt::from_i32(10).unwrap(),
        });
        let added_addr = addr_a + addr_b;
        match added_addr {
            Err(error) => assert_eq!(error, VirtualMachineError::RelocatableAddError),
            Ok(_value) => assert!(false),
        }
    }

    #[test]
    fn add_int_addr_to_relocatable_addr() {
        let addr_a = MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(7).unwrap(),
            offset: BigInt::from_i32(7).unwrap(),
        });
        let addr_b = MaybeRelocatable::Int(BigInt::from_i32(10).unwrap());
        let added_addr = addr_a + addr_b;
        if let Ok(MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index,
            offset,
        })) = added_addr
        {
            assert_eq!(offset, BigInt::from_i32(17).unwrap());
            assert_eq!(segment_index, BigInt::from_i32(7).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn add_relocatable_addr_to_int_addr() {
        let addr_a = MaybeRelocatable::Int(BigInt::from_i32(10).unwrap());
        let addr_b = MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(7).unwrap(),
            offset: BigInt::from_i32(7).unwrap(),
        });
        let added_addr = addr_a + addr_b;
        if let Ok(MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index,
            offset,
        })) = added_addr
        {
            assert_eq!(offset, BigInt::from_i32(17).unwrap());
            assert_eq!(segment_index, BigInt::from_i32(7).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn int_addr_rem() {
        let addr = MaybeRelocatable::Int(BigInt::new(
            Sign::Plus,
            vec![
                43680, 0, 0, 0, 0, 0, 0, 2013265920, 4294967289, 4294967295, 4294967295,
                4294967295, 4294967295, 4294967295, 4294967295, 1048575,
            ],
        ));
        let rem_addr = addr
            % BigInt::new(
                Sign::Plus,
                vec![
                    4294967089, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295,
                    4294967295, 67108863,
                ],
            );
        if let MaybeRelocatable::Int(num) = rem_addr {
            assert_eq!(num, BigInt::from_i32(3).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn relocatable_addr_rem() {
        let addr = MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(3).unwrap(),
            offset: (BigInt::new(
                Sign::Plus,
                vec![
                    43680, 0, 0, 0, 0, 0, 0, 2013265920, 4294967289, 4294967295, 4294967295,
                    4294967295, 4294967295, 4294967295, 4294967295, 1048575,
                ],
            )),
        });
        let rem_addr = addr
            % BigInt::new(
                Sign::Plus,
                vec![
                    4294967089, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295,
                    4294967295, 67108863,
                ],
            );
        if let MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index,
            offset,
        }) = rem_addr
        {
            assert_eq!(offset, BigInt::from_i32(3).unwrap());
            assert_eq!(segment_index, BigInt::from_i32(3).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn sub_int_addr_from_int_addr() {
        let addr_a = MaybeRelocatable::Int(BigInt::from_i32(7).unwrap());
        let addr_b = MaybeRelocatable::Int(BigInt::from_i32(5).unwrap());
        let sub_addr = addr_a - addr_b;
        if let Ok(MaybeRelocatable::Int(num)) = sub_addr {
            assert_eq!(num, BigInt::from_i32(2).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn sub_relocatable_addr_from_relocatable_addr_same_offset() {
        let addr_a = MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(7).unwrap(),
            offset: BigInt::from_i32(17).unwrap(),
        });
        let addr_b = MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(7).unwrap(),
            offset: BigInt::from_i32(7).unwrap(),
        });
        let sub_addr = addr_a - addr_b;
        if let Ok(MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index,
            offset,
        })) = sub_addr
        {
            assert_eq!(offset, BigInt::from_i32(10).unwrap());
            assert_eq!(segment_index, BigInt::from_i32(7).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn sub_relocatable_addr_from_relocatable_addr_diff_offset() {
        let addr_a = MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(7).unwrap(),
            offset: BigInt::from_i32(17).unwrap(),
        });
        let addr_b = MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(8).unwrap(),
            offset: BigInt::from_i32(7).unwrap(),
        });
        let sub_addr = addr_a - addr_b;
        match sub_addr {
            Err(error) => assert_eq!(error, VirtualMachineError::DiffIndexSubError),
            Ok(_) => assert!(false),
        }
    }

    #[test]
    fn sub_int_addr_from_relocatable_addr() {
        let addr_a = MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(7).unwrap(),
            offset: BigInt::from_i32(17).unwrap(),
        });
        let addr_b = MaybeRelocatable::Int(BigInt::from_i32(5).unwrap());
        let sub_addr = addr_a - addr_b;
        match sub_addr {
            Err(error) => assert_eq!(error, VirtualMachineError::NotImplementedError),
            Ok(_) => assert!(false),
        }
    }

    ///Tests for &MaybeRelocatable

    #[test]
    fn add_num_to_int_addr_ref() {
        let addr = MaybeRelocatable::Int(BigInt::from_i32(7).unwrap());
        let added_addr = addr.add_num_addr(BigInt::from_i32(2).unwrap(), None);
        if let MaybeRelocatable::Int(num) = added_addr {
            assert_eq!(num, BigInt::from_i32(9).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn add_num_to_relocatable_addr_ref() {
        let addr = MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(7).unwrap(),
            offset: BigInt::from_i32(65).unwrap(),
        });
        let added_addr = addr.add_num_addr(BigInt::from_i32(2).unwrap(), None);
        if let MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index,
            offset,
        }) = added_addr
        {
            assert_eq!(offset, BigInt::from_i32(67).unwrap());
            assert_eq!(segment_index, BigInt::from_i32(7).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn add_num_to_int_addr_ref_with_prime() {
        let addr = MaybeRelocatable::Int(BigInt::new(
            Sign::Plus,
            vec![
                43680, 0, 0, 0, 0, 0, 0, 2013265920, 4294967289, 4294967295, 4294967295,
                4294967295, 4294967295, 4294967295, 4294967295, 1048575,
            ],
        ));
        let added_addr = addr.add_num_addr(
            BigInt::from_i32(1).unwrap(),
            Some(BigInt::new(
                Sign::Plus,
                vec![
                    4294967089, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295,
                    4294967295, 67108863,
                ],
            )),
        );
        if let MaybeRelocatable::Int(num) = added_addr {
            assert_eq!(num, BigInt::from_i32(4).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn add_num_to_relocatable_addr_ref_with_prime() {
        let addr = MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(7).unwrap(),
            offset: BigInt::new(
                Sign::Plus,
                vec![
                    43680, 0, 0, 0, 0, 0, 0, 2013265920, 4294967289, 4294967295, 4294967295,
                    4294967295, 4294967295, 4294967295, 4294967295, 1048575,
                ],
            ),
        });
        let added_addr = addr.add_num_addr(
            BigInt::from_i32(2).unwrap(),
            Some(BigInt::new(
                Sign::Plus,
                vec![
                    4294967089, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295,
                    4294967295, 67108863,
                ],
            )),
        );
        if let MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index,
            offset,
        }) = added_addr
        {
            assert_eq!(offset, BigInt::from_i32(5).unwrap());
            assert_eq!(segment_index, BigInt::from_i32(7).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn add_int_addr_to_int_addr_ref() {
        let addr_a = &MaybeRelocatable::Int(BigInt::from_i32(7).unwrap());
        let addr_b = MaybeRelocatable::Int(BigInt::from_i32(17).unwrap());
        let added_addr = addr_a.add_addr(addr_b, None);
        if let Ok(MaybeRelocatable::Int(num)) = added_addr {
            assert_eq!(num, BigInt::from_i32(24).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn add_int_addr_to_int_addr_ref_with_prime() {
        let addr_a = &MaybeRelocatable::Int(BigInt::new(
            Sign::Plus,
            vec![
                43680, 0, 0, 0, 0, 0, 0, 2013265920, 4294967289, 4294967295, 4294967295,
                4294967295, 4294967295, 4294967295, 4294967295, 1048575,
            ],
        ));
        let addr_b = MaybeRelocatable::Int(BigInt::from_i32(17).unwrap());
        let added_addr = addr_a.add_addr(
            addr_b,
            Some(BigInt::new(
                Sign::Plus,
                vec![
                    4294967089, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295,
                    4294967295, 67108863,
                ],
            )),
        );
        if let Ok(MaybeRelocatable::Int(num)) = added_addr {
            assert_eq!(num, BigInt::from_i32(20).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn add_relocatable_addr_to_relocatable_addr_ref_should_fail() {
        let addr_a = &MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(7).unwrap(),
            offset: BigInt::from_i32(5).unwrap(),
        });
        let addr_b = MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(7).unwrap(),
            offset: BigInt::from_i32(10).unwrap(),
        });
        let added_addr = addr_a.add_addr(addr_b, None);
        match added_addr {
            Err(error) => assert_eq!(error, VirtualMachineError::RelocatableAddError),
            Ok(_value) => assert!(false),
        }
    }

    #[test]
    fn add_int_addr_to_relocatable_addr_ref() {
        let addr_a = &MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(7).unwrap(),
            offset: BigInt::from_i32(7).unwrap(),
        });
        let addr_b = MaybeRelocatable::Int(BigInt::from_i32(10).unwrap());
        let added_addr = addr_a.add_addr(addr_b, None);
        if let Ok(MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index,
            offset,
        })) = added_addr
        {
            assert_eq!(offset, BigInt::from_i32(17).unwrap());
            assert_eq!(segment_index, BigInt::from_i32(7).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn add_relocatable_addr_to_int_addr_ref() {
        let addr_a = &MaybeRelocatable::Int(BigInt::from_i32(10).unwrap());
        let addr_b = MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(7).unwrap(),
            offset: BigInt::from_i32(7).unwrap(),
        });
        let added_addr = addr_a.add_addr(addr_b, None);
        if let Ok(MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index,
            offset,
        })) = added_addr
        {
            assert_eq!(offset, BigInt::from_i32(17).unwrap());
            assert_eq!(segment_index, BigInt::from_i32(7).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn add_int_addr_to_relocatable_addr_ref_with_prime() {
        let addr_a = &MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(7).unwrap(),
            offset: BigInt::new(
                Sign::Plus,
                vec![
                    43680, 0, 0, 0, 0, 0, 0, 2013265920, 4294967289, 4294967295, 4294967295,
                    4294967295, 4294967295, 4294967295, 4294967295, 1048575,
                ],
            ),
        });
        let addr_b = MaybeRelocatable::Int(BigInt::from_i32(10).unwrap());
        let added_addr = addr_a.add_addr(
            addr_b,
            Some(BigInt::new(
                Sign::Plus,
                vec![
                    4294967089, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295,
                    4294967295, 67108863,
                ],
            )),
        );
        if let Ok(MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index,
            offset,
        })) = added_addr
        {
            assert_eq!(offset, BigInt::from_i32(13).unwrap());
            assert_eq!(segment_index, BigInt::from_i32(7).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn sub_int_addr_ref_from_int_addr_ref() {
        let addr_a = &MaybeRelocatable::Int(BigInt::from_i32(7).unwrap());
        let addr_b = &MaybeRelocatable::Int(BigInt::from_i32(5).unwrap());
        let sub_addr = addr_a.sub_addr(addr_b);
        if let Ok(MaybeRelocatable::Int(num)) = sub_addr {
            assert_eq!(num, BigInt::from_i32(2).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn sub_relocatable_addr_ref_from_relocatable_addr_ref_same_offset() {
        let addr_a = &MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(7).unwrap(),
            offset: BigInt::from_i32(17).unwrap(),
        });
        let addr_b = &MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(7).unwrap(),
            offset: BigInt::from_i32(7).unwrap(),
        });
        let sub_addr = addr_a.sub_addr(addr_b);
        if let Ok(MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index,
            offset,
        })) = sub_addr
        {
            assert_eq!(offset, BigInt::from_i32(10).unwrap());
            assert_eq!(segment_index, BigInt::from_i32(7).unwrap());
        } else {
            assert!(false);
        }
    }

    #[test]
    fn sub_relocatable_addr_ref_from_relocatable_addr_refdiff_offset() {
        let addr_a = &MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(7).unwrap(),
            offset: BigInt::from_i32(17).unwrap(),
        });
        let addr_b = &MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(8).unwrap(),
            offset: BigInt::from_i32(7).unwrap(),
        });
        let sub_addr = addr_a.sub_addr(addr_b);
        match sub_addr {
            Err(error) => assert_eq!(error, VirtualMachineError::DiffIndexSubError),
            Ok(_) => assert!(false),
        }
    }

    #[test]
    fn sub_int_addr_ref_from_relocatable_addr_ref() {
        let addr_a = &MaybeRelocatable::RelocatableValue(Relocatable {
            segment_index: BigInt::from_i32(7).unwrap(),
            offset: BigInt::from_i32(17).unwrap(),
        });
        let addr_b = &MaybeRelocatable::Int(BigInt::from_i32(5).unwrap());
        let sub_addr = addr_a.sub_addr(addr_b);
        match sub_addr {
            Err(error) => assert_eq!(error, VirtualMachineError::NotImplementedError),
            Ok(_) => assert!(false),
        }
    }
}
