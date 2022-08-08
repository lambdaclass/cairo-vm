use crate::types::relocatable::Relocatable;
use num_bigint::BigInt;

#[macro_export]
macro_rules! bigint {
    ($val : expr) => {
        Into::<BigInt>::into($val)
    };
}

#[macro_export]
macro_rules! bigint_str {
    ($val: expr) => {
        BigInt::parse_bytes($val, 10).unwrap()
    };
    ($val: expr, $opt: expr) => {
        BigInt::parse_bytes($val, $opt).unwrap()
    };
}

#[macro_export]
macro_rules! relocatable {
    ($val1 : expr, $val2 : expr) => {
        Relocatable {
            segment_index: ($val1),
            offset: ($val2),
        }
    };
}

pub fn is_subsequence<T: PartialEq>(subsequence: &[T], mut sequence: &[T]) -> bool {
    for search in subsequence {
        if let Some(index) = sequence.iter().position(|element| search == element) {
            sequence = &sequence[index + 1..];
        } else {
            return false;
        }
    }
    true
}

pub fn from_relocatable_to_indexes(relocatable: Relocatable) -> (usize, usize) {
    (relocatable.segment_index, relocatable.offset)
}

///Converts val to an integer in the range (-prime/2, prime/2) which is
///equivalent to val modulo prime.
pub fn to_field_element(num: BigInt, prime: BigInt) -> BigInt {
    let half_prime = prime.clone() / bigint!(2);
    ((num + half_prime.clone()) % prime) - half_prime
}

#[cfg(test)]
#[macro_use]
pub mod test_utils {
    use lazy_static::lazy_static;
    use num_bigint::BigInt;

    lazy_static! {
        pub static ref VM_PRIME: BigInt = BigInt::parse_bytes(
            b"3618502788666131213697322783095070105623107215331596699973092056135872020481",
            10,
        )
        .unwrap();
    }
    macro_rules! memory {
        ( $( (($si:expr, $off:expr), $val:tt) ),* ) => {
        {
            let mut memory = Memory::new();
            memory_from_memory!(memory, ( $( (($si, $off), $val) ),* ));
        memory
        }
        };
    }
    pub(crate) use memory;

    macro_rules! memory_from_memory {
        ($mem: expr, ( $( (($si:expr, $off:expr), $val:tt) ),* )) => {
            {
                $(
                    memory_inner!($mem, ($si, $off), $val);
                )*
            }
        };
    }
    pub(crate) use memory_from_memory;

    macro_rules! memory_inner {
        ($mem:expr, ($si:expr, $off:expr), ($sival:expr, $offval: expr)) => {
            let (k, v) = (
                &mayberelocatable!($si, $off),
                &mayberelocatable!($sival, $offval),
            );
            let mut res = $mem.insert(k, v);
            while matches!(res, Err(MemoryError::UnallocatedSegment(_, _))) {
                $mem.data.push(Vec::new());
                res = $mem.insert(k, v);
            }
        };
        ($mem:expr, ($si:expr, $off:expr), $val:expr) => {
            let (k, v) = (&mayberelocatable!($si, $off), &mayberelocatable!($val));
            let mut res = $mem.insert(k, v);
            while matches!(res, Err(MemoryError::UnallocatedSegment(_, _))) {
                $mem.data.push(Vec::new());
                res = $mem.insert(k, v);
            }
        };
    }
    pub(crate) use memory_inner;

    macro_rules! mayberelocatable {
        ($val1 : expr, $val2 : expr) => {
            MaybeRelocatable::from(($val1, $val2))
        };
        ($val1 : expr) => {
            MaybeRelocatable::from((bigint!($val1)))
        };
    }
    pub(crate) use mayberelocatable;

    macro_rules! references {
        ($num: expr) => {{
            let mut references = HashMap::<usize, HintReference>::new();
            for i in 0..$num {
                references.insert(i, HintReference::new_simple((i as i32 - $num)));
            }
            references
        }};
    }
    pub(crate) use references;

    macro_rules! vm_with_range_check {
        () => {
            VirtualMachine::new(
                BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
                vec![(
                    "range_check".to_string(),
                    Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
                )],
                false,
                &HINT_EXECUTOR,
            )
        };
    }
    pub(crate) use vm_with_range_check;

    macro_rules! vm {
        () => {
            VirtualMachine::new(
                BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
                vec![],
                false,
                &HINT_EXECUTOR,
            )
        };
    }
    pub(crate) use vm;

    macro_rules! ids {
        ( $( $name: expr ),* ) => {
            {
                let mut ids = HashMap::<String, BigInt>::new();
                let mut num = -1;
                $(
                    num += 1;
                    ids_inner!($name, num, ids);

                )*
                ids
            }
        };
    }
    pub(crate) use ids;

    macro_rules! ids_inner {
        ( $name: expr, $num: expr, $ids: expr ) => {
            $ids.insert(String::from($name), bigint!($num))
        };
    }
    pub(crate) use ids_inner;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::{types::relocatable::MaybeRelocatable, vm::vm_memory::memory::Memory};

    #[test]
    fn to_field_element_no_change_a() {
        assert_eq!(
            to_field_element(
                bigint!(1),
                bigint_str!(
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
                )
            ),
            bigint!(1)
        );
    }

    #[test]
    fn to_field_element_no_change_b() {
        assert_eq!(
            to_field_element(
                bigint_str!(
                    b"1455766198400600346948407886553099278761386236477570128859274086228078567108"
                ),
                bigint_str!(
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
                )
            ),
            bigint_str!(
                b"1455766198400600346948407886553099278761386236477570128859274086228078567108"
            )
        );
    }

    #[test]
    fn to_field_element_num_to_negative_a() {
        assert_eq!(
            to_field_element(
                bigint_str!(
                    b"3270867057177188607814717243084834301278723532952411121381966378910183338911"
                ),
                bigint_str!(
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
                )
            ),
            bigint_str!(
                b"-347635731488942605882605540010235804344383682379185578591125677225688681570"
            )
        );
    }

    #[test]
    fn to_field_element_num_to_negative_b() {
        assert_eq!(
            to_field_element(
                bigint_str!(
                    b"3333324623402098338894983297253618187074385014448599840723759915876610845540"
                ),
                bigint_str!(
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020481"
                )
            ),
            bigint_str!(
                b"-285178165264032874802339485841451918548722200882996859249332140259261174941"
            )
        );
    }

    #[test]
    fn memory_macro_test() {
        let mut memory = Memory::new();
        for _ in 0..2 {
            memory.data.push(Vec::new());
        }
        memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        let mem = memory![((1, 2), 1), ((1, 1), (1, 0))];
        assert_eq!(memory.data, mem.data);
    }
}
