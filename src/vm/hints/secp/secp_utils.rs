use crate::bigint;
use crate::math_utils::as_int;
use crate::vm::errors::vm_errors::VirtualMachineError;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{FromPrimitive, Signed};
use std::ops::Shl;

/*
Takes a 256-bit integer and returns its canonical representation as:
d0 + BASE * d1 + BASE**2 * d2,
where BASE = 2**86.
*/
pub fn split(integer: &BigInt) -> Result<Vec<BigInt>, VirtualMachineError> {
    if integer.is_negative() {
        return Err(VirtualMachineError::SecpSplitNegative(integer.clone()));
    }
    let base = bigint!(1).shl(86);
    let mut num = integer.clone();
    let mut remainder: BigInt;
    let mut canonical_repr = Vec::new();
    for _n in 0..3 {
        (num, remainder) = num.clone().div_rem(&base);
        canonical_repr.push(remainder);
    }
    if num != bigint!(0) {
        return Err(VirtualMachineError::SecpSplitutOfRange(integer.clone()));
    }

    Ok(canonical_repr)
}

/*
Takes an UnreducedBigInt3 struct which represents a triple of limbs (d0, d1, d2) of field
elements and reconstructs the corresponding 256-bit integer (see split()).
Note that the limbs do not have to be in the range [0, BASE).
prime should be the Cairo field, and it is used to handle negative values of the limbs.
*/
pub fn pack(d0: &BigInt, d1: &BigInt, d2: &BigInt, prime: &BigInt) -> BigInt {
    let unreduced_big_int_3 = vec![d0, d1, d2];
    let base: BigInt = bigint!(1).shl(86_usize);

    unreduced_big_int_3
        .iter()
        .enumerate()
        .map(|(idx, value)| as_int(value, prime) * base.pow(idx as u32))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint_str;

    #[test]
    fn secp_split() {
        let array_1 = split(&bigint!(0));
        let array_2 = split(&bigint!(999992));
        let array_3 = split(&bigint_str!(
            b"7737125245533626718119526477371252455336267181195264773712524553362"
        ));
        let array_4 = split(&bigint!(-1));
        //TODO, Check SecpSplitutOfRange limit
        let array_5 = split(&bigint_str!(
            b"773712524553362671811952647737125245533626718119526477371252455336267181195264"
        ));

        assert_eq!(array_1, Ok(vec![bigint!(0), bigint!(0), bigint!(0)]));
        assert_eq!(array_2, Ok(vec![bigint!(999992), bigint!(0), bigint!(0)]));
        assert_eq!(
            array_3,
            Ok(vec![
                bigint_str!(b"773712524553362"),
                bigint_str!(b"57408430697461422066401280"),
                bigint_str!(b"1292469707114105")
            ])
        );
        assert_eq!(
            array_4,
            Err(VirtualMachineError::SecpSplitNegative(bigint!(-1)))
        );
        assert_eq!(
            array_5,
            Err(VirtualMachineError::SecpSplitutOfRange(bigint_str!(
                b"773712524553362671811952647737125245533626718119526477371252455336267181195264"
            )))
        );
    }
}
