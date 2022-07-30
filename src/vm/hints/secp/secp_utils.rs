use crate::bigint;
use crate::math_utils::as_int;
use crate::vm::errors::vm_errors::VirtualMachineError;
use num_bigint::BigInt;
use num_traits::{FromPrimitive, Signed, Zero};

/*
Takes a 256-bit integer and returns its canonical representation as:
d0 + BASE * d1 + BASE**2 * d2,
where BASE = 2**86.
*/
pub fn split(integer: &BigInt) -> Result<[BigInt; 3], VirtualMachineError> {
    if integer.is_negative() {
        return Err(VirtualMachineError::SecpSplitNegative(integer.clone()));
    }
    let base = bigint!(1) << 86_usize;
    let base_max = base - bigint!(1);
    let mut num = integer.clone();
    let mut canonical_repr: [BigInt; 3] = Default::default();
    for item in &mut canonical_repr {
        *item = (&num & &base_max).to_owned();
        num >>= 86_usize;
    }
    if !num.is_zero() {
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

    unreduced_big_int_3
        .iter()
        .enumerate()
        .map(|(idx, value)| as_int(value, prime) << (idx * 86))
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

        assert_eq!(array_1, Ok([bigint!(0), bigint!(0), bigint!(0)]));
        assert_eq!(array_2, Ok([bigint!(999992), bigint!(0), bigint!(0)]));
        assert_eq!(
            array_3,
            Ok([
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

    #[test]
    fn secp_pack() {
        let pack_1 = pack(&bigint!(10), &bigint!(10), &bigint!(10), &bigint!(160));
        assert_eq!(
            pack_1,
            bigint_str!(b"59863107065073783529622931521771477038469668772249610")
        );

        let pack_2 = pack(
            &bigint_str!(b"773712524553362"),
            &bigint_str!(b"57408430697461422066401280"),
            &bigint_str!(b"1292469707114105"),
            &bigint_str!(b"1292469707114105"),
        );
        assert_eq!(
            pack_2,
            bigint_str!(b"4441762184457963985490320281689802156301430343378457")
        );
    }
}
