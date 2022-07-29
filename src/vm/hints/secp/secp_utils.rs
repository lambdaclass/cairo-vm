use crate::bigint;
use crate::vm::errors::vm_errors::VirtualMachineError;
use num_bigint::BigInt;
use num_traits::{FromPrimitive, Signed, Zero};

/*
Takes a 256-bit integer and returns its canonical representation as:
d0 + BASE * d1 + BASE**2 * d2,
where BASE = 2**86.
*/
pub fn split(integer: &BigInt) -> Result<Vec<BigInt>, VirtualMachineError> {
    if integer.is_negative() {
        return Err(VirtualMachineError::SecpSplitNegative(integer.clone()));
    }
    let base = bigint!(1) << 86_usize;
    let base_max = base - bigint!(1);
    let mut num = integer.clone();
    let mut canonical_repr: Vec<BigInt> = Vec::with_capacity(3);
    for _i in 0..3 {
        canonical_repr.push((&num & &base_max).to_owned());
        num >>= 86_usize;
    }
    if !num.is_zero() {
        return Err(VirtualMachineError::SecpSplitutOfRange(integer.clone()));
    }
    Ok(canonical_repr)
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
