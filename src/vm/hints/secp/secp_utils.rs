use crate::bigint;
use crate::bigint_str;
use crate::math_utils::as_int;
use crate::serde::deserialize_program::ApTracking;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::execute_hint::HintReference;
use crate::vm::hints::hint_utils::get_relocatable_from_var_name;
use crate::vm::vm_core::VMProxy;
use lazy_static::lazy_static;
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use std::collections::HashMap;

lazy_static! {
    pub static ref BASE_86: BigInt = bigint!(1) << 86_usize;
    pub static ref BASE_86_MAX: BigInt = &*BASE_86 - bigint!(1);
    pub static ref SECP_P: BigInt = (bigint!(1) << (256))
        - (1_i64 << 32)
        - (1 << 9)
        - (1 << 8)
        - (1 << 7)
        - (1 << 6)
        - (1 << 4)
        - 1;
    pub static ref N: BigInt = bigint_str!(
        b"115792089237316195423570985008687907852837564279074904382605163141518161494337"
    );
    pub static ref BETA: BigInt = bigint!(7);
}
/*
Takes a 256-bit integer and returns its canonical representation as:
d0 + BASE * d1 + BASE**2 * d2,
where BASE = 2**86.
*/
pub fn split(integer: &BigInt) -> Result<[BigInt; 3], VirtualMachineError> {
    if integer.is_negative() {
        return Err(VirtualMachineError::SecpSplitNegative(integer.clone()));
    }

    let mut num = integer.clone();
    let mut canonical_repr: [BigInt; 3] = Default::default();
    for item in &mut canonical_repr {
        *item = (&num & &*BASE_86_MAX).to_owned();
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

pub fn pack_from_var_name(
    name: &str,
    vm_proxy: &VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<BigInt, VirtualMachineError> {
    let to_pack = get_relocatable_from_var_name(name, &vm_proxy, ids_data, ap_tracking)?;

    let d0 = vm_proxy.memory.get_integer(&to_pack)?;
    let d1 = vm_proxy.memory.get_integer(&(&to_pack + 1))?;
    let d2 = vm_proxy.memory.get_integer(&(&to_pack + 2))?;

    Ok(pack(d0, d1, d2, vm_proxy.prime))
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
