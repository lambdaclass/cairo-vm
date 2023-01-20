use crate::{
    hint_processor::{
        builtin_hint_processor::hint_utils::get_relocatable_from_var_name,
        hint_processor_definition::HintReference,
    },
    serde::deserialize_program::ApTracking,
    types::relocatable::Relocatable,
    vm::{errors::hint_errors::HintError, vm_core::VirtualMachine},
};
use big_num::BigNum;
use felt::Felt;
use num_traits::Zero;
use std::collections::HashMap;
use std::ops::Shl;

// Constants in package "starkware.cairo.common.cairo_secp.constants".
pub const BASE_86: &str = "starkware.cairo.common.cairo_secp.constants.BASE";
pub const BETA: &str = "starkware.cairo.common.cairo_secp.constants.BETA";
pub const N0: &str = "starkware.cairo.common.cairo_secp.constants.N0";
pub const N1: &str = "starkware.cairo.common.cairo_secp.constants.N1";
pub const N2: &str = "starkware.cairo.common.cairo_secp.constants.N2";
pub const P0: &str = "starkware.cairo.common.cairo_secp.constants.P0";
pub const P1: &str = "starkware.cairo.common.cairo_secp.constants.P1";
pub const P2: &str = "starkware.cairo.common.cairo_secp.constants.P2";
pub const SECP_REM: &str = "starkware.cairo.common.cairo_secp.constants.SECP_REM";

/*
Takes a 256-bit integer and returns its canonical representation as:
d0 + BASE * d1 + BASE**2 * d2,
where BASE = 2**86.
*/
pub fn split(
    integer: &BigNum,
    constants: &HashMap<String, Felt>,
) -> Result<[BigNum; 3], HintError> {
    let base_86_max: BigNum = (constants
        .get(BASE_86)
        .ok_or(HintError::MissingConstant(BASE_86))?
        - 1_u32)
        .into();

    let mut canonical_repr: [BigNum; 3] = Default::default();
    let mut num = integer.clone();
    for item in &mut canonical_repr {
        *item = &num & &base_86_max;
        num >>= 86_usize;
    }

    if !num.is_zero() {
        return Err(HintError::SecpSplitOutOfRange(integer.clone()));
    }
    Ok(canonical_repr)
}

/*
Takes an UnreducedFelt3 struct which represents a triple of limbs (d0, d1, d2) of field
elements and reconstructs the corresponding 256-bit integer (see split()).
Note that the limbs do not have to be in the range [0, BASE).
*/
pub fn pack(d0: &Felt, d1: &Felt, d2: &Felt) -> BigNum {
    let unreduced_big_int_3 = vec![d0, d1, d2];

    unreduced_big_int_3
        .into_iter()
        .enumerate()
        // to_bigint() here is used to replace as_int() functionality (changing the range from (0,P] to [-P/2, -P/2])
        .map(|(idx, value)| BigNum::from(value.to_bigint()).shl(idx * 86))
        .sum()
}

pub fn pack_from_var_name(
    name: &str,
    vm: &VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<BigNum, HintError> {
    let to_pack = get_relocatable_from_var_name(name, vm, ids_data, ap_tracking)?;

    let d0 = vm.get_integer(&to_pack)?;
    let d1 = vm.get_integer(&(&to_pack + 1_usize))?;
    let d2 = vm.get_integer(&(&to_pack + 2_usize))?;
    Ok(pack(d0.as_ref(), d1.as_ref(), d2.as_ref()))
}

pub fn pack_from_relocatable(rel: Relocatable, vm: &VirtualMachine) -> Result<BigNum, HintError> {
    let d0 = vm.get_integer(&rel)?;
    let d1 = vm.get_integer(&(&rel + 1_usize))?;
    let d2 = vm.get_integer(&(&rel + 2_usize))?;

    Ok(pack(d0.as_ref(), d1.as_ref(), d2.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use big_num::BigNumOps;
    use felt::felt_str;
    use num_traits::One;

    #[test]
    fn secp_split() {
        let mut constants = HashMap::new();
        constants.insert(BASE_86.to_string(), Felt::one() << 86_usize);

        let array_1 = split(&BigNum::zero(), &constants);
        let array_2 = split(&BigNum::from(999992), &constants);
        let array_3 = split(
            &BigNum::parse_bytes(
                b"7737125245533626718119526477371252455336267181195264773712524553362",
                10,
            )
            .expect("Couldn't convert to BigNum"),
            &constants,
        );
        //TODO, Check SecpSplitutOfRange limit
        let array_4 = split(
            &BigNum::parse_bytes(
                b"773712524553362671811952647737125245533626718119526477371252455336267181195264",
                10,
            )
            .expect("Couldn't convert to BigNum"),
            &constants,
        );

        assert_eq!(
            array_1,
            Ok([BigNum::zero(), BigNum::zero(), BigNum::zero()])
        );
        assert_eq!(
            array_2,
            Ok([BigNum::from(999992), BigNum::zero(), BigNum::zero()])
        );
        assert_eq!(
            array_3,
            Ok([
                BigNum::parse_bytes(b"773712524553362", 10).expect("Couldn't convert to BigNum"),
                BigNum::parse_bytes(b"57408430697461422066401280", 10)
                    .expect("Couldn't convert to BigNum"),
                BigNum::parse_bytes(b"1292469707114105", 10).expect("Couldn't convert to BigNum")
            ])
        );
        assert_eq!(
            array_4,
            Err(HintError::SecpSplitOutOfRange(
                BigNum::parse_bytes(b"773712524553362671811952647737125245533626718119526477371252455336267181195264", 10
            )
                .expect("Couldn't convert to BigNum")
            ))
        );
    }

    #[test]
    fn secp_pack() {
        let pack_1 = pack(&Felt::new(10_i32), &Felt::new(10_i32), &Felt::new(10_i32));
        assert_eq!(
            pack_1,
            BigNum::parse_bytes(b"59863107065073783529622931521771477038469668772249610", 10)
                .expect("BigNum parse failure")
        );

        let pack_2 = pack(
            &felt_str!("773712524553362"),
            &felt_str!("57408430697461422066401280"),
            &felt_str!("1292469707114105"),
        );
        assert_eq!(
            pack_2,
            BigNum::parse_bytes(
                b"7737125245533626718119526477371252455336267181195264773712524553362",
                10
            )
            .expect("BigNum parse failure")
        );
    }
}
