use crate::{
    hint_processor::{
        builtin_hint_processor::hint_utils::get_relocatable_from_var_name,
        hint_processor_definition::HintReference,
    },
    //    math_utils::as_int,
    serde::deserialize_program::ApTracking,
    types::relocatable::Relocatable,
    vm::{errors::vm_errors::VirtualMachineError, vm_core::VirtualMachine},
};
use felt::{Felt, FeltOps};
use num_traits::{One, Signed, Zero};
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
    integer: &num_bigint::BigInt,
    constants: &HashMap<String, Felt>,
) -> Result<[num_bigint::BigInt; 3], VirtualMachineError> {
    if integer.is_negative() {
        return Err(VirtualMachineError::SecpSplitNegative(integer.clone()));
    }

    let base_86_max = constants
        .get(BASE_86)
        .ok_or(VirtualMachineError::MissingConstant(BASE_86))?
        .to_bigint_unsigned()
        - &num_bigint::BigInt::one();

    let mut canonical_repr: [num_bigint::BigInt; 3] = Default::default();
    let mut num = integer.clone();
    for item in &mut canonical_repr {
        *item = &num & &base_86_max;
        num >>= 86_usize;
    }

    if !num.is_zero() {
        return Err(VirtualMachineError::SecpSplitutOfRange(integer.clone()));
    }
    Ok(canonical_repr)
}

/*
Takes an UnreducedFelt3 struct which represents a triple of limbs (d0, d1, d2) of field
elements and reconstructs the corresponding 256-bit integer (see split()).
Note that the limbs do not have to be in the range [0, BASE).
*/
pub fn pack(d0: &Felt, d1: &Felt, d2: &Felt) -> num_bigint::BigInt {
    let unreduced_big_int_3 = vec![d0, d1, d2];

    unreduced_big_int_3
        .into_iter()
        .enumerate()
        .map(|(idx, value)| value.to_bigint().shl(idx * 86))
        .sum()
}

pub fn pack_from_var_name(
    name: &str,
    vm: &VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<num_bigint::BigInt, VirtualMachineError> {
    let to_pack = get_relocatable_from_var_name(name, vm, ids_data, ap_tracking)?;

    let d0 = vm.get_integer(&to_pack)?;
    let d1 = vm.get_integer(&(&to_pack + 1_usize))?;
    let d2 = vm.get_integer(&(&to_pack + 2_usize))?;
    Ok(pack(d0.as_ref(), d1.as_ref(), d2.as_ref()))
}

pub fn pack_from_relocatable(
    rel: Relocatable,
    vm: &VirtualMachine,
) -> Result<num_bigint::BigInt, VirtualMachineError> {
    let d0 = vm.get_integer(&rel)?;
    let d1 = vm.get_integer(&(&rel + 1_usize))?;
    let d2 = vm.get_integer(&(&rel + 2_usize))?;

    Ok(pack(d0.as_ref(), d1.as_ref(), d2.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::*;
    use felt::NewFelt;
    use num_bigint::BigInt;

    #[test]
    fn secp_split() {
        let mut constants = HashMap::new();
        constants.insert(BASE_86.to_string(), Felt::one() << 86_usize);

        let array_1 = split(&BigInt::zero(), &constants);
        let array_2 = split(&bigint!(999992), &constants);
        let array_3 = split(
            &bigint_str!("7737125245533626718119526477371252455336267181195264773712524553362"),
            &constants,
        );
        let array_4 = split(&bigint!(-1), &constants);
        //TODO, Check SecpSplitutOfRange limit
        let array_5 = split(
            &bigint_str!(
                "773712524553362671811952647737125245533626718119526477371252455336267181195264"
            ),
            &constants,
        );

        assert_eq!(
            array_1,
            Ok([BigInt::zero(), BigInt::zero(), BigInt::zero()])
        );
        assert_eq!(
            array_2,
            Ok([bigint!(999992), BigInt::zero(), BigInt::zero()])
        );
        assert_eq!(
            array_3,
            Ok([
                bigint_str!("773712524553362"),
                bigint_str!("57408430697461422066401280"),
                bigint_str!("1292469707114105")
            ])
        );
        assert_eq!(
            array_4,
            Err(VirtualMachineError::SecpSplitNegative(bigint!(-1)))
        );
        assert_eq!(
            array_5,
            Err(VirtualMachineError::SecpSplitutOfRange(bigint_str!(
                "773712524553362671811952647737125245533626718119526477371252455336267181195264"
            )))
        );
    }

    #[test]
    fn secp_pack() {
        let pack_1 = pack(&Felt::new(10_i32), &Felt::new(10_i32), &Felt::new(10_i32));
        assert_eq!(
            pack_1,
            bigint_str!("59863107065073783529622931521771477038469668772249610")
        );

        let pack_2 = pack(
            &felt_str!("773712524553362"),
            &felt_str!("57408430697461422066401280"),
            &felt_str!("1292469707114105"),
        );
        assert_eq!(
            pack_2,
            bigint_str!("7737125245533626718119526477371252455336267181195264773712524553362")
        );
    }
}
