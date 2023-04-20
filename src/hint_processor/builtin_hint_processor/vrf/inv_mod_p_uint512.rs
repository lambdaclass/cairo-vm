use core::ops::Shl;

use crate::{
    hint_processor::{
        builtin_hint_processor::hint_utils::get_relocatable_from_var_name,
        hint_processor_definition::HintReference,
    },
    math_utils::div_mod,
    serde::deserialize_program::ApTracking,
    stdlib::collections::HashMap,
    vm::errors::hint_errors::HintError,
};
use felt::Felt252;
use num_bigint::{BigInt, BigUint};
use num_traits::{Num, One};

use crate::vm::vm_core::VirtualMachine;

/*
def pack_512(d0, d1,d2,d3, num_bits_shift: int) -> int:
    limbs = (d0, d1, d2, d3)
    return sum(limb << (num_bits_shift * i) for i, limb in enumerate(limbs))

*/
fn pack_512(limbs: &[Felt252; 4], num_bits_shift: usize) -> BigUint {
    limbs
        .iter()
        .enumerate()
        .map(|(idx, value)| value.to_biguint().shl(idx * num_bits_shift))
        .sum()
}

/*
Implements hint:
%{
    def pack_512(u, num_bits_shift: int) -> int:
        limbs = (u.d0, u.d1, u.d2, u.d3)
        return sum(limb << (num_bits_shift * i) for i, limb in enumerate(limbs))

    x = pack_512(ids.x, num_bits_shift = 128)
    p = ids.p.low + (ids.p.high << 128)
    x_inverse_mod_p = pow(x,-1, p)

    x_inverse_mod_p_split = (x_inverse_mod_p & ((1 << 128) - 1), x_inverse_mod_p >> 128)

    ids.x_inverse_mod_p.low = x_inverse_mod_p_split[0]
    ids.x_inverse_mod_p.high = x_inverse_mod_p_split[1]
%}
*/
pub fn inv_mod_p_uint512(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    let limbs_ptr = get_relocatable_from_var_name("x", vm, ids_data, ap_tracking)?;
    let limbs: Vec<Felt252> = vm
        .get_integer_range(limbs_ptr, 4)?
        .iter()
        .map(|f| f.clone().into_owned())
        .collect();

    let x = pack_512(
        &limbs
            .try_into()
            .map_err(|_| HintError::FixedSizeArrayFail(4))?,
        128,
    );

    let p_ptr = get_relocatable_from_var_name("p", vm, ids_data, ap_tracking)?;
    let p_low = vm.get_integer(p_ptr)?;
    let p_high = vm.get_integer((p_ptr + 1_i32)?)?;

    let p = p_low.into_owned().to_biguint() + (p_high.into_owned().to_biguint() << 128_usize);
    let x_inverse_mod_p =
        Felt252::from(div_mod(&BigInt::one(), &BigInt::from(x), &BigInt::from(p)));

    let x_inverse_mod_p_ptr =
        get_relocatable_from_var_name("x_inverse_mod_p", vm, ids_data, ap_tracking)?;

    vm.insert_value(
        x_inverse_mod_p_ptr,
        &x_inverse_mod_p
            & &Felt252::from_str_radix("340282366920938463463374607431768211455", 10).unwrap(),
    )?;

    vm.insert_value((x_inverse_mod_p_ptr + 1_i32)?, x_inverse_mod_p >> 128)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use num_traits::FromPrimitive;

    use super::*;

    #[test]
    fn test_pack_512() {
        assert_eq!(
            pack_512(
                &[
                    Felt252::new(13123),
                    Felt252::new(534354),
                    Felt252::new(9901823),
                    Felt252::new(7812371)
                ],
                2
            ),
            BigUint::from(660571451_u128)
        );
        assert_eq!(
            pack_512(
                &[
                    Felt252::new(13123),
                    Felt252::new(534354),
                    Felt252::new(9901823),
                    Felt252::new(7812371)
                ],
                76
            ),
            BigUint::from_str_radix(
                "3369937688063908975412897222574435556910082026593269572342866796946053411651",
                10
            )
            .unwrap()
        );

        assert_eq!(
            pack_512(
                &[
                    Felt252::new(90812398),
                    Felt252::new(55),
                    Felt252::new(83127),
                    Felt252::from_i128(45312309123).unwrap()
                ],
                761
            ),
            BigUint::from_str_radix("80853029148137605102740201774483901385926652025450340798711030404174727480763870493377667725625759764292622444803788021444434452626041518098606806141685367065099387655302625873713592439838446220691925786159227082298892378981461987274693629088875674987359669209043388107114325450518636532594445145924759095125734364345163525655691027843325303271775064263282011908012871334532482494107608759994020937000541268185418760956243245766874157401648637158526410360988956699864519559367805347900540475245570833510432301935056255005826223734865268553682118180231081037207280009003811438596531432027766301678781550463988061852846171462460595592799020846810683500364584025173048032553173114469560143047387885550", 10).unwrap()
        );
    }
}
