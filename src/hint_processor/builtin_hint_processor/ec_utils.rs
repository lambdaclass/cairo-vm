use crate::stdlib::{borrow::Cow, collections::HashMap, prelude::*};
use crate::utils::CAIRO_PRIME;
use crate::{
    hint_processor::{
        builtin_hint_processor::hint_utils::{
            get_integer_from_var_name, get_relocatable_from_var_name,
        },
        hint_processor_definition::HintReference,
    },
    serde::deserialize_program::ApTracking,
    vm::{errors::hint_errors::HintError, vm_core::VirtualMachine},
};
use felt::Felt;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_bigint::ToBigInt;
use num_traits::{Bounded, Num, One, Pow};
use sha2::{Digest, Sha256};

use crate::math_utils::sqrt;

#[derive(Debug, PartialEq)]
struct EcPoint<'a> {
    x: Cow<'a, Felt>,
    y: Cow<'a, Felt>,
}
impl EcPoint<'_> {
    fn from_var_name<'a>(
        name: &'a str,
        vm: &'a VirtualMachine,
        ids_data: &'a HashMap<String, HintReference>,
        ap_tracking: &'a ApTracking,
    ) -> Result<EcPoint<'a>, HintError> {
        // Get first addr of EcPoint struct
        let point_addr = get_relocatable_from_var_name(name, vm, ids_data, ap_tracking)?;
        Ok(EcPoint {
            x: vm
                .get_integer(point_addr)
                .map_err(|_| HintError::IdentifierHasNoMember(name.to_string(), "x".to_string()))?,
            y: vm
                .get_integer((point_addr + 1)?)
                .map_err(|_| HintError::IdentifierHasNoMember(name.to_string(), "x".to_string()))?,
        })
    }
}

// Implements hint:
// from starkware.crypto.signature.signature import ALPHA, BETA, FIELD_PRIME
// from starkware.python.math_utils import random_ec_point
// from starkware.python.utils import to_bytes

// # Define a seed for random_ec_point that's dependent on all the input, so that:
// #   (1) The added point s is deterministic.
// #   (2) It's hard to choose inputs for which the builtin will fail.
// seed = b"".join(map(to_bytes, [ids.p.x, ids.p.y, ids.m, ids.q.x, ids.q.y]))
// ids.s.x, ids.s.y = random_ec_point(FIELD_PRIME, ALPHA, BETA, seed)

pub fn random_ec_point_hint(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    let p = EcPoint::from_var_name("p", vm, ids_data, ap_tracking)?;
    let q = EcPoint::from_var_name("q", vm, ids_data, ap_tracking)?;
    let m = get_integer_from_var_name("m", vm, ids_data, ap_tracking)?;
    let bytes: Vec<u8> = [p.x, p.y, m, q.x, q.y]
        .iter()
        .flat_map(|x| to_padded_bytes(&x))
        .collect();
    let (x, y) = random_ec_point_seeded(bytes)?;
    let s_addr = get_relocatable_from_var_name("s", vm, ids_data, ap_tracking)?;
    vm.insert_value(s_addr, x)?;
    vm.insert_value((s_addr + 1)?, y)?;
    Ok(())
}

// Returns the Felt as a vec of bytes of len 32, pads left with zeros
fn to_padded_bytes(n: &Felt) -> Vec<u8> {
    let felt_to_bytes = n.to_bytes_be();
    let mut bytes: Vec<u8> = vec![0; 32 - felt_to_bytes.len()];
    bytes.extend(felt_to_bytes);
    bytes
}

// Returns a random non-zero point on the elliptic curve
//   y^2 = x^3 + alpha * x + beta (mod field_prime).
// The point is created deterministically from the seed.
fn random_ec_point_seeded(seed_bytes: Vec<u8>) -> Result<(Felt, Felt), HintError> {
    // Hash initial seed
    let mut hasher = Sha256::new();
    hasher.update(seed_bytes);
    let seed = hasher.finalize_reset().to_vec();
    for i in 0..100 {
        // Calculate x
        let i_bytes = (i as u8).to_le_bytes();
        let mut input = seed[1..].to_vec();
        input.extend(i_bytes);
        input.extend(vec![0; 10 - i_bytes.len()]);
        hasher.update(input);
        let x = BigUint::from_bytes_be(&hasher.finalize_reset());
        // Calculate y
        let y_coef = (-1).pow(seed[0] & 1);
        let y = recover_y(&x);
        if let Some(y) = y {
            // Conversion from BigUint to BigInt doesnt fail
            return Ok((Felt::from(x), Felt::from(y.to_bigint().unwrap() * y_coef)));
        }
    }
    Err(HintError::RandomEcPointNotOnCurve)
}
const ALPHA: u32 = 1;
lazy_static! {
    static ref BETA: BigUint = BigUint::from_str_radix(
        "3141592653589793238462643383279502884197169399375105820974944592307816406665",
        10
    )
    .unwrap();
}

// Recovers the corresponding y coordinate on the elliptic curve
//     y^2 = x^3 + alpha * x + beta (mod field_prime)
//     of a given x coordinate.
// Returns None if x is not the x coordinate of a point in the curve
fn recover_y(x: &BigUint) -> Option<BigUint> {
    let y_squared: BigUint = x.modpow(&BigUint::from(3_u32), &*CAIRO_PRIME) + ALPHA * x + &*BETA;
    if is_quad_residue(&y_squared) {
        Some(sqrt(&Felt::from(y_squared)).to_biguint())
    } else {
        None
    }
}

// Implementation adapted from sympy implementation
// Conditions:
// + prime is ommited as it will be CAIRO_PRIME
// + a >= 0 < prime (other cases ommited)
fn is_quad_residue(a: &BigUint) -> bool {
    if a < &BigUint::from(2_u8) {
        return true;
    };
    a.modpow(&(Felt::max_value().to_biguint() / 2_u32), &*CAIRO_PRIME) == BigUint::one()
}

#[cfg(test)]
mod tests {
    use crate::any_box;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData;
    use crate::hint_processor::hint_processor_definition::HintProcessor;
    use crate::types::exec_scope::ExecutionScopes;
    use num_traits::Zero;

    use crate::hint_processor::builtin_hint_processor::hint_code;
    use crate::utils::test_utils::*;
    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn test_is_quad_residue_less_than_2() {
        assert!(is_quad_residue(&BigUint::one()));
        assert!(is_quad_residue(&BigUint::zero()));
    }

    #[test]
    fn test_is_quad_residue_false() {
        assert!(!is_quad_residue(
            &BigUint::from_str_radix(
                "205857351767627712295703269674687767888261140702556021834663354704341414042",
                10
            )
            .unwrap()
        ));
    }

    #[test]
    fn test_is_quad_residue_true() {
        assert!(is_quad_residue(
            &BigUint::from_str_radix(
                "99957092485221722822822221624080199277265330641980989815386842231144616633668",
                10
            )
            .unwrap()
        ));
    }

    #[test]
    fn test_recover_y_valid() {
        let x = BigUint::from_str_radix(
            "2497468900767850684421727063357792717599762502387246235265616708902555305129",
            10,
        )
        .unwrap();
        let y = BigUint::from_str_radix(
            "205857351767627712295703269674687767888261140702556021834663354704341414042",
            10,
        )
        .unwrap();
        assert_eq!(recover_y(&x), Some(y));
    }

    #[test]
    fn test_recover_y_invalid() {
        let x = BigUint::from_str_radix(
            "205857351767627712295703269674687767888261140702556021834663354704341414042",
            10,
        )
        .unwrap();
        assert_eq!(recover_y(&x), None);
    }

    #[test]
    fn get_random_ec_point_seeded() {
        let seed: Vec<u8> = vec![
            6, 164, 190, 174, 245, 169, 52, 37, 185, 115, 23, 156, 219, 160, 201, 212, 47, 48, 224,
            26, 95, 30, 45, 183, 61, 160, 136, 75, 141, 103, 86, 252, 7, 37, 101, 236, 129, 188, 9,
            255, 83, 251, 250, 217, 147, 36, 169, 42, 165, 179, 159, 181, 130, 103, 227, 149, 232,
            171, 227, 98, 144, 235, 242, 79, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 34, 6, 84, 253, 126, 103, 161, 35, 221, 19, 134,
            128, 147, 179, 183, 119, 127, 31, 254, 245, 150, 194, 227, 36, 242, 92, 234, 249, 20,
            102, 152, 72, 44, 4, 250, 210, 105, 203, 248, 96, 152, 14, 56, 118, 143, 233, 203, 107,
            11, 154, 176, 62, 227, 254, 132, 207, 222, 46, 204, 206, 89, 124, 135, 79, 216,
        ];
        let x = Felt::from_str_radix(
            "2497468900767850684421727063357792717599762502387246235265616708902555305129",
            10,
        )
        .unwrap();
        let y = Felt::from_str_radix(
            "3412645436898503501401619513420382337734846074629040678138428701431530606439",
            10,
        )
        .unwrap();
        assert_eq!(random_ec_point_seeded(seed).unwrap(), (x, y));
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn run_pow_prev_locs_exp_is_not_integer() {
        let hint_code = hint_code::RANDOM_EC_POINT;
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 6;
        //Create hint_data
        let ids_data = non_continuous_ids_data![("p", -6), ("q", -3), ("m", -4), ("s", 0)];
        //Insert ids.prev_locs.exp into memory as a RelocatableValue
        /*  p.x = 0x6a4beaef5a93425b973179cdba0c9d42f30e01a5f1e2db73da0884b8d6756fc
           p.y = 0x72565ec81bc09ff53fbfad99324a92aa5b39fb58267e395e8abe36290ebf24f
           m = 34
           q.x = 0x654fd7e67a123dd13868093b3b7777f1ffef596c2e324f25ceaf9146698482c
           q.y = 0x4fad269cbf860980e38768fe9cb6b0b9ab03ee3fe84cfde2eccce597c874fd8
        */
        add_segments!(vm, 1);
        vm.insert_value(
            (1, 0).into(),
            Felt::from_str_radix(
                "0x6a4beaef5a93425b973179cdba0c9d42f30e01a5f1e2db73da0884b8d6756fc",
                16,
            )
            .unwrap(),
        )
        .unwrap();
        vm.insert_value(
            (1, 1).into(),
            Felt::from_str_radix(
                "0x6a4beaef5a93425b973179cdba0c9d42f30e01a5f1e2db73da0884b8d6756fc",
                16,
            )
            .unwrap(),
        )
        .unwrap();
        vm.insert_value((1, 2).into(), Felt::from(34)).unwrap();
        vm.insert_value(
            (1, 3).into(),
            Felt::from_str_radix(
                "0x654fd7e67a123dd13868093b3b7777f1ffef596c2e324f25ceaf9146698482c",
                16,
            )
            .unwrap(),
        )
        .unwrap();
        vm.insert_value(
            (1, 4).into(),
            Felt::from_str_radix(
                "0x4fad269cbf860980e38768fe9cb6b0b9ab03ee3fe84cfde2eccce597c874fd8",
                16,
            )
            .unwrap(),
        )
        .unwrap();
        //Execute the hint
        assert_matches!(run_hint!(vm, ids_data, hint_code), Ok(()));
        // Check post-hint memory values
        // s.x = 108925483682366235368969256555281508851459278989259552980345066351008608800
        // s.y = 1592365885972480102953613056006596671718206128324372995731808913669237079419
        assert_eq!(
            vm.get_integer((1, 5).into()).unwrap().as_ref(),
            &Felt::from_str_radix(
                "108925483682366235368969256555281508851459278989259552980345066351008608800",
                10
            )
            .unwrap()
        );
        assert_eq!(
            vm.get_integer((1, 6).into()).unwrap().as_ref(),
            &Felt::from_str_radix(
                "1592365885972480102953613056006596671718206128324372995731808913669237079419",
                10
            )
            .unwrap()
        );
    }
}
