use crate::math_utils::isqrt;
use crate::serde::deserialize_program::ApTracking;
use crate::types::relocatable::MaybeRelocatable;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::hint_utils::{
    get_address_from_var_name, get_integer_from_relocatable_plus_offset, get_integer_from_var_name,
    get_relocatable_from_var_name,
};
use crate::vm::vm_core::VirtualMachine;
use crate::{bigint, bigint_i128, bigint_u64};
use num_bigint::BigInt;
use num_integer::{div_rem, Integer};
use num_traits::{FromPrimitive, Signed};
use std::collections::HashMap;
use std::ops::{Shl, Shr};

/*
Implements hint:
%{
    sum_low = ids.a.low + ids.b.low
    ids.carry_low = 1 if sum_low >= ids.SHIFT else 0
    sum_high = ids.a.high + ids.b.high + ids.carry_low
    ids.carry_high = 1 if sum_high >= ids.SHIFT else 0
%}
*/
pub fn uint256_add(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let shift: BigInt = bigint!(2).pow(128);

    let a_relocatable = get_relocatable_from_var_name("a", &ids, vm, hint_ap_tracking)?;
    let b_relocatable = get_relocatable_from_var_name("b", &ids, vm, hint_ap_tracking)?;
    let carry_high_addr = get_address_from_var_name("carry_high", &ids, vm, hint_ap_tracking)?;
    let carry_low_addr = get_address_from_var_name("carry_low", &ids, vm, hint_ap_tracking)?;

    let a_low = get_integer_from_relocatable_plus_offset(&a_relocatable, 0, vm)?;
    let a_high = get_integer_from_relocatable_plus_offset(&a_relocatable, 1, vm)?;
    let b_low = get_integer_from_relocatable_plus_offset(&b_relocatable, 0, vm)?;
    let b_high = get_integer_from_relocatable_plus_offset(&b_relocatable, 1, vm)?;

    //Main logic
    //sum_low = ids.a.low + ids.b.low
    //ids.carry_low = 1 if sum_low >= ids.SHIFT else 0
    //sum_high = ids.a.high + ids.b.high + ids.carry_low
    //ids.carry_high = 1 if sum_high >= ids.SHIFT else 0

    let carry_low = if a_low + b_low >= shift {
        bigint!(1)
    } else {
        bigint!(0)
    };

    let carry_high = if a_high + b_high + &carry_low >= shift {
        bigint!(1)
    } else {
        bigint!(0)
    };

    vm.memory
        .insert(&carry_high_addr, &MaybeRelocatable::from(carry_high))
        .map_err(VirtualMachineError::MemoryError)?;

    vm.memory
        .insert(&carry_low_addr, &MaybeRelocatable::from(carry_low))
        .map_err(VirtualMachineError::MemoryError)
}

/*
Implements hint:
%{
    ids.low = ids.a & ((1<<64) - 1)
    ids.high = ids.a >> 64
%}
*/
pub fn split_64(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a = get_integer_from_var_name("a", &ids, vm, hint_ap_tracking)?;
    let high_addr = get_address_from_var_name("high", &ids, vm, hint_ap_tracking)?;
    let low_addr = get_address_from_var_name("low", &ids, vm, hint_ap_tracking)?;

    let mut digits = a.iter_u64_digits();
    let low = digits.next().unwrap_or(0u64);
    let high = digits.next().unwrap_or(0u64);

    vm.memory
        .insert(&low_addr, &MaybeRelocatable::from(bigint_u64!(low)))
        .map_err(VirtualMachineError::MemoryError)?;
    vm.memory
        .insert(&high_addr, &MaybeRelocatable::from(bigint_u64!(high)))
        .map_err(VirtualMachineError::MemoryError)
}

/*
Implements hint:
%{
    from starkware.python.math_utils import isqrt
    n = (ids.n.high << 128) + ids.n.low
    root = isqrt(n)
    assert 0 <= root < 2 ** 128
    ids.root.low = root
    ids.root.high = 0
%}
*/
pub fn uint256_sqrt(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let n_relocatable = get_relocatable_from_var_name("n", &ids, vm, hint_ap_tracking)?;

    let root_addr = get_address_from_var_name("root", &ids, vm, hint_ap_tracking)?;
    let n_low = get_integer_from_relocatable_plus_offset(&n_relocatable, 0, vm)?;
    let n_high = get_integer_from_relocatable_plus_offset(&n_relocatable, 1, vm)?;

    //Main logic
    //from starkware.python.math_utils import isqrt
    //n = (ids.n.high << 128) + ids.n.low
    //root = isqrt(n)
    //assert 0 <= root < 2 ** 128
    //ids.root.low = root
    //ids.root.high = 0

    let root = isqrt(&(n_high.shl(128_usize) + n_low))?;

    if !(root.is_positive() && root < bigint!(2).pow(128)) {
        return Err(VirtualMachineError::AssertionFailed(format!(
            "assert 0 <= {} < 2 ** 128",
            &root
        )));
    }

    vm.memory
        .insert(&root_addr, &MaybeRelocatable::from(root))
        .map_err(VirtualMachineError::MemoryError)?;

    vm.memory
        .insert(
            &root_addr.add_usize_mod(1, None),
            &MaybeRelocatable::from(bigint!(0)),
        )
        .map_err(VirtualMachineError::MemoryError)
}

/*
Implements hint:
%{ memory[ap] = 1 if 0 <= (ids.a.high % PRIME) < 2 ** 127 else 0 %}
*/
pub fn uint256_signed_nn(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a_relocatable = get_relocatable_from_var_name("a", &ids, vm, hint_ap_tracking)?;

    let a_high = get_integer_from_relocatable_plus_offset(&a_relocatable, 1, vm)?;

    //Main logic
    //memory[ap] = 1 if 0 <= (ids.a.high % PRIME) < 2 ** 127 else 0

    let result: BigInt =
        if a_high.is_positive() && (a_high.mod_floor(&vm.prime)) < bigint_i128!(i128::MAX) + 1 {
            bigint!(1)
        } else {
            bigint!(0)
        };

    vm.memory
        .insert(&vm.run_context.ap, &MaybeRelocatable::from(result))
        .map_err(VirtualMachineError::MemoryError)
}

/*
Implements hint:
%{
    a = (ids.a.high << 128) + ids.a.low
    div = (ids.div.high << 128) + ids.div.low
    quotient, remainder = divmod(a, div)

    ids.quotient.low = quotient & ((1 << 128) - 1)
    ids.quotient.high = quotient >> 128
    ids.remainder.low = remainder & ((1 << 128) - 1)
    ids.remainder.high = remainder >> 128
%}
*/
pub fn uint256_unsigned_div_rem(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a_relocatable = get_relocatable_from_var_name("a", &ids, vm, hint_ap_tracking)?;
    let div_relocatable = get_relocatable_from_var_name("div", &ids, vm, hint_ap_tracking)?;
    let quotient_addr = get_address_from_var_name("quotient", &ids, vm, hint_ap_tracking)?;
    let remainder_addr = get_address_from_var_name("remainder", &ids, vm, hint_ap_tracking)?;

    let a_low = get_integer_from_relocatable_plus_offset(&a_relocatable, 0, vm)?;
    let a_high = get_integer_from_relocatable_plus_offset(&a_relocatable, 1, vm)?;
    let div_low = get_integer_from_relocatable_plus_offset(&div_relocatable, 0, vm)?;
    let div_high = get_integer_from_relocatable_plus_offset(&div_relocatable, 1, vm)?;

    //Main logic
    //a = (ids.a.high << 128) + ids.a.low
    //div = (ids.div.high << 128) + ids.div.low
    //quotient, remainder = divmod(a, div)

    //ids.quotient.low = quotient & ((1 << 128) - 1)
    //ids.quotient.high = quotient >> 128
    //ids.remainder.low = remainder & ((1 << 128) - 1)
    //ids.remainder.high = remainder >> 128

    let a = a_high.shl(128_usize) + a_low;
    let div = div_high.shl(128_usize) + div_low;
    //a and div will always be positive numbers
    //Then, Rust div_rem equals Python divmod
    let (quotient, remainder) = div_rem(a, div);

    let quotient_low = &quotient & ((bigint!(1).shl(128_usize)) - 1_usize);
    let quotient_high = quotient.shr(128_usize);

    let remainder_low = &remainder & ((bigint!(1).shl(128_usize)) - 1_usize);
    let remainder_high = remainder.shr(128_usize);

    //Insert ids.quotient.low
    vm.memory
        .insert(&quotient_addr, &MaybeRelocatable::from(quotient_low))
        .map_err(VirtualMachineError::MemoryError)?;

    //Insert ids.quotient.high
    vm.memory
        .insert(
            &quotient_addr.add_usize_mod(1, None),
            &MaybeRelocatable::from(quotient_high),
        )
        .map_err(VirtualMachineError::MemoryError)?;

    //Insert ids.remainder.low
    vm.memory
        .insert(&remainder_addr, &MaybeRelocatable::from(remainder_low))
        .map_err(VirtualMachineError::MemoryError)?;

    //Insert ids.remainder.high
    vm.memory
        .insert(
            &remainder_addr.add_usize_mod(1, None),
            &MaybeRelocatable::from(remainder_high),
        )
        .map_err(VirtualMachineError::MemoryError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint_str;
    use crate::types::instruction::Register;
    use crate::types::relocatable::MaybeRelocatable;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::vm::hints::execute_hint::{execute_hint, HintReference};
    use crate::{bigint, vm::runners::builtin_runner::RangeCheckBuiltinRunner};
    use num_bigint::{BigInt, Sign};
    use num_traits::FromPrimitive;

    #[test]
    fn run_uint256_add_ok() {
        let hint_code = "sum_low = ids.a.low + ids.b.low\nids.carry_low = 1 if sum_low >= ids.SHIFT else 0\nsum_high = ids.a.high + ids.b.high + ids.carry_low\nids.carry_high = 1 if sum_high >= ids.SHIFT else 0".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 10));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        ids.insert(String::from("carry_high"), bigint!(2));
        ids.insert(String::from("carry_low"), bigint!(3));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -6,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: 3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: 2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
        ]);

        //Insert ids.a.low into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //Insert ids.a.high into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 5)),
                &MaybeRelocatable::from(bigint!(3)),
            )
            .unwrap();
        //Insert ids.b.low into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 6)),
                &MaybeRelocatable::from(bigint!(4)),
            )
            .unwrap();
        //Insert ids.b.high into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 7)),
                &MaybeRelocatable::from(bigint!(2).pow(128)),
            )
            .unwrap();

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ApTracking::new()),
            Ok(())
        );

        //Check hint memory inserts
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 12))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 13))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1))))
        );
    }

    #[test]
    fn run_uint256_add_fail_inserts() {
        let hint_code = "sum_low = ids.a.low + ids.b.low\nids.carry_low = 1 if sum_low >= ids.SHIFT else 0\nsum_high = ids.a.high + ids.b.high + ids.carry_low\nids.carry_high = 1 if sum_high >= ids.SHIFT else 0".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 10));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        ids.insert(String::from("carry_high"), bigint!(2));
        ids.insert(String::from("carry_low"), bigint!(3));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -6,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: 3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: 2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
        ]);

        //Insert ids.a.low into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //Insert ids.a.high into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 5)),
                &MaybeRelocatable::from(bigint!(3)),
            )
            .unwrap();
        //Insert ids.b.low into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 6)),
                &MaybeRelocatable::from(bigint!(4)),
            )
            .unwrap();
        //Insert ids.b.high into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 7)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();

        //Insert a value in the ids.carry_low address, so the hint insertion fails
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 12)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((1, 12)),
                    MaybeRelocatable::from(bigint!(2)),
                    MaybeRelocatable::from(bigint!(0))
                )
            ))
        );
    }

    #[test]
    fn run_split_64_ok() {
        let hint_code = "ids.low = ids.a & ((1<<64) - 1)\nids.high = ids.a >> 64".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 10));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("high"), bigint!(1));
        ids.insert(String::from("low"), bigint!(2));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: 1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
        ]);

        //Insert ids.a into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 7)),
                &MaybeRelocatable::from(bigint_str!(b"850981239023189021389081239089023")),
            )
            .unwrap();

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ApTracking::new()),
            Ok(())
        );

        //Check hint memory inserts
        //ids.low
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 10))),
            Ok(Some(&MaybeRelocatable::from(bigint_str!(
                b"7249717543555297151"
            ))))
        );
        //ids.high
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 11))),
            Ok(Some(&MaybeRelocatable::from(bigint_str!(
                b"46131785404667"
            ))))
        );
    }

    #[test]
    fn run_split_64_memory_error() {
        let hint_code = "ids.low = ids.a & ((1<<64) - 1)\nids.high = ids.a >> 64".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 10));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("high"), bigint!(1));
        ids.insert(String::from("low"), bigint!(2));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: 1,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
        ]);

        //Insert ids.a into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 7)),
                &MaybeRelocatable::from(bigint_str!(b"850981239023189021389081239089023")),
            )
            .unwrap();

        //Insert a value in the ids.low address, so the hint insert fails
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 10)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((1, 10)),
                    MaybeRelocatable::from(bigint!(0)),
                    MaybeRelocatable::from(bigint_str!(b"7249717543555297151"))
                )
            ))
        );
    }

    #[test]
    fn run_uint256_sqrt_ok() {
        let hint_code = "from starkware.python.math_utils import isqrt\nn = (ids.n.high << 128) + ids.n.low\nroot = isqrt(n)\nassert 0 <= root < 2 ** 128\nids.root.low = root\nids.root.high = 0".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 5));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("n"), bigint!(0));
        ids.insert(String::from("root"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
        ]);

        //Insert  ids.n.low into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(bigint!(17)),
            )
            .unwrap();

        //Insert ids.n.high into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(7)),
            )
            .unwrap();

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ApTracking::new()),
            Ok(())
        );

        //Check hint memory inserts
        //ids.root.low
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 5))),
            Ok(Some(&MaybeRelocatable::from(bigint_str!(
                b"48805497317890012913"
            ))))
        );
        //ids.root.high
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 6))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
    }

    #[test]
    fn run_uint256_sqrt_assert_error() {
        let hint_code = "from starkware.python.math_utils import isqrt\nn = (ids.n.high << 128) + ids.n.low\nroot = isqrt(n)\nassert 0 <= root < 2 ** 128\nids.root.low = root\nids.root.high = 0".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 5));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("n"), bigint!(0));
        ids.insert(String::from("root"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
        ]);

        //Insert  ids.n.low into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();

        //Insert ids.n.high into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint_str!(b"340282366920938463463374607431768211458")),
            )
            .unwrap();

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ApTracking::new()),
            Err(VirtualMachineError::AssertionFailed(String::from(
                "assert 0 <= 340282366920938463463374607431768211456 < 2 ** 128"
            )))
        );
    }

    #[test]
    fn run_uint256_invalid_memory_insert() {
        let hint_code = "from starkware.python.math_utils import isqrt\nn = (ids.n.high << 128) + ids.n.low\nroot = isqrt(n)\nassert 0 <= root < 2 ** 128\nids.root.low = root\nids.root.high = 0".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 5));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("n"), bigint!(0));
        ids.insert(String::from("root"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
        ]);

        //Insert  ids.n.low into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(bigint!(17)),
            )
            .unwrap();

        //Insert ids.n.high into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(7)),
            )
            .unwrap();

        //Insert a value in the ids.root.low address so the hint insert fails
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 5)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((1, 5)),
                    MaybeRelocatable::from(bigint!(1)),
                    MaybeRelocatable::from(bigint_str!(b"48805497317890012913")),
                )
            ))
        );
    }

    #[test]
    fn run_signed_nn_ok_result_one() {
        let hint_code = "memory[ap] = 1 if 0 <= (ids.a.high % PRIME) < 2 ** 127 else 0".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 4));
        vm.run_context.ap = MaybeRelocatable::from((1, 5));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));

        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -4,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
            },
        )]);

        //Insert ids.a.high into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(2).pow(127) - 1 + &vm.prime),
            )
            .unwrap();

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ApTracking::new()),
            Ok(())
        );

        //Check hint memory insert
        //memory[ap] = 1 if 0 <= (ids.a.high % PRIME) < 2 ** 127 else 0
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 5))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1))))
        );
    }

    #[test]
    fn run_signed_nn_ok_result_zero() {
        let hint_code = "memory[ap] = 1 if 0 <= (ids.a.high % PRIME) < 2 ** 127 else 0".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 4));
        vm.run_context.ap = MaybeRelocatable::from((1, 5));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));

        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -4,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
            },
        )]);

        //Insert ids.a.high into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(2).pow(127) + &vm.prime),
            )
            .unwrap();

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ApTracking::new()),
            Ok(())
        );

        //Check hint memory insert
        //memory[ap] = 1 if 0 <= (ids.a.high % PRIME) < 2 ** 127 else 0
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 5))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
    }

    #[test]
    fn run_signed_nn_ok_invalid_memory_insert() {
        let hint_code = "memory[ap] = 1 if 0 <= (ids.a.high % PRIME) < 2 ** 127 else 0".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 4));
        vm.run_context.ap = MaybeRelocatable::from((1, 5));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));

        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -4,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
            },
        )]);

        //Insert ids.a.high into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        //Insert a value in ap so the hint insert fails
        vm.memory
            .insert(&vm.run_context.ap, &MaybeRelocatable::from(bigint!(55)))
            .unwrap();
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((1, 5)),
                    MaybeRelocatable::from(bigint!(55)),
                    MaybeRelocatable::from(bigint!(1)),
                )
            ))
        );
    }

    #[test]
    fn run_unsigned_div_rem_ok() {
        let hint_code = "a = (ids.a.high << 128) + ids.a.low\ndiv = (ids.div.high << 128) + ids.div.low\nquotient, remainder = divmod(a, div)\n\nids.quotient.low = quotient & ((1 << 128) - 1)\nids.quotient.high = quotient >> 128\nids.remainder.low = remainder & ((1 << 128) - 1)\nids.remainder.high = remainder >> 128".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 10));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("div"), bigint!(1));
        ids.insert(String::from("quotient"), bigint!(2));
        ids.insert(String::from("remainder"), bigint!(3));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -6,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: 2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
        ]);

        //Insert ids.a.low into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from(bigint!(89)),
            )
            .unwrap();
        //Insert ids.a.high into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 5)),
                &MaybeRelocatable::from(bigint!(72)),
            )
            .unwrap();
        //Insert ids.div.low into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 6)),
                &MaybeRelocatable::from(bigint!(3)),
            )
            .unwrap();
        //Insert ids.div.high into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 7)),
                &MaybeRelocatable::from(bigint!(7)),
            )
            .unwrap();

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ApTracking::new()),
            Ok(())
        );

        //Check hint memory inserts
        //ids.quotient.low
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 10))),
            Ok(Some(&MaybeRelocatable::from(bigint!(10))))
        );
        //ids.quotient.high
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 11))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
        //ids.remainder.low
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 12))),
            Ok(Some(&MaybeRelocatable::from(bigint!(59))))
        );
        //ids.remainder.high
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 13))),
            Ok(Some(&MaybeRelocatable::from(bigint!(2))))
        );
    }

    #[test]
    fn run_unsigned_div_rem_invalid_memory_insert() {
        let hint_code = "a = (ids.a.high << 128) + ids.a.low\ndiv = (ids.div.high << 128) + ids.div.low\nquotient, remainder = divmod(a, div)\n\nids.quotient.low = quotient & ((1 << 128) - 1)\nids.quotient.high = quotient >> 128\nids.remainder.low = remainder & ((1 << 128) - 1)\nids.remainder.high = remainder >> 128".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
        );
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 10));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("div"), bigint!(1));
        ids.insert(String::from("quotient"), bigint!(2));
        ids.insert(String::from("remainder"), bigint!(3));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -6,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: 2,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                },
            ),
        ]);

        //Insert ids.a.low into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from(bigint!(89)),
            )
            .unwrap();
        //Insert ids.a.high into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 5)),
                &MaybeRelocatable::from(bigint!(72)),
            )
            .unwrap();
        //Insert ids.div.low into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 6)),
                &MaybeRelocatable::from(bigint!(3)),
            )
            .unwrap();
        //Insert ids.div.high into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 7)),
                &MaybeRelocatable::from(bigint!(7)),
            )
            .unwrap();
        //Insert a value in the ids.quotient.low address so the hint insert fails
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 10)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((1, 10)),
                    MaybeRelocatable::from(bigint!(0)),
                    MaybeRelocatable::from(bigint!(10)),
                )
            ))
        );
    }
}
