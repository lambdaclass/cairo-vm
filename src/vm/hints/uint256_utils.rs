use crate::bigint;
use crate::math_utils::isqrt;
use crate::serde::deserialize_program::ApTracking;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::hint_utils::{get_integer_from_var_name, get_relocatable_from_var_name};
use crate::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use num_integer::{div_rem, Integer};
use num_traits::Signed;
use std::collections::HashMap;
use std::ops::{Shl, Shr};

use super::hint_utils::{insert_int_into_ap, insert_integer_from_var_name};

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
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let shift: BigInt = bigint!(2).pow(128);

    let a_relocatable = get_relocatable_from_var_name(
        "a",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let b_relocatable = get_relocatable_from_var_name(
        "b",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let a_low = vm.memory.get_integer(&a_relocatable)?;
    let a_high = vm.memory.get_integer(&(a_relocatable + 1))?;
    let b_low = vm.memory.get_integer(&b_relocatable)?;
    let b_high = vm.memory.get_integer(&(b_relocatable + 1))?;

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
    insert_integer_from_var_name(
        "carry_high",
        carry_high,
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    insert_integer_from_var_name(
        "carry_low",
        carry_low,
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )
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
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a = get_integer_from_var_name(
        "a",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let mut digits = a.iter_u64_digits();
    let low = digits.next().unwrap_or(0u64);
    let high = digits.next().unwrap_or(0u64);
    insert_integer_from_var_name(
        "high",
        bigint!(high),
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    insert_integer_from_var_name(
        "low",
        bigint!(low),
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )
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
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let n_addr = get_relocatable_from_var_name(
        "n",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let root_addr = get_relocatable_from_var_name(
        "root",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let n_low = vm.memory.get_integer(&n_addr)?;
    let n_high = vm.memory.get_integer(&(n_addr + 1))?;

    //Main logic
    //from starkware.python.math_utils import isqrt
    //n = (ids.n.high << 128) + ids.n.low
    //root = isqrt(n)
    //assert 0 <= root < 2 ** 128
    //ids.root.low = root
    //ids.root.high = 0

    let root = isqrt(&(n_high.shl(128_usize) + n_low))?;

    if root.is_negative() || root >= bigint!(1).shl(128) {
        return Err(VirtualMachineError::AssertionFailed(format!(
            "assert 0 <= {} < 2 ** 128",
            &root
        )));
    }
    vm.memory.insert_integer(&root_addr, root)?;
    vm.memory.insert_integer(&(root_addr + 1), bigint!(0))
}

/*
Implements hint:
%{ memory[ap] = 1 if 0 <= (ids.a.high % PRIME) < 2 ** 127 else 0 %}
*/
pub fn uint256_signed_nn(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a_addr = get_relocatable_from_var_name(
        "a",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let a_high = vm.memory.get_integer(&(a_addr + 1))?;
    //Main logic
    //memory[ap] = 1 if 0 <= (ids.a.high % PRIME) < 2 ** 127 else 0
    let result: BigInt =
        if !a_high.is_negative() && (a_high.mod_floor(&vm.prime)) <= bigint!(i128::MAX) {
            bigint!(1)
        } else {
            bigint!(0)
        };
    insert_int_into_ap(&mut vm.memory, &vm.run_context, result)
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
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a_addr = get_relocatable_from_var_name(
        "a",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let div_addr = get_relocatable_from_var_name(
        "div",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let quotient_addr = get_relocatable_from_var_name(
        "quotient",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let remainder_addr = get_relocatable_from_var_name(
        "remainder",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;

    let a_low = vm.memory.get_integer(&a_addr)?;
    let a_high = vm.memory.get_integer(&(a_addr + 1))?;
    let div_low = vm.memory.get_integer(&div_addr)?;
    let div_high = vm.memory.get_integer(&(div_addr + 1))?;

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

    let quotient_low = &quotient & bigint!(u128::MAX);
    let quotient_high = quotient.shr(128_usize);

    let remainder_low = &remainder & bigint!(u128::MAX);
    let remainder_high = remainder.shr(128_usize);

    //Insert ids.quotient.low
    vm.memory.insert_integer(&quotient_addr, quotient_low)?;
    //Insert ids.quotient.high
    vm.memory
        .insert_integer(&(quotient_addr + 1), quotient_high)?;
    //Insert ids.remainder.low
    vm.memory.insert_integer(&remainder_addr, remainder_low)?;
    //Insert ids.remainder.high
    vm.memory
        .insert_integer(&(remainder_addr + 1), remainder_high)
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                immediate: None,
            },
        )]);

        //Insert ids.a.high into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(&vm.prime + i128::MAX),
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
                immediate: None,
            },
        )]);

        //Insert ids.a.high into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1).shl(127) + &vm.prime),
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
                immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
                    immediate: None,
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
