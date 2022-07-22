use crate::bigint;
use crate::serde::deserialize_program::ApTracking;
use crate::types::relocatable::MaybeRelocatable;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::hint_utils::{
    get_address_from_var_name, get_integer_from_address_plus_offset, get_integer_from_var_name,
};
use crate::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use num_traits::FromPrimitive;
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

    let a_addr = get_address_from_var_name("a", ids.clone(), vm, hint_ap_tracking)?;
    let b_addr = get_address_from_var_name("b", ids.clone(), vm, hint_ap_tracking)?;
    let carry_high_addr =
        get_address_from_var_name("carry_high", ids.clone(), vm, hint_ap_tracking)?;
    let carry_low_addr = get_address_from_var_name("carry_low", ids, vm, hint_ap_tracking)?;

    let a_low = get_integer_from_address_plus_offset(&a_addr, 0, vm)?;
    let a_high = get_integer_from_address_plus_offset(&a_addr, 1, vm)?;
    let b_low = get_integer_from_address_plus_offset(&b_addr, 0, vm)?;
    let b_high = get_integer_from_address_plus_offset(&b_addr, 1, vm)?;

    // Hint main logic
    // sum_low = ids.a.low + ids.b.low
    // ids.carry_low = 1 if sum_low >= ids.SHIFT else 0
    // sum_high = ids.a.high + ids.b.high + ids.carry_low
    // ids.carry_high = 1 if sum_high >= ids.SHIFT else 0

    let carry_low = if a_low + b_low >= shift {
        bigint!(1)
    } else {
        bigint!(0)
    };

    let carry_high = if a_high + b_high + carry_low.clone() >= shift {
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
    let a = get_integer_from_var_name("a", ids.clone(), vm, hint_ap_tracking)?;
    let high_addr = get_address_from_var_name("high", ids.clone(), vm, hint_ap_tracking)?;
    let low_addr = get_address_from_var_name("low", ids, vm, hint_ap_tracking)?;

    let low: BigInt = a & (bigint!(1).shl(64_usize) - 1);
    let high: BigInt = a.shr(64_usize);

    vm.memory
        .insert(&low_addr, &MaybeRelocatable::from(low))
        .map_err(VirtualMachineError::MemoryError)?;
    vm.memory
        .insert(&high_addr, &MaybeRelocatable::from(high))
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
        //Insert ids.b.high into memory
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
        //Insert ids.b.high into memory
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
        // ids.low
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 10))),
            Ok(Some(&MaybeRelocatable::from(bigint_str!(
                b"7249717543555297151"
            ))))
        );
        // ids.high
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

        //Insert a value in the ids.low address, so the hint insertion fails
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
}
