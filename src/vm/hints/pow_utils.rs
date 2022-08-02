use crate::serde::deserialize_program::ApTracking;
use crate::types::relocatable::Relocatable;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::vm_core::VirtualMachine;
use crate::{bigint, relocatable};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::FromPrimitive;
use std::collections::HashMap;

use super::hint_utils::{get_relocatable_from_var_name, insert_integer_from_var_name};

/*
Implements hint:
%{ ids.locs.bit = (ids.prev_locs.exp % PRIME) & 1 %}
*/
pub fn pow(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let prev_locs_addr = get_relocatable_from_var_name(
        "prev_locs",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let prev_locs_exp_addr = relocatable!(prev_locs_addr.segment_index, prev_locs_addr.offset + 4);
    let prev_locs_exp = vm.memory.get_integer(&prev_locs_exp_addr)?;
    let locs_bit = prev_locs_exp.mod_floor(&vm.prime) & bigint!(1);
    insert_integer_from_var_name(
        "locs",
        locs_bit,
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use crate::types::instruction::Register;
    use crate::types::relocatable::MaybeRelocatable;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::vm::hints::execute_hint::{execute_hint, HintReference};
    use crate::{bigint, vm::runners::builtin_runner::RangeCheckBuiltinRunner};
    use num_bigint::{BigInt, Sign};
    use num_traits::FromPrimitive;

    use super::*;

    #[test]
    fn run_pow_ok() {
        let hint_code = "ids.locs.bit = (ids.prev_locs.exp % PRIME) & 1".as_bytes();
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

        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 12));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("prev_locs"), bigint!(0));
        ids.insert(String::from("locs"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::AP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: Some(ApTracking {
                        group: 4,
                        offset: 3,
                    }),
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::AP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: Some(ApTracking {
                        group: 4,
                        offset: 3,
                    }),
                    immediate: None,
                },
            ),
        ]);

        //Insert ids.prev_locs.exp into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 10)),
                &MaybeRelocatable::from(bigint!(3)),
            )
            .unwrap();

        let ap_tracking = ApTracking {
            group: 4,
            offset: 4,
        };

        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids, &ap_tracking), Ok(()));

        //Check hint memory inserts
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 11))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1))))
        );
    }

    #[test]
    fn run_pow_incorrect_ids() {
        let hint_code = "ids.locs.bit = (ids.prev_locs.exp % PRIME) & 1".as_bytes();
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

        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 11));

        //Create incorrect ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("locs"), bigint!(1));

        let ap_tracking: ApTracking = ApTracking::new();

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ap_tracking),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_pow_incorrect_references() {
        let hint_code = "ids.locs.bit = (ids.prev_locs.exp % PRIME) & 1".as_bytes();
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

        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 11));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("prev_locs"), bigint!(0));
        ids.insert(String::from("locs"), bigint!(1));

        //Create incorrect references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::AP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: Some(ApTracking::new()),
                    immediate: None,
                },
            ),
            // Incorrect reference, offset1 out of range
            (
                1,
                HintReference {
                    register: Register::AP,
                    offset1: -12,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: Some(ApTracking::new()),
                    immediate: None,
                },
            ),
        ]);

        let ap_tracking: ApTracking = ApTracking::new();

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ap_tracking),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 10))
            ))
        );
    }

    #[test]
    fn run_pow_prev_locs_exp_is_not_integer() {
        let hint_code = "ids.locs.bit = (ids.prev_locs.exp % PRIME) & 1".as_bytes();
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

        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 11));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("prev_locs"), bigint!(0));
        ids.insert(String::from("locs"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::AP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: Some(ApTracking::new()),
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::AP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: Some(ApTracking::new()),
                    immediate: None,
                },
            ),
        ]);

        //Insert ids.prev_locs.exp into memory as a RelocatableValue
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 10)),
                &MaybeRelocatable::from((1, 11)),
            )
            .unwrap();

        let ap_tracking: ApTracking = ApTracking::new();

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ap_tracking),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 10))
            ))
        );
    }

    #[test]
    fn run_pow_invalid_memory_insert() {
        let hint_code = "ids.locs.bit = (ids.prev_locs.exp % PRIME) & 1".as_bytes();
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

        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 11));

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("prev_locs"), bigint!(0));
        ids.insert(String::from("locs"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::AP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: Some(ApTracking::new()),
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::AP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: Some(ApTracking::new()),
                    immediate: None,
                },
            ),
        ]);

        //Insert ids.prev_locs.exp into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 10)),
                &MaybeRelocatable::from(bigint!(3)),
            )
            .unwrap();

        // Insert ids.locs.bit before the hint execution, so the hint memory.insert fails
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 11)),
                &MaybeRelocatable::from(bigint!(3)),
            )
            .unwrap();

        let ap_tracking: ApTracking = ApTracking::new();

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ap_tracking),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((1, 11)),
                    MaybeRelocatable::from(bigint!(3)),
                    MaybeRelocatable::from(bigint!(1))
                )
            ))
        );
    }
}
