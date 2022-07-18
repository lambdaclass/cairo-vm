use crate::bigint;
use crate::types::relocatable::MaybeRelocatable;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::hint_utils::get_address_from_reference;
use crate::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::FromPrimitive;
use std::collections::HashMap;

/*
Implements hint:
%{ ids.locs.bit = (ids.prev_locs.exp % PRIME) & 1 %}
*/
pub fn pow(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    println!("ids: {:?}:", ids);

    //Check that ids contains the reference id for the variables used by the hint
    let (prev_locs_ref, locs_ref) = if let (Some(prev_locs_ref), Some(locs_ref)) = (
        ids.get(&String::from("prev_locs")),
        ids.get(&String::from("locs")),
    ) {
        (prev_locs_ref, locs_ref)
    } else {
        return Err(VirtualMachineError::IncorrectIds(
            vec![String::from("prev_locs"), String::from("locs")],
            ids.into_keys().collect(),
        ));
    };

    println!("prev_locs_ref {:?}", prev_locs_ref);
    println!("locs_ref {:?}", locs_ref);
    println!("vm.references {:?}", vm.references);

    // Get the addresses of the variables used in the hints
    let (prev_locs_addr, locs_addr) = if let (
        Some(MaybeRelocatable::RelocatableValue(prev_locs_addr)),
        Some(MaybeRelocatable::RelocatableValue(locs_addr)),
    ) = (
        get_address_from_reference(prev_locs_ref, &vm.references, &vm.run_context, vm),
        get_address_from_reference(locs_ref, &vm.references, &vm.run_context, vm),
    ) {
        (prev_locs_addr, locs_addr)
    } else {
        return Err(VirtualMachineError::FailedToGetIds);
    };

    println!("prev_locs_addr: {:?}", prev_locs_addr);
    println!("locs_addr: {:?}", locs_addr);

    let prev_locs_exp_addr =
        MaybeRelocatable::from((prev_locs_addr.segment_index, prev_locs_addr.offset + 4));
    match vm.memory.get(&prev_locs_exp_addr) {
        Ok(Some(MaybeRelocatable::Int(prev_locs_exp))) => {
            let locs_bit = prev_locs_exp.mod_floor(&vm.prime) & bigint!(1);
            println!("locs: {:?}", locs_bit);
            vm.memory
                .insert(
                    &MaybeRelocatable::RelocatableValue(locs_addr),
                    &MaybeRelocatable::Int(locs_bit),
                )
                .map_err(VirtualMachineError::MemoryError)?;
            Ok(())
        }
        Ok(_) => Err(VirtualMachineError::ExpectedInteger(prev_locs_exp_addr)),
        Err(memory_error) => Err(VirtualMachineError::MemoryError(memory_error)),
    }
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
                },
            ),
            (
                1,
                HintReference {
                    register: Register::AP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
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

        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids), Ok(()));

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

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::IncorrectIds(
                vec![String::from("prev_locs"), String::from("locs")],
                vec![String::from("locs")]
            ))
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
                },
            ),
        ]);

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::FailedToGetIds)
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
                },
            ),
            (
                1,
                HintReference {
                    register: Register::AP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
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

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
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
                },
            ),
            (
                1,
                HintReference {
                    register: Register::AP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
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

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
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
