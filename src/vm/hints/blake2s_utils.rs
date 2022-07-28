use std::collections::HashMap;

use num_traits::ToPrimitive;

use super::blake2s_hash::blake2s_compress;
use super::hint_utils::get_ptr_from_var_name;
use crate::bigint_u64;
use crate::serde::deserialize_program::ApTracking;
use crate::types::relocatable::Relocatable;
use crate::vm::vm_core::VirtualMachine;
use crate::{
    types::relocatable::MaybeRelocatable,
    vm::{
        errors::vm_errors::VirtualMachineError,
        vm_memory::{memory::Memory, memory_segments::MemorySegmentManager},
    },
};
use num_bigint::BigInt;
use num_traits::FromPrimitive;

fn get_fixed_size_u64_array<const T: usize>(
    h_range: &Vec<Option<&MaybeRelocatable>>,
) -> Result<[u64; T], VirtualMachineError> {
    let mut u64_vec = Vec::<u64>::with_capacity(h_range.len());
    for element in h_range {
        let num = element
            .ok_or(VirtualMachineError::UnexpectMemoryGap)?
            .get_int_ref()?;
        u64_vec.push(num.to_u64().ok_or(VirtualMachineError::BigintToU64Fail)?);
    }
    u64_vec
        .try_into()
        .map_err(|_| VirtualMachineError::FixedSizeArrayFail(T))
}

fn get_maybe_relocatable_array_from_u64(array: &Vec<u64>) -> Vec<MaybeRelocatable> {
    let mut new_array = Vec::<MaybeRelocatable>::with_capacity(array.len());
    for element in array {
        new_array.push(MaybeRelocatable::from(bigint_u64!(*element)));
    }
    new_array
}
/*Helper function for the Cairo blake2s() implementation.
Computes the blake2s compress function and fills the value in the right position.
output_ptr should point to the middle of an instance, right after initial_state, message, t, f,
which should all have a value at this point, and right before the output portion which will be
written by this function.*/
fn compute_blake2s_func(
    segments: &mut MemorySegmentManager,
    memory: &mut Memory,
    output_rel: Relocatable,
) -> Result<(), VirtualMachineError> {
    let h = get_fixed_size_u64_array::<8>(
        &memory
            .get_range(&MaybeRelocatable::RelocatableValue(output_rel.sub(26)?), 8)
            .map_err(VirtualMachineError::MemoryError)?,
    )?;
    let message = get_fixed_size_u64_array::<16>(
        &memory
            .get_range(&MaybeRelocatable::RelocatableValue(output_rel.sub(18)?), 16)
            .map_err(VirtualMachineError::MemoryError)?,
    )?;
    let t = memory
        .get_integer(&output_rel.sub(2)?)?
        .to_u64()
        .ok_or(VirtualMachineError::BigintToU64Fail)?;
    let f = memory
        .get_integer(&output_rel.sub(1)?)?
        .to_u64()
        .ok_or(VirtualMachineError::BigintToU64Fail)?;
    let new_state =
        get_maybe_relocatable_array_from_u64(&blake2s_compress(&h, &message, t, 0, f, 0));
    let output_ptr = MaybeRelocatable::RelocatableValue(output_rel);
    segments
        .load_data(memory, &output_ptr, new_state)
        .map_err(VirtualMachineError::MemoryError)?;
    Ok(())
}

/* Implements hint:
   from starkware.cairo.common.cairo_blake2s.blake2s_utils import compute_blake2s_func
   compute_blake2s_func(segments=segments, output_ptr=ids.output)
*/
pub fn compute_blake2s(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let output = get_ptr_from_var_name("output", &ids, vm, hint_ap_tracking)?;
    compute_blake2s_func(&mut vm.segments, &mut vm.memory, output)
}

#[cfg(test)]
mod tests {
    use num_bigint::Sign;

    use super::*;
    use crate::{
        bigint, bigint_i128,
        types::instruction::Register,
        vm::hints::execute_hint::{execute_hint, HintReference},
    };

    #[test]
    fn compute_blake2s_output_offset_zero() {
        let hint_code = "from starkware.cairo.common.cairo_blake2s.blake2s_utils import compute_blake2s_func\ncompute_blake2s_func(segments=segments, output_ptr=ids.output)".as_bytes();
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory (output)
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 5)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("output"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Err(VirtualMachineError::CantSubOffset(5, 26))
        );
    }

    #[test]
    fn compute_blake2s_output_empty_segment() {
        let hint_code = "from starkware.cairo.common.cairo_blake2s.blake2s_utils import compute_blake2s_func\ncompute_blake2s_func(segments=segments, output_ptr=ids.output)".as_bytes();
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory (output)
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 26)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("output"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Err(VirtualMachineError::UnexpectMemoryGap)
        );
    }

    #[test]
    fn compute_blake2s_output_not_relocatable() {
        let hint_code = "from starkware.cairo.common.cairo_blake2s.blake2s_utils import compute_blake2s_func\ncompute_blake2s_func(segments=segments, output_ptr=ids.output)".as_bytes();
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory (output)
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(12)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("output"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Err(VirtualMachineError::ExpectedRelocatable(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn compute_blake2s_output_input_bigger_than_u64() {
        let hint_code = "from starkware.cairo.common.cairo_blake2s.blake2s_utils import compute_blake2s_func\ncompute_blake2s_func(segments=segments, output_ptr=ids.output)".as_bytes();
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory (output)
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 26)),
            )
            .unwrap();
        //Insert big number into output_ptr segment
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from(bigint_i128!(7842562439562793675803603603688959)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("output"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Err(VirtualMachineError::BigintToU64Fail)
        );
    }

    #[test]
    fn compute_blake2s_output_input_relocatable() {
        let hint_code = "from starkware.cairo.common.cairo_blake2s.blake2s_utils import compute_blake2s_func\ncompute_blake2s_func(segments=segments, output_ptr=ids.output)".as_bytes();
        //Create vm
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory (output)
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 26)),
            )
            .unwrap();
        //Insert big number into output_ptr segment
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from((4, 5)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("output"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids, &ApTracking::default()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((4, 5))
            ))
        );
    }
}
