use std::collections::HashMap;

use num_traits::ToPrimitive;

use super::blake2s_hash::blake2s_compress;
use super::hint_utils::get_ptr_from_var_name;
use crate::bigint_u64;
use crate::serde::deserialize_program::ApTracking;
use crate::types::relocatable::Relocatable;
use crate::vm::hints::blake2s_hash::IV;
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
    h_range: Vec<Option<&MaybeRelocatable>>,
) -> Result<[u64; T], VirtualMachineError> {
    let mut u64_vec = Vec::<u64>::new();
    for element in h_range {
        let mayberel = element.ok_or(VirtualMachineError::UnexpectMemoryGap)?;
        let num = if let MaybeRelocatable::Int(num) = mayberel {
            num
        } else {
            return Err(VirtualMachineError::ExpectedInteger(mayberel.clone()));
        };
        u64_vec.push(num.to_u64().ok_or(VirtualMachineError::BigintToU64Fail)?);
    }
    u64_vec
        .try_into()
        .map_err(|_| VirtualMachineError::FixedSizeArrayFail(T))
}

fn get_maybe_relocatable_array_from_u64(array: Vec<u64>) -> Vec<MaybeRelocatable> {
    let mut new_array = Vec::<MaybeRelocatable>::new();
    for element in array {
        new_array.push(MaybeRelocatable::from(bigint_u64!(element)));
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
    let output_ptr = MaybeRelocatable::RelocatableValue(output_rel);
    let h = get_fixed_size_u64_array::<8>(
        memory
            .get_range(&output_ptr.sub_usize_mod(26, None)?, 8)
            .map_err(VirtualMachineError::MemoryError)?,
    )?;
    let message = get_fixed_size_u64_array::<16>(
        memory
            .get_range(&output_ptr.sub_usize_mod(18, None)?, 16)
            .map_err(VirtualMachineError::MemoryError)?,
    )?;
    let t = memory
        .get_integer_from_maybe_relocatable(&output_ptr.sub_usize_mod(2, None)?)?
        .to_u64()
        .ok_or(VirtualMachineError::BigintToU64Fail)?;
    let f = memory
        .get_integer_from_maybe_relocatable(&output_ptr.sub_usize_mod(1, None)?)?
        .to_u64()
        .ok_or(VirtualMachineError::BigintToU64Fail)?;
    let new_state = get_maybe_relocatable_array_from_u64(blake2s_compress(h, message, t, 0, f, 0));
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

/* Implements Hint:
    # Add dummy pairs of input and output.
    from starkware.cairo.common.cairo_blake2s.blake2s_utils import IV, blake2s_compress

    _n_packed_instances = int(ids.N_PACKED_INSTANCES)
    assert 0 <= _n_packed_instances < 20
    _blake2s_input_chunk_size_felts = int(ids.INPUT_BLOCK_FELTS)
    assert 0 <= _blake2s_input_chunk_size_felts < 100

    message = [0] * _blake2s_input_chunk_size_felts
    modified_iv = [IV[0] ^ 0x01010020] + IV[1:]
    output = blake2s_compress(
        message=message,
        h=modified_iv,
        t0=0,
        t1=0,
        f0=0xffffffff,
        f1=0,
    )
    padding = (modified_iv + message + [0, 0xffffffff] + output) * (_n_packed_instances - 1)
    segments.write_arg(ids.blake2s_ptr_end, padding)
*/
pub fn finalize_blake2s(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let blake2s_ptr_end = get_ptr_from_var_name("blake2s_ptr_end", &ids, vm, hint_ap_tracking)?;
    const N_PACKED_INSTANCES: usize = 7;
    let message: [u64; 16] = [0; 16];
    let mut modified_iv = IV;
    modified_iv[0] = IV[0] ^ 0x01010020;
    let output = blake2s_compress(modified_iv, message, 0, 0, 0xffffffff, 0);
    let mut padding = modified_iv.to_vec();
    padding.extend(message);
    padding.extend([0, 0xffffffff]);
    padding.extend(output);
    let padding_copy = padding.clone();
    for _ in 1..N_PACKED_INSTANCES - 1 {
        padding.extend(padding_copy.clone());
    }
    let data = get_maybe_relocatable_array_from_u64(padding);
    vm.segments
        .load_data(
            &mut vm.memory,
            &MaybeRelocatable::RelocatableValue(blake2s_ptr_end),
            data,
        )
        .map_err(VirtualMachineError::MemoryError)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use num_bigint::Sign;

    use super::*;
    use crate::{
        bigint, bigint_i128,
        types::instruction::Register,
        vm::{
            errors::memory_errors::MemoryError,
            hints::execute_hint::{execute_hint, HintReference},
        },
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

    #[test]
    fn finalize_blake2s_valid() {
        let hint_code = "# Add dummy pairs of input and output.\nfrom starkware.cairo.common.cairo_blake2s.blake2s_utils import IV, blake2s_compress\n\n_n_packed_instances = int(ids.N_PACKED_INSTANCES)\nassert 0 <= _n_packed_instances < 20\n_blake2s_input_chunk_size_felts = int(ids.INPUT_BLOCK_FELTS)\nassert 0 <= _blake2s_input_chunk_size_felts < 100\n\nmessage = [0] * _blake2s_input_chunk_size_felts\nmodified_iv = [IV[0] ^ 0x01010020] + IV[1:]\noutput = blake2s_compress(\n    message=message,\n    h=modified_iv,\n    t0=0,\n    t1=0,\n    f0=0xffffffff,\n    f1=0,\n)\npadding = (modified_iv + message + [0, 0xffffffff] + output) * (_n_packed_instances - 1)\nsegments.write_arg(ids.blake2s_ptr_end, padding)".as_bytes();
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
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("blake2s_ptr_end"), bigint!(0));
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
            Ok(())
        );
        //Check the inserted data
        let expected_data: [u64; 204] = [
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4294967295, 813310313,
            2491453561, 3491828193, 2085238082, 1219908895, 514171180, 4245497115, 4193177630,
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4294967295, 813310313,
            2491453561, 3491828193, 2085238082, 1219908895, 514171180, 4245497115, 4193177630,
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4294967295, 813310313,
            2491453561, 3491828193, 2085238082, 1219908895, 514171180, 4245497115, 4193177630,
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4294967295, 813310313,
            2491453561, 3491828193, 2085238082, 1219908895, 514171180, 4245497115, 4193177630,
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4294967295, 813310313,
            2491453561, 3491828193, 2085238082, 1219908895, 514171180, 4245497115, 4193177630,
            1795745351, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635,
            1541459225, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4294967295, 813310313,
            2491453561, 3491828193, 2085238082, 1219908895, 514171180, 4245497115, 4193177630,
        ];
        //Get data from memory
        let data = get_fixed_size_u64_array::<204>(
            vm.memory
                .get_range(&MaybeRelocatable::from((1, 0)), 204)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(expected_data, data);
    }

    #[test]
    fn finalize_blake2s_invalid_segment_taken() {
        let hint_code = "# Add dummy pairs of input and output.\nfrom starkware.cairo.common.cairo_blake2s.blake2s_utils import IV, blake2s_compress\n\n_n_packed_instances = int(ids.N_PACKED_INSTANCES)\nassert 0 <= _n_packed_instances < 20\n_blake2s_input_chunk_size_felts = int(ids.INPUT_BLOCK_FELTS)\nassert 0 <= _blake2s_input_chunk_size_felts < 100\n\nmessage = [0] * _blake2s_input_chunk_size_felts\nmodified_iv = [IV[0] ^ 0x01010020] + IV[1:]\noutput = blake2s_compress(\n    message=message,\n    h=modified_iv,\n    t0=0,\n    t1=0,\n    f0=0xffffffff,\n    f1=0,\n)\npadding = (modified_iv + message + [0, 0xffffffff] + output) * (_n_packed_instances - 1)\nsegments.write_arg(ids.blake2s_ptr_end, padding)".as_bytes();
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
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Insert data into blake2s segment
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("blake2s_ptr_end"), bigint!(0));
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
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((1, 0)),
                    MaybeRelocatable::from((1, 0)),
                    MaybeRelocatable::from(bigint_u64!(1795745351))
                )
            ))
        );
    }

    #[test]
    fn finalize_blake2s_invalid_segment_no_ids() {
        let hint_code = "# Add dummy pairs of input and output.\nfrom starkware.cairo.common.cairo_blake2s.blake2s_utils import IV, blake2s_compress\n\n_n_packed_instances = int(ids.N_PACKED_INSTANCES)\nassert 0 <= _n_packed_instances < 20\n_blake2s_input_chunk_size_felts = int(ids.INPUT_BLOCK_FELTS)\nassert 0 <= _blake2s_input_chunk_size_felts < 100\n\nmessage = [0] * _blake2s_input_chunk_size_felts\nmodified_iv = [IV[0] ^ 0x01010020] + IV[1:]\noutput = blake2s_compress(\n    message=message,\n    h=modified_iv,\n    t0=0,\n    t1=0,\n    f0=0xffffffff,\n    f1=0,\n)\npadding = (modified_iv + message + [0, 0xffffffff] + output) * (_n_packed_instances - 1)\nsegments.write_arg(ids.blake2s_ptr_end, padding)".as_bytes();
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
            execute_hint(&mut vm, hint_code, HashMap::new(), &ApTracking::default()),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }
}
