use crate::hint_processor::hint_processor_utils::felt_to_u32;
use std::collections::HashMap;

use num_traits::ToPrimitive;

use super::blake2s_hash::blake2s_compress;
use crate::bigint;
use crate::hint_processor::builtin_hint_processor::blake2s_hash::IV;
use crate::hint_processor::builtin_hint_processor::hint_utils::{
    get_ptr_from_var_name, get_relocatable_from_var_name,
};
use crate::hint_processor::hint_processor_definition::HintReference;
use crate::hint_processor::proxies::memory_proxy::MemoryProxy;
use crate::hint_processor::proxies::vm_proxy::VMProxy;
use crate::serde::deserialize_program::ApTracking;
use crate::types::relocatable::{FieldElement, Relocatable};
use crate::{
    types::relocatable::MaybeRelocatable,
    vm::{
        errors::vm_errors::VirtualMachineError, vm_memory::memory_segments::MemorySegmentManager,
    },
};
use num_bigint::BigInt;

fn get_fixed_size_u32_array<const T: usize>(
    h_range: &Vec<&BigInt>,
) -> Result<[u32; T], VirtualMachineError> {
    let mut u32_vec = Vec::<u32>::with_capacity(h_range.len());
    for num in h_range {
        u32_vec.push(num.to_u32().ok_or(VirtualMachineError::BigintToU32Fail)?);
    }
    u32_vec
        .try_into()
        .map_err(|_| VirtualMachineError::FixedSizeArrayFail(T))
}

fn get_maybe_relocatable_array_from_u32(array: &Vec<u32>) -> Vec<MaybeRelocatable> {
    let mut new_array = Vec::<MaybeRelocatable>::with_capacity(array.len());
    for element in array {
        new_array.push(MaybeRelocatable::from(bigint!(*element)));
    }
    new_array
}

fn get_maybe_relocatable_array_from_bigint(array: &[FieldElement]) -> Vec<MaybeRelocatable> {
    array.iter().map(MaybeRelocatable::from).collect()
}
/*Helper function for the Cairo blake2s() implementation.
Computes the blake2s compress function and fills the value in the right position.
output_ptr should point to the middle of an instance, right after initial_state, message, t, f,
which should all have a value at this point, and right before the output portion which will be
written by this function.*/
fn compute_blake2s_func(
    segments: &mut MemorySegmentManager,
    memory: &mut MemoryProxy,
    output_rel: Relocatable,
) -> Result<(), VirtualMachineError> {
    let h = get_fixed_size_u32_array::<8>(&memory.get_integer_range(&(output_rel.sub(26)?), 8)?)?;
    let message =
        get_fixed_size_u32_array::<16>(&memory.get_integer_range(&(output_rel.sub(18)?), 16)?)?;
    let t = felt_to_u32(memory.get_integer(&output_rel.sub(2)?)?)?;
    let f = felt_to_u32(memory.get_integer(&output_rel.sub(1)?)?)?;
    let new_state =
        get_maybe_relocatable_array_from_u32(&blake2s_compress(&h, &message, t, 0, f, 0));
    let output_ptr = MaybeRelocatable::RelocatableValue(output_rel);
    memory
        .load_data(segments, &output_ptr, new_state)
        .map_err(VirtualMachineError::MemoryError)?;
    Ok(())
}

/* Implements hint:
   from starkware.cairo.common.cairo_blake2s.blake2s_utils import compute_blake2s_func
   compute_blake2s_func(segments=segments, output_ptr=ids.output)
*/
pub fn compute_blake2s(
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let output = get_ptr_from_var_name("output", vm_proxy, ids_data, ap_tracking)?;
    compute_blake2s_func(vm_proxy.segments, &mut vm_proxy.memory, output)
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
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    const N_PACKED_INSTANCES: usize = 7;
    let blake2s_ptr_end =
        get_ptr_from_var_name("blake2s_ptr_end", vm_proxy, ids_data, ap_tracking)?;
    let message: [u32; 16] = [0; 16];
    let mut modified_iv = IV;
    modified_iv[0] = IV[0] ^ 0x01010020;
    let output = blake2s_compress(&modified_iv, &message, 0, 0, 0xffffffff, 0);
    let mut padding = modified_iv.to_vec();
    padding.extend(message);
    padding.extend([0, 0xffffffff]);
    padding.extend(output);
    let padding = padding.as_slice();
    let mut full_padding = Vec::<u32>::with_capacity(padding.len() * N_PACKED_INSTANCES);
    for _ in 0..N_PACKED_INSTANCES - 1 {
        full_padding.extend_from_slice(padding);
    }
    let data = get_maybe_relocatable_array_from_u32(&full_padding);
    vm_proxy
        .memory
        .load_data(
            vm_proxy.segments,
            &MaybeRelocatable::RelocatableValue(blake2s_ptr_end),
            data,
        )
        .map_err(VirtualMachineError::MemoryError)?;
    Ok(())
}

/* Implements Hint:
    B = 32
    MASK = 2 ** 32 - 1
    segments.write_arg(ids.data, [(ids.low >> (B * i)) & MASK for i in range(4)])
    segments.write_arg(ids.data + 4, [(ids.high >> (B * i)) & MASK for i in range(4)])
*/
pub fn blake2s_add_uint256(
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    //Get variables from ids
    let data_ptr = get_ptr_from_var_name("data", vm_proxy, ids_data, ap_tracking)?;
    let low_addr = get_relocatable_from_var_name("low", vm_proxy, ids_data, ap_tracking)?;
    let high_addr = get_relocatable_from_var_name("high", vm_proxy, ids_data, ap_tracking)?;
    let low = vm_proxy.memory.get_integer(&low_addr)?.clone();
    let high = vm_proxy.memory.get_integer(&high_addr)?.clone();
    //Main logic
    //Declare constant
    const MASK: u32 = u32::MAX;
    const B: u32 = 32;
    //Build first batch of data
    let mut inner_data = Vec::<FieldElement>::new();
    for i in 0..4 {
        inner_data.push((&low >> (B * i)) & MASK);
    }
    //Insert first batch of data
    let data = get_maybe_relocatable_array_from_bigint(&inner_data);
    vm_proxy
        .memory
        .load_data(
            vm_proxy.segments,
            &MaybeRelocatable::RelocatableValue(data_ptr.clone()),
            data,
        )
        .map_err(VirtualMachineError::MemoryError)?;
    //Build second batch of data
    let mut inner_data = Vec::<FieldElement>::new();
    for i in 0..4 {
        inner_data.push((&high >> (B * i)) & MASK);
    }
    //Insert second batch of data
    let data = get_maybe_relocatable_array_from_bigint(&inner_data);
    vm_proxy
        .memory
        .load_data(
            vm_proxy.segments,
            &MaybeRelocatable::RelocatableValue(data_ptr).add_usize_mod(4, None),
            data,
        )
        .map_err(VirtualMachineError::MemoryError)?;
    Ok(())
}

/* Implements Hint:
    B = 32
    MASK = 2 ** 32 - 1
    segments.write_arg(ids.data, [(ids.high >> (B * (3 - i))) & MASK for i in range(4)])
    segments.write_arg(ids.data + 4, [(ids.low >> (B * (3 - i))) & MASK for i in range(4)])
*/
pub fn blake2s_add_uint256_bigend(
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    //Get variables from ids
    let data_ptr = get_ptr_from_var_name("data", vm_proxy, ids_data, ap_tracking)?;
    let low_addr = get_relocatable_from_var_name("low", vm_proxy, ids_data, ap_tracking)?;
    let high_addr = get_relocatable_from_var_name("high", vm_proxy, ids_data, ap_tracking)?;
    let low = vm_proxy.memory.get_integer(&low_addr)?.clone();
    let high = vm_proxy.memory.get_integer(&high_addr)?.clone();
    //Main logic
    //Declare constant
    const MASK: u32 = u32::MAX as u32;

    const B: u32 = 32;
    //Build first batch of data
    let mut inner_data = Vec::<FieldElement>::new();
    for i in 0..4 {
        inner_data.push((&high >> (B * (3 - i))) & MASK);
    }
    //Insert first batch of data
    let data = get_maybe_relocatable_array_from_bigint(&inner_data);
    vm_proxy
        .memory
        .load_data(
            vm_proxy.segments,
            &MaybeRelocatable::RelocatableValue(data_ptr.clone()),
            data,
        )
        .map_err(VirtualMachineError::MemoryError)?;
    //Build second batch of data
    let mut inner_data = Vec::<FieldElement>::new();
    for i in 0..4 {
        inner_data.push((&low >> (B * (3 - i))) & MASK);
    }
    //Insert second batch of data
    let data = get_maybe_relocatable_array_from_bigint(&inner_data);
    vm_proxy
        .memory
        .load_data(
            vm_proxy.segments,
            &MaybeRelocatable::RelocatableValue(data_ptr).add_usize_mod(4, None),
            data,
        )
        .map_err(VirtualMachineError::MemoryError)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::any_box;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData;
    use crate::hint_processor::proxies::exec_scopes_proxy::get_exec_scopes_proxy;
    use crate::hint_processor::proxies::vm_proxy::get_vm_proxy;
    use crate::relocatable;
    use crate::types::exec_scope::ExecutionScopes;
    use crate::utils::test_utils::*;
    use crate::vm::vm_core::VirtualMachine;
    use crate::vm::vm_memory::memory::Memory;
    use crate::{bigint, vm::errors::memory_errors::MemoryError};
    use num_bigint::Sign;
    use std::any::Any;

    use crate::hint_processor::hint_processor_definition::HintProcessor;

    #[test]
    fn compute_blake2s_output_offset_zero() {
        let hint_code = "from starkware.cairo.common.cairo_blake2s.blake2s_utils import compute_blake2s_func\ncompute_blake2s_func(segments=segments, output_ptr=ids.output)";
        //Create vm
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 1;
        //Insert ids into memory (output)
        vm.memory = memory![((1, 0), (2, 5))];
        //Create hint data
        let ids_data = ids_data!["output"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::CantSubOffset(5, 26))
        );
    }

    #[test]
    fn compute_blake2s_output_empty_segment() {
        let hint_code = "from starkware.cairo.common.cairo_blake2s.blake2s_utils import compute_blake2s_func\ncompute_blake2s_func(segments=segments, output_ptr=ids.output)";
        //Create vm
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 1;
        //Insert ids into memory (output)
        vm.memory = memory![((1, 0), (2, 26))];
        add_segments!(vm, 1);
        //Create hint data
        let ids_data = ids_data!["output"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((2, 0))
            ))
        );
    }

    #[test]
    fn compute_blake2s_output_not_relocatable() {
        let hint_code = "from starkware.cairo.common.cairo_blake2s.blake2s_utils import compute_blake2s_func\ncompute_blake2s_func(segments=segments, output_ptr=ids.output)";
        //Create vm
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 1;
        //Insert ids into memory (output)
        vm.memory = memory![((1, 0), 12)];
        //Create hint data
        let ids_data = ids_data!["output"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ExpectedRelocatable(
                MaybeRelocatable::from((1, 0))
            ))
        );
    }

    #[test]
    fn compute_blake2s_output_input_bigger_than_u32() {
        let hint_code = "from starkware.cairo.common.cairo_blake2s.blake2s_utils import compute_blake2s_func\ncompute_blake2s_func(segments=segments, output_ptr=ids.output)";
        //Create vm
        let mut vm = vm!();
        //Initialize fp
        //Insert ids into memory
        vm.run_context.fp = 1;
        vm.memory = memory![
            ((1, 0), (2, 26)),
            ((2, 0), 7842562439562793675803603603688959_i128),
            ((2, 1), 7842562439562793675803603603688959_i128),
            ((2, 2), 7842562439562793675803603603688959_i128),
            ((2, 3), 7842562439562793675803603603688959_i128),
            ((2, 4), 7842562439562793675803603603688959_i128),
            ((2, 5), 7842562439562793675803603603688959_i128),
            ((2, 6), 7842562439562793675803603603688959_i128),
            ((2, 7), 7842562439562793675803603603688959_i128)
        ];
        //Create hint data
        let ids_data = ids_data!["output"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::BigintToU32Fail)
        );
    }

    #[test]
    fn compute_blake2s_output_input_relocatable() {
        let hint_code = "from starkware.cairo.common.cairo_blake2s.blake2s_utils import compute_blake2s_func\ncompute_blake2s_func(segments=segments, output_ptr=ids.output)";
        //Create vm
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 1;
        //Insert ids into memory (output)
        vm.memory = memory![((1, 0), (2, 26)), ((2, 0), (5, 5))];
        //Create hint data
        let ids_data = ids_data!["output"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((2, 0))
            ))
        );
    }

    #[test]
    fn finalize_blake2s_valid() {
        let hint_code = "# Add dummy pairs of input and output.\nfrom starkware.cairo.common.cairo_blake2s.blake2s_utils import IV, blake2s_compress\n\n_n_packed_instances = int(ids.N_PACKED_INSTANCES)\nassert 0 <= _n_packed_instances < 20\n_blake2s_input_chunk_size_felts = int(ids.INPUT_BLOCK_FELTS)\nassert 0 <= _blake2s_input_chunk_size_felts < 100\n\nmessage = [0] * _blake2s_input_chunk_size_felts\nmodified_iv = [IV[0] ^ 0x01010020] + IV[1:]\noutput = blake2s_compress(\n    message=message,\n    h=modified_iv,\n    t0=0,\n    t1=0,\n    f0=0xffffffff,\n    f1=0,\n)\npadding = (modified_iv + message + [0, 0xffffffff] + output) * (_n_packed_instances - 1)\nsegments.write_arg(ids.blake2s_ptr_end, padding)";
        //Create vm
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 1;
        //Insert ids into memory (output)
        vm.memory = memory![((1, 0), (2, 0))];
        add_segments!(vm, 1);
        //Create hint data
        let ids_data = ids_data!["blake2s_ptr_end"];
        //Execute the hint
        assert_eq!(run_hint!(vm, ids_data, hint_code), Ok(()));
        //Check the inserted data
        let expected_data: [u32; 204] = [
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
        let data = get_fixed_size_u32_array::<204>(
            &vm.memory
                .get_integer_range(&relocatable!(2, 0), 204)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(expected_data, data);
    }

    #[test]
    fn finalize_blake2s_invalid_segment_taken() {
        let hint_code = "# Add dummy pairs of input and output.\nfrom starkware.cairo.common.cairo_blake2s.blake2s_utils import IV, blake2s_compress\n\n_n_packed_instances = int(ids.N_PACKED_INSTANCES)\nassert 0 <= _n_packed_instances < 20\n_blake2s_input_chunk_size_felts = int(ids.INPUT_BLOCK_FELTS)\nassert 0 <= _blake2s_input_chunk_size_felts < 100\n\nmessage = [0] * _blake2s_input_chunk_size_felts\nmodified_iv = [IV[0] ^ 0x01010020] + IV[1:]\noutput = blake2s_compress(\n    message=message,\n    h=modified_iv,\n    t0=0,\n    t1=0,\n    f0=0xffffffff,\n    f1=0,\n)\npadding = (modified_iv + message + [0, 0xffffffff] + output) * (_n_packed_instances - 1)\nsegments.write_arg(ids.blake2s_ptr_end, padding)";
        //Create vm
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 1;
        //Insert ids into memory (output)
        vm.memory = memory![((1, 0), (2, 0)), ((2, 0), (2, 0))];
        let ids_data = ids_data!["blake2s_ptr_end"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((2, 0)),
                    MaybeRelocatable::from((2, 0)),
                    MaybeRelocatable::from(bigint!(1795745351))
                )
            ))
        );
    }

    #[test]
    fn finalize_blake2s_invalid_no_ids() {
        let hint_code = "# Add dummy pairs of input and output.\nfrom starkware.cairo.common.cairo_blake2s.blake2s_utils import IV, blake2s_compress\n\n_n_packed_instances = int(ids.N_PACKED_INSTANCES)\nassert 0 <= _n_packed_instances < 20\n_blake2s_input_chunk_size_felts = int(ids.INPUT_BLOCK_FELTS)\nassert 0 <= _blake2s_input_chunk_size_felts < 100\n\nmessage = [0] * _blake2s_input_chunk_size_felts\nmodified_iv = [IV[0] ^ 0x01010020] + IV[1:]\noutput = blake2s_compress(\n    message=message,\n    h=modified_iv,\n    t0=0,\n    t1=0,\n    f0=0xffffffff,\n    f1=0,\n)\npadding = (modified_iv + message + [0, 0xffffffff] + output) * (_n_packed_instances - 1)\nsegments.write_arg(ids.blake2s_ptr_end, padding)";
        //Create vm
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 1;
        //Execute the hint
        assert_eq!(
            run_hint!(vm, HashMap::new(), hint_code),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn blake2s_add_uint256_valid_zero() {
        let hint_code = "B = 32\nMASK = 2 ** 32 - 1\nsegments.write_arg(ids.data, [(ids.low >> (B * i)) & MASK for i in range(4)])\nsegments.write_arg(ids.data + 4, [(ids.high >> (B * i)) & MASK for i in range(4)]";
        //Create vm
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 3;
        //Insert ids into memory
        vm.memory = memory![((1, 0), (2, 0)), ((1, 1), 0), ((1, 2), 0)];
        vm.segments.add(&mut vm.memory);
        let ids_data = ids_data!["data", "high", "low"];
        //Execute the hint
        assert_eq!(run_hint!(vm, ids_data, hint_code), Ok(()));
        //Check data ptr
        check_memory![
            vm.memory,
            ((2, 0), 0),
            ((2, 1), 0),
            ((2, 2), 0),
            ((2, 3), 0),
            ((2, 4), 0),
            ((2, 5), 0),
            ((2, 6), 0),
            ((2, 7), 0)
        ];
        assert_eq!(vm.memory.get(&MaybeRelocatable::from((2, 8))), Ok(None));
    }

    #[test]
    fn blake2s_add_uint256_valid_non_zero() {
        let hint_code = "B = 32\nMASK = 2 ** 32 - 1\nsegments.write_arg(ids.data, [(ids.low >> (B * i)) & MASK for i in range(4)])\nsegments.write_arg(ids.data + 4, [(ids.high >> (B * i)) & MASK for i in range(4)]";
        //Create vm
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 3;
        //Insert ids into memory
        vm.memory = memory![((1, 0), (2, 0)), ((1, 1), 25), ((1, 2), 20)];
        vm.segments.add(&mut vm.memory);
        let ids_data = ids_data!["data", "high", "low"];
        //Execute the hint
        assert_eq!(run_hint!(vm, ids_data, hint_code), Ok(()));
        //Check data ptr
        check_memory![
            vm.memory,
            ((2, 0), 20),
            ((2, 1), 0),
            ((2, 2), 0),
            ((2, 3), 0),
            ((2, 4), 25),
            ((2, 5), 0),
            ((2, 6), 0),
            ((2, 7), 0)
        ];
        assert_eq!(vm.memory.get(&MaybeRelocatable::from((2, 8))), Ok(None));
    }

    #[test]
    fn blake2s_add_uint256_bigend_valid_zero() {
        let hint_code = "B = 32\nMASK = 2 ** 32 - 1\nsegments.write_arg(ids.data, [(ids.high >> (B * (3 - i))) & MASK for i in range(4)])\nsegments.write_arg(ids.data + 4, [(ids.low >> (B * (3 - i))) & MASK for i in range(4)])";
        //Create vm
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 3;
        //Insert ids into memory
        vm.memory = memory![((1, 0), (2, 0)), ((1, 1), 0), ((1, 2), 0)];
        add_segments!(vm, 1);
        let ids_data = ids_data!["data", "high", "low"];
        //Execute the hint
        assert_eq!(run_hint!(vm, ids_data, hint_code), Ok(()));
        //Check data ptr
        check_memory![
            vm.memory,
            ((2, 0), 0),
            ((2, 1), 0),
            ((2, 2), 0),
            ((2, 3), 0),
            ((2, 4), 0),
            ((2, 5), 0),
            ((2, 6), 0),
            ((2, 7), 0)
        ];
        assert_eq!(vm.memory.get(&MaybeRelocatable::from((2, 8))), Ok(None));
    }

    #[test]
    fn blake2s_add_uint256_bigend_valid_non_zero() {
        let hint_code = "B = 32\nMASK = 2 ** 32 - 1\nsegments.write_arg(ids.data, [(ids.high >> (B * (3 - i))) & MASK for i in range(4)])\nsegments.write_arg(ids.data + 4, [(ids.low >> (B * (3 - i))) & MASK for i in range(4)])";
        //Create vm
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 3;
        //Insert ids into memory
        vm.memory = memory![((1, 0), (2, 0)), ((1, 1), 25), ((1, 2), 20)];
        vm.segments.add(&mut vm.memory);
        let ids_data = ids_data!["data", "high", "low"];
        //Execute the hint
        assert_eq!(run_hint!(vm, ids_data, hint_code), Ok(()));
        //Check data ptr
        check_memory![
            vm.memory,
            ((2, 0), 0),
            ((2, 1), 0),
            ((2, 2), 0),
            ((2, 3), 25),
            ((2, 4), 0),
            ((2, 5), 0),
            ((2, 6), 0),
            ((2, 7), 20)
        ];
        assert_eq!(vm.memory.get(&MaybeRelocatable::from((2, 8))), Ok(None));
    }
}
