use crate::{
    hint_processor::{
        builtin_hint_processor::hint_utils::{
            get_integer_from_var_name, get_ptr_from_var_name, get_relocatable_from_var_name,
        },
        hint_processor_definition::HintReference,
    },
    serde::deserialize_program::ApTracking,
    types::{exec_scope::ExecutionScopes, relocatable::Relocatable},
    vm::{errors::hint_errors::HintError, vm_core::VirtualMachine},
};
use felt::Felt;
use num_integer::Integer;
use num_traits::{One, Pow, Signed, ToPrimitive};
use sha3::{Digest, Keccak256};
use std::{cmp, collections::HashMap, ops::Shl};

use super::hint_utils::insert_value_from_var_name;

/* Implements hint:
   %{
       from eth_hash.auto import keccak

       data, length = ids.data, ids.length

       if '__keccak_max_size' in globals():
           assert length <= __keccak_max_size, \
               f'unsafe_keccak() can only be used with length<={__keccak_max_size}. ' \
               f'Got: length={length}.'

       keccak_input = bytearray()
       for word_i, byte_i in enumerate(range(0, length, 16)):
           word = memory[data + word_i]
           n_bytes = min(16, length - byte_i)
           assert 0 <= word < 2 ** (8 * n_bytes)
           keccak_input += word.to_bytes(n_bytes, 'big')

       hashed = keccak(keccak_input)
       ids.high = int.from_bytes(hashed[:16], 'big')
       ids.low = int.from_bytes(hashed[16:32], 'big')
   %}
*/
pub fn unsafe_keccak(
    vm: &mut VirtualMachine,
    exec_scopes: &mut ExecutionScopes,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    let length = get_integer_from_var_name("length", vm, ids_data, ap_tracking)?;

    if let Ok(keccak_max_size) = exec_scopes.get::<Felt>("__keccak_max_size") {
        if length.as_ref() > &keccak_max_size {
            return Err(HintError::KeccakMaxSize(
                length.into_owned(),
                keccak_max_size,
            ));
        }
    }

    // `data` is an array, represented by a pointer to the first element.
    let data = get_ptr_from_var_name("data", vm, ids_data, ap_tracking)?;

    let high_addr = get_relocatable_from_var_name("high", vm, ids_data, ap_tracking)?;
    let low_addr = get_relocatable_from_var_name("low", vm, ids_data, ap_tracking)?;

    // transform to u64 to make ranges cleaner in the for loop below
    let u64_length = length
        .to_u64()
        .ok_or_else(|| HintError::InvalidKeccakInputLength(length.into_owned()))?;

    let mut keccak_input = Vec::new();
    for (word_i, byte_i) in (0..u64_length).step_by(16).enumerate() {
        let word_addr = Relocatable {
            segment_index: data.segment_index,
            offset: data.offset + word_i,
        };

        let word = vm.get_integer(word_addr)?;
        let n_bytes = cmp::min(16, u64_length - byte_i);

        if word.is_negative() || word.as_ref() >= &Felt::one().shl(8 * (n_bytes as u32)) {
            return Err(HintError::InvalidWordSize(word.into_owned()));
        }

        let mut bytes = word.to_bytes_be();
        let mut bytes = {
            let n_word_bytes = &bytes.len();
            left_pad(&mut bytes, n_bytes as usize - n_word_bytes)
        };

        keccak_input.append(&mut bytes);
    }

    let mut hasher = Keccak256::new();
    hasher.update(keccak_input);

    let hashed = hasher.finalize();

    let high = Felt::from_bytes_be(&hashed[..16]);
    let low = Felt::from_bytes_be(&hashed[16..32]);

    vm.insert_value(high_addr, &high)?;
    vm.insert_value(low_addr, &low)?;
    Ok(())
}

/*
Implements hint:

    %{
        from eth_hash.auto import keccak
        keccak_input = bytearray()
        n_elms = ids.keccak_state.end_ptr - ids.keccak_state.start_ptr
        for word in memory.get_range(ids.keccak_state.start_ptr, n_elms):
            keccak_input += word.to_bytes(16, 'big')
        hashed = keccak(keccak_input)
        ids.high = int.from_bytes(hashed[:16], 'big')
        ids.low = int.from_bytes(hashed[16:32], 'big')
    %}

 */
pub fn unsafe_keccak_finalize(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    /* -----------------------------
    Just for reference (cairo code):
    struct KeccakState:
        member start_ptr : felt*
        member end_ptr : felt*
    end
    ----------------------------- */

    let keccak_state_ptr =
        get_relocatable_from_var_name("keccak_state", vm, ids_data, ap_tracking)?;

    // as `keccak_state` is a struct, the pointer to the struct is the same as the pointer to the first element.
    // this is why to get the pointer stored in the field `start_ptr` it is enough to pass the variable name as
    // `keccak_state`, which is the one that appears in the reference manager of the compiled JSON.
    let start_ptr = get_ptr_from_var_name("keccak_state", vm, ids_data, ap_tracking)?;

    // in the KeccakState struct, the field `end_ptr` is the second one, so this variable should be get from
    // the memory cell contiguous to the one where KeccakState is pointing to.
    let end_ptr = vm.get_relocatable(Relocatable {
        segment_index: keccak_state_ptr.segment_index,
        offset: keccak_state_ptr.offset + 1,
    })?;

    let n_elems = (end_ptr - start_ptr)?;

    let mut keccak_input = Vec::new();
    let range = vm.get_integer_range(start_ptr, n_elems)?;

    for word in range.into_iter() {
        let mut bytes = word.to_bytes_be();
        let mut bytes = {
            let n_word_bytes = &bytes.len();
            left_pad(&mut bytes, 16 - n_word_bytes)
        };
        keccak_input.append(&mut bytes);
    }

    let mut hasher = Keccak256::new();
    hasher.update(keccak_input);

    let hashed = hasher.finalize();

    let high_addr = get_relocatable_from_var_name("high", vm, ids_data, ap_tracking)?;
    let low_addr = get_relocatable_from_var_name("low", vm, ids_data, ap_tracking)?;

    let high = Felt::from_bytes_be(&hashed[..16]);
    let low = Felt::from_bytes_be(&hashed[16..32]);

    vm.insert_value(high_addr, &high)?;
    vm.insert_value(low_addr, &low)?;
    Ok(())
}

fn left_pad(bytes_vector: &mut [u8], n_zeros: usize) -> Vec<u8> {
    let mut res: Vec<u8> = vec![0; n_zeros];
    res.extend(bytes_vector.iter());

    res
}

// Implements hint: ids.output0_low = ids.output0 & ((1 << 128) - 1)
// ids.output0_high = ids.output0 >> 128
pub fn split_output(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    num: u32,
) -> Result<(), HintError> {
    let output_name = format!("output{}", num);
    let output_cow = get_integer_from_var_name(&output_name, vm, ids_data, ap_tracking)?;
    let output = output_cow.as_ref();
    let low = output & ((Felt::one() << 128_u32) - 1_u32);
    let high = output >> 128;
    insert_value_from_var_name(
        &format!("output{}_high", num),
        high,
        vm,
        ids_data,
        ap_tracking,
    )?;
    insert_value_from_var_name(
        &format!("output{}_low", num),
        low,
        vm,
        ids_data,
        ap_tracking,
    )
}

// Implements hints of type: ids.high{input_key}, ids.low{input_key} = divmod(memory[ids.inputs + {input_key}], 256 ** {exponent})
pub fn split_input(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    input_key: usize,
    exponent: u32,
) -> Result<(), HintError> {
    let inputs_ptr = get_ptr_from_var_name("inputs", vm, ids_data, ap_tracking)?;
    let binding = vm.get_integer((inputs_ptr + input_key)?)?;
    let third_input = binding.as_ref();
    let (high, low) = third_input.div_rem(&Felt::from(256.pow(exponent)));
    insert_value_from_var_name(
        &format!("high{}", input_key),
        high,
        vm,
        ids_data,
        ap_tracking,
    )?;
    insert_value_from_var_name(&format!("low{}", input_key), low, vm, ids_data, ap_tracking)
}
