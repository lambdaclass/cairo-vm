use super::hint_utils::{
    get_int_from_scope, get_integer_from_var_name, get_ptr_from_var_name,
    get_relocatable_from_var_name,
};
use crate::types::relocatable::MaybeRelocatable;
use crate::{
    bigint,
    serde::deserialize_program::ApTracking,
    types::relocatable::Relocatable,
    vm::{errors::vm_errors::VirtualMachineError, vm_core::VirtualMachine},
};
use num_bigint::{BigInt, Sign};
use num_traits::FromPrimitive;
use num_traits::Signed;
use num_traits::ToPrimitive;
use sha3::{Digest, Keccak256};
use std::{cmp, collections::HashMap, ops::Shl};

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
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
<<<<<<< HEAD
    let length = get_integer_from_var_name("length", &ids, vm, hint_ap_tracking)?.clone();
=======
    let length = get_integer_from_var_name("length", &ids, vm, hint_ap_tracking)?
        .clone();
>>>>>>> Small refacator in unsafe_keccak

    if let Some(keccak_max_size) = get_int_from_scope(vm, "__keccak_max_size") {
        if length > keccak_max_size {
            return Err(VirtualMachineError::KeccakMaxSize(length, keccak_max_size));
        }
    }

    // `data` is an array, represented by a pointer to the first element.
    let data = get_ptr_from_var_name("data", &ids, vm, hint_ap_tracking)?;

    let high_addr = get_relocatable_from_var_name("high", &ids, vm, hint_ap_tracking)?;
    let low_addr = get_relocatable_from_var_name("low", &ids, vm, hint_ap_tracking)?;

    // transform to u64 to make ranges cleaner in the for loop below
    let u64_length = length
        .to_u64()
        .ok_or(VirtualMachineError::InvalidKeccakInputLength(length))?;

    let mut keccak_input = Vec::new();
    for (word_i, byte_i) in (0..u64_length).step_by(16).enumerate() {
        let word_addr = Relocatable {
            segment_index: data.segment_index,
            offset: data.offset + word_i,
        };

        let word = vm.memory.get_integer(&word_addr)?;
        let n_bytes = cmp::min(16, u64_length - byte_i);

        if word.is_negative() || word >= &bigint!(1).shl(8 * (n_bytes as u32)) {
            return Err(VirtualMachineError::InvalidWordSize(word.clone()));
        }

        let (_, mut bytes) = word.to_bytes_be();
        let mut bytes = {
            let n_word_bytes = &bytes.len();
            left_pad(&mut bytes, (n_bytes as usize - n_word_bytes) as usize)
        };

        keccak_input.append(&mut bytes);
    }

    let mut hasher = Keccak256::new();
    hasher.update(keccak_input);

    let hashed = hasher.finalize();

    let high = BigInt::from_bytes_be(Sign::Plus, &hashed[..16]);
    let low = BigInt::from_bytes_be(Sign::Plus, &hashed[16..32]);

    match (
        vm.memory.insert(
            &MaybeRelocatable::RelocatableValue(high_addr),
            &MaybeRelocatable::Int(high),
        ),
        vm.memory.insert(
            &MaybeRelocatable::RelocatableValue(low_addr),
            &MaybeRelocatable::Int(low),
        ),
    ) {
        (Ok(_), Ok(_)) => Ok(()),
        (Err(error), _) | (_, Err(error)) => Err(VirtualMachineError::MemoryError(error)),
    }
}

fn left_pad(bytes_vector: &mut [u8], n_zeros: usize) -> Vec<u8> {
    let mut res: Vec<u8> = vec![0; n_zeros];
    res.extend(bytes_vector.iter());

    res
}
