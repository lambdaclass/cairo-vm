use crate::{
    bigint,
    serde::deserialize_program::ApTracking,
    vm::{
        errors::vm_errors::VirtualMachineError,
        hints::hint_utils::{
            bigint_to_u32, get_integer_from_var_name, get_ptr_from_var_name,
            get_relocatable_from_var_name, insert_value_from_var_name,
        },
        vm_core::VirtualMachine,
    },
};

use generic_array::GenericArray;
use num_bigint::BigInt;
use num_traits::{One, Zero};
use sha2::compress256;
use std::collections::HashMap;

const SHA256_INPUT_CHUNK_SIZE_FELTS: usize = 16;
const SHA256_STATE_SIZE_FELTS: usize = 8;
const BLOCK_SIZE: usize = 7;

pub fn sha256_input(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let n_bytes = get_integer_from_var_name(
        "n_bytes",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let full_word = if n_bytes >= &bigint!(4) {
        BigInt::one()
    } else {
        BigInt::zero()
    };

    insert_value_from_var_name(
        "full_word",
        full_word,
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )
}

pub fn sha256_main(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    if SHA256_INPUT_CHUNK_SIZE_FELTS >= 100 {
        return Err(VirtualMachineError::ShaInputChunkOutOfBounds(
            SHA256_INPUT_CHUNK_SIZE_FELTS,
        ));
    }

    let sha256_start = get_relocatable_from_var_name(
        "sha256_start",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;

    let input_ptr = vm.memory.get_relocatable(&sha256_start)?;

    let mut message: Vec<u8> = Vec::new();

    for i in 0..SHA256_INPUT_CHUNK_SIZE_FELTS {
        message.extend(bigint_to_u32(vm.memory.get_integer(&(input_ptr + i))?)?.to_be_bytes());
    }

    let mut iv: [u32; SHA256_STATE_SIZE_FELTS] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];

    let new_message = GenericArray::clone_from_slice(&message);
    compress256(&mut iv, &[new_message]);

    let mut output: Vec<BigInt> = Vec::with_capacity(SHA256_STATE_SIZE_FELTS);

    for i in 0..SHA256_STATE_SIZE_FELTS {
        output.push(bigint!(iv[i]));
    }

    let output_base = get_ptr_from_var_name(
        "output",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;

    vm.segments
        .write_arg(&mut vm.memory, &output_base, &output, Some(&vm.prime))
        .map_err(VirtualMachineError::MemoryError)?;
    Ok(())
}

pub fn sha256_finalize(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    if BLOCK_SIZE >= 20 {
        return Err(VirtualMachineError::BlockSizeOutOfBounds(BLOCK_SIZE));
    }
    if SHA256_INPUT_CHUNK_SIZE_FELTS >= 100 {
        return Err(VirtualMachineError::ShaInputChunkOutOfBounds(
            SHA256_INPUT_CHUNK_SIZE_FELTS,
        ));
    }

    let message: Vec<u8> = vec![0; 64];

    let mut iv: [u32; SHA256_STATE_SIZE_FELTS] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];

    let iv_static: Vec<BigInt> = iv.iter().map(|n| bigint!(*n)).collect();

    let new_message = GenericArray::clone_from_slice(&message);
    compress256(&mut iv, &[new_message]);

    let mut output: Vec<BigInt> = Vec::with_capacity(SHA256_STATE_SIZE_FELTS);

    for i in 0..SHA256_STATE_SIZE_FELTS {
        output.push(bigint!(iv[i]));
    }

    let sha256_ptr_end = get_ptr_from_var_name(
        "sha256_ptr_end",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;

    let mut padding: Vec<BigInt> = Vec::new();

    for _ in 0..BLOCK_SIZE - 1 {
        padding.extend(vec![BigInt::zero(); 16]);
        padding.extend(iv_static.clone());
        padding.extend(output.clone());
    }

    vm.segments
        .write_arg(&mut vm.memory, &sha256_ptr_end, &padding, Some(&vm.prime))
        .map_err(VirtualMachineError::MemoryError)?;
    Ok(())
}
