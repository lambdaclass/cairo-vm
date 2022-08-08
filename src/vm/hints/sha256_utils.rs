use crate::{
    bigint, bigint_str,
    serde::deserialize_program::ApTracking,
    vm::{
        vm_core::VirtualMachine,
        errors::vm_errors::VirtualMachineError,
        hints::hint_utils::{get_integer_from_var_name, get_relocatable_from_var_name, insert_value_from_var_name},
    }
};

use num_bigint::BigInt;
use num_traits::{Zero, One};
use std::collections::HashMap;
use sha256::digest_bytes;

const SHA256_INPUT_CHUNK_SIZE_FELTS: usize = 16;

pub fn sha256_input(vm: &mut VirtualMachine, ids: &HashMap<String, BigInt>, hint_ap_tracking: Option<&ApTracking>) -> Result<(), VirtualMachineError> {
    let n_bytes = get_integer_from_var_name("n_bytes", ids, &vm.memory, &vm.references, &vm.run_context, hint_ap_tracking)?;
    let full_word = if n_bytes >= &bigint!(4) {
        BigInt::one() 
    } else {
        BigInt::zero()
    };

    insert_value_from_var_name("full_word", full_word, ids, &mut vm.memory, &vm.references, &vm.run_context, hint_ap_tracking)
}

pub fn sha256_main(vm: &mut VirtualMachine, ids: &HashMap<String, BigInt>, hint_ap_tracking: Option<&ApTracking>) -> Result<(), VirtualMachineError> {
    const BYTE_STEP: usize = 8;
    const STRING_SIZE_SHA: usize = 64;

    if SHA256_INPUT_CHUNK_SIZE_FELTS > 100 {
        return Err(VirtualMachineError::ShaInputChunkOutOfBounds(SHA256_INPUT_CHUNK_SIZE_FELTS));
    }

    let sha256_start = get_relocatable_from_var_name("sha256_start", ids, &vm.memory, &vm.references, &vm.run_context, hint_ap_tracking)?;
    let input_ptr = vm.memory.get_relocatable(&sha256_start)?;

    let mut message: Vec<u8> = Vec::new();

    for i in 0..SHA256_INPUT_CHUNK_SIZE_FELTS{
        message.extend(vm.memory.get_integer(&(input_ptr + i))?.to_signed_bytes_be());
    }

    let digested_message = digest_bytes(&message);
    let new_state = digested_message.as_bytes();
    let mut output: Vec<BigInt> = Vec::new();

    for i in (0..STRING_SIZE_SHA - BYTE_STEP).step_by(BYTE_STEP) {
        output.push(bigint_str!(&new_state[i..i + BYTE_STEP], 16));
    }

    let output_base = get_relocatable_from_var_name(
        "output",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;

    println!("{}", &digested_message);
    vm.segments.write_arg(&mut vm.memory, &output_base, &output, Some(&vm.prime)).map_err(VirtualMachineError::MemoryError)?;
    Ok(())
}
