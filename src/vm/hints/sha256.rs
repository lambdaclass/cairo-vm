pub fn sha256_input(vm: &mut VirtualMachine, ids: &HashMap<String, BigInt>, hint_ap_tracking: Option<&ApTracking>) -> Result<(), VirtualMachineError> {
    let n_bytes = get_integer_from_var_name("n_bytes", ids, vm, hint_ap_tracking)?;
    let full_word = if n_bytes >= 4 {
        BigInt::one() 
    } else {
        BigInt::zero()
    };

    insert_integer_from_var_name("full_word", full_word, ids, vm, hint_ap_tracking)
}

pub fn sha256(vm: &mut VirtualMachine, ids: &HashMap<String, BigInt>, hint_ap_tracking: Option<&ApTracking>) -> Result<(), VirtualMachineError> {
    let const BIT_STEP_32: usize = 32;
    let const BIT_SIZE_SHA: usize = 256;

    let sha256_input_chunk_size_felts = get_usize_from_var_name("SHA256_INPUT_CHUNK_SIZE_FELTS", ids, vm, hint_ap_tracking)?; 
    if sha256_input_chunk_size_felts < 100 {
        return Err(VirtualMachineError::ShaInputChunkOutOfBounds);
    }

    let sha256_start = get_relocatable_from_var_name("sha256_start", ids, vm, hint_ap_tracking)?;
    let input_ptr = vm.memory.get_relocatable(&sha256_start)?;

    let mut message: Vec<u8> = Vec::new();

    for i in 0..sha256_input_chunk_size_felts {
        message.extend(get_integer_from_relocatable_plus_offset(input_ptr, i, vm)?.to_signed_bytes_be());
    }

    let new_state = digest_bytes(message).as_bytes();
    let mut output: Vec<u32> = Vec::new();

    for i in (0..BIT_SIZE_SHA - BIT_STEP_32).step_by(BIT_STEP_32) {
        output.push(bigint_str!(&new_state[i..i + BIT_STEP_32]));
    }

    let output_base = vm.segments.add(&mut vm.memory, Some(output.len()));
    for (i, sha_chunk) in output.into_iter().enumerate() {
        vm.memory
            .insert_value(&(&output_base + i), sha_chunk)?;
    }
}
