use crate::hint_processor::hint_utils::bigint_to_u32;
use crate::hint_processor::hint_utils::get_integer_from_var_name;
use crate::hint_processor::hint_utils::get_ptr_from_var_name;
use crate::hint_processor::hint_utils::insert_value_from_var_name;
use crate::{
    bigint,
    serde::deserialize_program::ApTracking,
    vm::{errors::vm_errors::VirtualMachineError, vm_core::VMProxy},
};

use generic_array::GenericArray;
use num_bigint::BigInt;
use num_traits::{One, Zero};
use sha2::compress256;
use std::collections::HashMap;

use crate::hint_processor::hint_processor_definition::HintReference;

const SHA256_INPUT_CHUNK_SIZE_FELTS: usize = 16;
const SHA256_STATE_SIZE_FELTS: usize = 8;
const BLOCK_SIZE: usize = 7;
const IV: [u32; SHA256_STATE_SIZE_FELTS] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

pub fn sha256_input(
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let n_bytes = get_integer_from_var_name("n_bytes", vm_proxy, ids_data, ap_tracking)?;

    insert_value_from_var_name(
        "full_word",
        if n_bytes >= &bigint!(4) {
            BigInt::one()
        } else {
            BigInt::zero()
        },
        vm_proxy,
        ids_data,
        ap_tracking,
    )
}

pub fn sha256_main(
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let input_ptr = get_ptr_from_var_name("sha256_start", vm_proxy, ids_data, ap_tracking)?;

    let mut message: Vec<u8> = Vec::with_capacity(4 * SHA256_INPUT_CHUNK_SIZE_FELTS);

    for i in 0..SHA256_INPUT_CHUNK_SIZE_FELTS {
        let input_element = vm_proxy.memory.get_integer(&(&input_ptr + i))?;
        let bytes = bigint_to_u32(input_element)?.to_be_bytes();
        message.extend(bytes);
    }

    let mut iv = IV;
    let new_message = GenericArray::clone_from_slice(&message);
    compress256(&mut iv, &[new_message]);

    let mut output: Vec<BigInt> = Vec::with_capacity(SHA256_STATE_SIZE_FELTS);

    for new_state in iv {
        output.push(bigint!(new_state));
    }

    let output_base = get_ptr_from_var_name("output", vm_proxy, ids_data, ap_tracking)?;

    vm_proxy
        .memory
        .write_arg(
            vm_proxy.segments,
            &output_base,
            &output,
            Some(vm_proxy.prime),
        )
        .map_err(VirtualMachineError::MemoryError)?;
    Ok(())
}

pub fn sha256_finalize(
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let message: Vec<u8> = vec![0; 64];

    let mut iv = IV;

    let iv_static: Vec<BigInt> = iv.iter().map(|n| bigint!(*n)).collect();

    let new_message = GenericArray::clone_from_slice(&message);
    compress256(&mut iv, &[new_message]);

    let mut output: Vec<BigInt> = Vec::with_capacity(SHA256_STATE_SIZE_FELTS);

    for new_state in iv {
        output.push(bigint!(new_state));
    }

    let sha256_ptr_end = get_ptr_from_var_name("sha256_ptr_end", vm_proxy, ids_data, ap_tracking)?;

    let mut padding: Vec<BigInt> = Vec::new();
    let zero_vector_message = vec![BigInt::zero(); 16];

    for _ in 0..BLOCK_SIZE - 1 {
        padding.extend_from_slice(zero_vector_message.as_slice());
        padding.extend_from_slice(iv_static.as_slice());
        padding.extend_from_slice(output.as_slice());
    }

    vm_proxy
        .memory
        .write_arg(
            vm_proxy.segments,
            &sha256_ptr_end,
            &padding,
            Some(vm_proxy.prime),
        )
        .map_err(VirtualMachineError::MemoryError)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::get_vm_proxy;
    use crate::hint_processor::hint_processor_definition::HintReference;
    use crate::types::relocatable::MaybeRelocatable;
    use crate::utils::test_utils::*;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::vm::runners::builtin_runner::RangeCheckBuiltinRunner;
    use crate::vm::vm_core::VirtualMachine;
    use crate::vm::vm_memory::memory::Memory;
    use num_bigint::Sign;

    #[test]
    fn sha256_input_one() {
        let mut vm = vm_with_range_check!();
        vm.memory = memory![((0, 1), 7)];
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        let ids_data = ids_data!["full_word", "n_bytes"];
        let vm_proxy = &mut &mut get_vm_proxy(&mut vm);
        assert_eq!(
            sha256_input(vm_proxy, &ids_data, &ApTracking::new()),
            Ok(())
        );

        check_memory![&vm.memory, ((0, 0), 1)];
    }

    #[test]
    fn sha256_input_zero() {
        let mut vm = vm_with_range_check!();
        vm.memory = memory![((0, 1), 3)];
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        let ids_data = ids_data!["full_word", "n_bytes"];
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(
            sha256_input(vm_proxy, &ids_data, &ApTracking::new()),
            Ok(())
        );

        check_memory![&vm.memory, ((0, 0), 0)];
    }

    #[test]
    fn sha256_ok() {
        let mut vm = vm_with_range_check!();

        vm.memory = memory![
            ((0, 0), (1, 0)),
            ((0, 1), (2, 0)),
            ((1, 0), 22),
            ((1, 1), 22),
            ((1, 2), 22),
            ((1, 3), 22),
            ((1, 4), 22),
            ((1, 5), 22),
            ((1, 6), 22),
            ((1, 7), 22),
            ((1, 8), 22),
            ((1, 9), 22),
            ((1, 10), 22),
            ((1, 11), 22),
            ((1, 12), 22),
            ((1, 13), 22),
            ((1, 14), 22),
            ((1, 15), 22),
            ((2, 9), 0)
        ];
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        let ids_data = ids_data!["sha256_start", "output"];
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        assert_eq!(sha256_main(vm_proxy, &ids_data, &ApTracking::new()), Ok(()));

        check_memory![
            &vm.memory,
            ((2, 0), 3704205499_u32),
            ((2, 1), 2308112482_u32),
            ((2, 2), 3022351583_u32),
            ((2, 3), 174314172_u32),
            ((2, 4), 1762869695_u32),
            ((2, 5), 1649521060_u32),
            ((2, 6), 2811202336_u32),
            ((2, 7), 4231099170_u32)
        ];
    }
}
