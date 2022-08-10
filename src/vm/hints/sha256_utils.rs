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

    insert_value_from_var_name(
        "full_word",
        if n_bytes >= &bigint!(4) {
            BigInt::one()
        } else {
            BigInt::zero()
        },
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
    let sha256_start = get_relocatable_from_var_name(
        "sha256_start",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;

    let input_ptr = vm.memory.get_relocatable(&sha256_start)?;

    let mut message: Vec<u8> = Vec::with_capacity(4 * SHA256_INPUT_CHUNK_SIZE_FELTS);

    for i in 0..SHA256_INPUT_CHUNK_SIZE_FELTS {
        let input_element = vm.memory.get_integer(&(input_ptr + i))?;
        let bytes = bigint_to_u32(input_element)?.to_be_bytes();
        message.extend(bytes);
    }

    let mut iv: [u32; SHA256_STATE_SIZE_FELTS] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];

    let new_message = GenericArray::clone_from_slice(&message);
    compress256(&mut iv, &[new_message]);

    let mut output: Vec<BigInt> = Vec::with_capacity(SHA256_STATE_SIZE_FELTS);

    for new_state in iv {
        output.push(bigint!(new_state));
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
    let message: Vec<u8> = vec![0; 64];

    let mut iv: [u32; SHA256_STATE_SIZE_FELTS] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];

    let iv_static: Vec<BigInt> = iv.iter().map(|n| bigint!(*n)).collect();

    let new_message = GenericArray::clone_from_slice(&message);
    compress256(&mut iv, &[new_message]);

    let mut output: Vec<BigInt> = Vec::with_capacity(SHA256_STATE_SIZE_FELTS);

    for new_state in iv {
        output.push(bigint!(new_state));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::relocatable::MaybeRelocatable;
    use crate::utils::test_utils::*;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::vm::hints::execute_hint::BuiltinHintExecutor;
    use crate::vm::hints::execute_hint::HintReference;
    use crate::vm::runners::builtin_runner::RangeCheckBuiltinRunner;
    use crate::vm::vm_memory::memory::Memory;
    use num_bigint::Sign;
    static HINT_EXECUTOR: BuiltinHintExecutor = BuiltinHintExecutor {};

    #[test]
    fn sha256_input_one() {
        let mut vm = vm_with_range_check!();
        vm.memory = memory![((0, 1), 7)];
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        let ids = ids!["full_word", "n_bytes"];
        vm.references = references!(2);

        assert_eq!(
            sha256_input(&mut vm, &ids, Some(&ApTracking::new())),
            Ok(())
        );

        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from(BigInt::one())))
        );
    }

    #[test]
    fn sha256_input_zero() {
        let mut vm = vm_with_range_check!();
        vm.memory = memory![((0, 1), 3)];
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        let ids = ids!["full_word", "n_bytes"];
        vm.references = references!(2);

        assert_eq!(
            sha256_input(&mut vm, &ids, Some(&ApTracking::new())),
            Ok(())
        );

        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from(BigInt::zero())))
        );
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
        vm.references = references!(2);

        let ids = ids!["sha256_start", "output"];

        assert_eq!(sha256_main(&mut vm, &ids, Some(&ApTracking::new())), Ok(()));

        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((2, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(3704205499_u32))))
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((2, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(2308112482_u32))))
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((2, 2))),
            Ok(Some(&MaybeRelocatable::from(bigint!(3022351583_u32))))
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((2, 3))),
            Ok(Some(&MaybeRelocatable::from(bigint!(174314172_u32))))
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((2, 4))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1762869695_u32))))
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((2, 5))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1649521060_u32))))
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((2, 6))),
            Ok(Some(&MaybeRelocatable::from(bigint!(2811202336_u32))))
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((2, 7))),
            Ok(Some(&MaybeRelocatable::from(bigint!(4231099170_u32))))
        );
    }
}
