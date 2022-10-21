use crate::hint_processor::builtin_hint_processor::hint_utils::get_integer_from_var_name;
use crate::hint_processor::builtin_hint_processor::hint_utils::get_ptr_from_var_name;
use crate::hint_processor::builtin_hint_processor::hint_utils::insert_value_into_ap;
use crate::vm::vm_core::VirtualMachine;
use crate::{
    bigint, hint_processor::hint_processor_definition::HintReference,
    serde::deserialize_program::ApTracking, types::relocatable::MaybeRelocatable,
    vm::errors::vm_errors::VirtualMachineError,
};
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use std::collections::HashMap;

// Constants in package "starkware.cairo.common.cairo_keccak.keccak".
const BYTES_IN_WORD: &str = "starkware.cairo.common.cairo_keccak.keccak.BYTES_IN_WORD";
const KECCAK_FULL_RATE_IN_BYTES: &str =
    "starkware.cairo.common.cairo_keccak.keccak.KECCAK_FULL_RATE_IN_BYTES";
const KECCAK_STATE_SIZE_FELTS: &str =
    "starkware.cairo.common.cairo_keccak.keccak.KECCAK_STATE_SIZE_FELTS";

// Constants in package "starkware.cairo.common.cairo_keccak.packed_keccak".
const BLOCK_SIZE: &str = "starkware.cairo.common.cairo_keccak.packed_keccak.BLOCK_SIZE";

/*
Implements hint:
    %{
      segments.write_arg(ids.inputs, [ids.low % 2 ** 64, ids.low // 2 ** 64])
      segments.write_arg(ids.inputs + 2, [ids.high % 2 ** 64, ids.high // 2 ** 64])
    %}
*/
pub fn keccak_write_args(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let inputs_ptr = get_ptr_from_var_name("inputs", vm, ids_data, ap_tracking)?;

    let low = get_integer_from_var_name("low", vm, ids_data, ap_tracking)?;
    let high = get_integer_from_var_name("high", vm, ids_data, ap_tracking)?;

    let low_args = [low & bigint!(u64::MAX), low >> 64];
    let high_args = [high & bigint!(u64::MAX), high >> 64];

    vm.write_arg(&inputs_ptr, &low_args.to_vec())
        .map_err(VirtualMachineError::MemoryError)?;

    vm.write_arg(&inputs_ptr.add(2)?, &high_args.to_vec())
        .map_err(VirtualMachineError::MemoryError)?;

    Ok(())
}

/*
Implements hint:
    Cairo code:
    if nondet %{ ids.n_bytes < ids.BYTES_IN_WORD %} != 0:

    Compiled code:
    memory[ap] = to_felt_or_relocatable(ids.n_bytes < ids.BYTES_IN_WORD)
*/
pub fn compare_bytes_in_word_nondet(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    let n_bytes = get_integer_from_var_name("n_bytes", vm, ids_data, ap_tracking)?;

    // This works fine, but it should be checked for a performance improvement.
    // One option is to try to convert n_bytes into usize, with failure to do so simply
    // making value be 0 (if it can't convert then it's either negative, which can't be in Cairo memory
    // or too big, which also means n_bytes > BYTES_IN_WORD). The other option is to exctract
    // bigint!(BYTES_INTO_WORD) into a lazy_static!
    let bytes_in_word = constants
        .get(BYTES_IN_WORD)
        .ok_or(VirtualMachineError::MissingConstant(BYTES_IN_WORD))?;
    let value = bigint!((n_bytes < bytes_in_word) as usize);
    insert_value_into_ap(vm, value)
}

/*
Implements hint:
    Cairo code:
    if nondet %{ ids.n_bytes >= ids.KECCAK_FULL_RATE_IN_BYTES %} != 0:

    Compiled code:
    "memory[ap] = to_felt_or_relocatable(ids.n_bytes >= ids.KECCAK_FULL_RATE_IN_BYTES)"
*/
pub fn compare_keccak_full_rate_in_bytes_nondet(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    let n_bytes = get_integer_from_var_name("n_bytes", vm, ids_data, ap_tracking)?;

    let keccak_full_rate_in_bytes =
        constants
            .get(KECCAK_FULL_RATE_IN_BYTES)
            .ok_or(VirtualMachineError::MissingConstant(
                KECCAK_FULL_RATE_IN_BYTES,
            ))?;
    let value = bigint!((n_bytes >= keccak_full_rate_in_bytes) as usize);
    insert_value_into_ap(vm, value)
}

/*
Implements hint:
    %{
        from starkware.cairo.common.cairo_keccak.keccak_utils import keccak_func
        _keccak_state_size_felts = int(ids.KECCAK_STATE_SIZE_FELTS)
        assert 0 <= _keccak_state_size_felts < 100

        output_values = keccak_func(memory.get_range(
            ids.keccak_ptr - _keccak_state_size_felts, _keccak_state_size_felts))
        segments.write_arg(ids.keccak_ptr, output_values)
    %}
*/
pub fn block_permutation(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    let keccak_state_size_felts =
        constants
            .get(KECCAK_STATE_SIZE_FELTS)
            .ok_or(VirtualMachineError::MissingConstant(
                KECCAK_STATE_SIZE_FELTS,
            ))?;

    if keccak_state_size_felts >= &bigint!(100) {
        return Err(VirtualMachineError::InvalidKeccakStateSizeFelts(
            keccak_state_size_felts.clone(),
        ));
    }

    let keccak_ptr = get_ptr_from_var_name("keccak_ptr", vm, ids_data, ap_tracking)?;

    let keccak_state_size_felts = keccak_state_size_felts.to_usize().unwrap();
    let values = vm
        .get_range(
            &MaybeRelocatable::RelocatableValue(keccak_ptr.sub(keccak_state_size_felts)?),
            keccak_state_size_felts,
        )
        .map_err(VirtualMachineError::MemoryError)?;

    let mut u64_values = maybe_reloc_vec_to_u64_array(&values)?
        .try_into()
        .map_err(|_| VirtualMachineError::SliceToArrayError)?;

    // this function of the keccak crate is the one used instead of keccak_func from
    // keccak_utils.py
    keccak::f1600(&mut u64_values);

    let bigint_values = u64_array_to_bigint_vec(&u64_values);

    vm.write_arg(&keccak_ptr, &bigint_values)
        .map_err(VirtualMachineError::MemoryError)?;

    Ok(())
}

/* Implements hint:
    %{
        # Add dummy pairs of input and output.
        _keccak_state_size_felts = int(ids.KECCAK_STATE_SIZE_FELTS)
        _block_size = int(ids.BLOCK_SIZE)
        assert 0 <= _keccak_state_size_felts < 100
        assert 0 <= _block_size < 10
        inp = [0] * _keccak_state_size_felts
        padding = (inp + keccak_func(inp)) * _block_size
        segments.write_arg(ids.keccak_ptr_end, padding)
    %}
*/
pub fn cairo_keccak_finalize(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    let keccak_state_size_felts =
        constants
            .get(KECCAK_STATE_SIZE_FELTS)
            .ok_or(VirtualMachineError::MissingConstant(
                KECCAK_STATE_SIZE_FELTS,
            ))?;
    let block_size = constants
        .get(BLOCK_SIZE)
        .ok_or(VirtualMachineError::MissingConstant(BLOCK_SIZE))?;

    if keccak_state_size_felts >= &bigint!(100) {
        return Err(VirtualMachineError::InvalidKeccakStateSizeFelts(
            keccak_state_size_felts.clone(),
        ));
    }

    if block_size >= &bigint!(10) {
        return Err(VirtualMachineError::InvalidBlockSize(block_size.clone()));
    }

    let keccak_state_size_felts = keccak_state_size_felts.to_usize().unwrap();
    let block_size = block_size.to_usize().unwrap();

    let mut inp = vec![0; keccak_state_size_felts]
        .try_into()
        .map_err(|_| VirtualMachineError::SliceToArrayError)?;
    keccak::f1600(&mut inp);

    let mut padding = vec![bigint!(0_u64); keccak_state_size_felts];
    padding.extend(u64_array_to_bigint_vec(&inp));

    let base_padding = padding.clone();

    for _ in 0..(block_size - 1) {
        padding.extend_from_slice(base_padding.as_slice());
    }

    let keccak_ptr_end = get_ptr_from_var_name("keccak_ptr_end", vm, ids_data, ap_tracking)?;

    vm.write_arg(&keccak_ptr_end, &padding)
        .map_err(VirtualMachineError::MemoryError)?;

    Ok(())
}

// Helper function to transform a vector of MaybeRelocatables into a vector
// of u64. Raises error if there are None's or if MaybeRelocatables are not Bigints.
fn maybe_reloc_vec_to_u64_array(
    vec: &[Option<&MaybeRelocatable>],
) -> Result<Vec<u64>, VirtualMachineError> {
    let array = vec
        .iter()
        .map(|n| {
            if let Some(MaybeRelocatable::Int(num)) = n {
                num.to_u64().ok_or(VirtualMachineError::BigintToU64Fail)
            } else {
                Err(VirtualMachineError::ExpectedIntAtRange(n.cloned()))
            }
        })
        .collect::<Result<Vec<u64>, VirtualMachineError>>()?;

    Ok(array)
}

fn u64_array_to_bigint_vec(array: &[u64]) -> Vec<BigInt> {
    array.iter().map(|n| bigint!(*n)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::any_box;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData;
    use crate::hint_processor::hint_processor_definition::HintProcessor;
    use crate::hint_processor::hint_processor_definition::HintReference;
    use crate::types::exec_scope::ExecutionScopes;
    use crate::types::relocatable::Relocatable;
    use crate::utils::test_utils::*;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::vm::runners::builtin_runner::RangeCheckBuiltinRunner;
    use crate::vm::vm_core::VirtualMachine;
    use crate::vm::vm_memory::memory::Memory;
    use num_bigint::{BigInt, Sign};
    use std::any::Any;

    #[test]
    fn keccak_write_args_valid_test() {
        let hint_code = "segments.write_arg(ids.inputs, [ids.low % 2 ** 64, ids.low // 2 ** 64])\nsegments.write_arg(ids.inputs + 2, [ids.high % 2 ** 64, ids.high // 2 ** 64])";
        let mut vm = vm_with_range_check!();
        vm.memory = memory![
            ((1, 0), 233),
            ((1, 1), 351),
            ((1, 2), (2, 0)),
            ((2, 4), 5_i32)
        ];
        //Initialize fp
        vm.run_context.fp = 3;
        //Create ids
        let ids_data = ids_data!["low", "high", "inputs"];
        assert_eq!(run_hint!(vm, ids_data, hint_code), Ok(()));
    }

    #[test]
    fn keccak_write_args_write_error() {
        let hint_code = "segments.write_arg(ids.inputs, [ids.low % 2 ** 64, ids.low // 2 ** 64])\nsegments.write_arg(ids.inputs + 2, [ids.high % 2 ** 64, ids.high // 2 ** 64])";
        let mut vm = vm_with_range_check!();
        vm.memory = memory![((1, 0), 233), ((1, 1), 351), ((1, 2), (2, 0))];
        //Initialize fp
        vm.run_context.fp = 3;
        //Create ids
        let ids_data = ids_data!["low", "high", "inputs"];
        let error = run_hint!(vm, ids_data, hint_code);
        assert!(matches!(error, Err(VirtualMachineError::MemoryError(_))));
    }

    #[test]
    fn compare_bytes_in_word_nondet_valid() {
        let hint_code =
            "memory[ap] = to_felt_or_relocatable(ids.n_bytes >= ids.KECCAK_FULL_RATE_IN_BYTES)";
        let mut vm = vm_with_range_check!();

        vm.segments.add(&mut vm.memory);
        vm.memory = memory![((1, 0), 24)];

        run_context!(vm, 0, 1, 1);
        let ids_data = ids_data!["n_bytes"];
        assert_eq!(
            run_hint!(
                vm,
                ids_data,
                hint_code,
                exec_scopes_ref!(),
                &[(KECCAK_FULL_RATE_IN_BYTES, bigint!(136))]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect()
            ),
            Ok(())
        );
    }

    #[test]
    fn compare_keccak_full_rate_in_bytes_nondet_valid() {
        let hint_code =
            "memory[ap] = to_felt_or_relocatable(ids.n_bytes >= ids.KECCAK_FULL_RATE_IN_BYTES)";

        let mut vm = vm_with_range_check!();

        vm.segments.add(&mut vm.memory);
        vm.memory = memory![((1, 0), 24)];

        run_context!(vm, 0, 1, 1);

        let ids_data = ids_data!["n_bytes"];
        assert_eq!(
            run_hint!(
                vm,
                ids_data,
                hint_code,
                exec_scopes_ref!(),
                &[(KECCAK_FULL_RATE_IN_BYTES, bigint!(136))]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect()
            ),
            Ok(())
        );
    }

    #[test]
    fn block_permutation_valid_test() {
        let hint_code =
            "memory[ap] = to_felt_or_relocatable(ids.n_bytes >= ids.KECCAK_FULL_RATE_IN_BYTES)";
        let mut vm = vm_with_range_check!();

        vm.segments.add(&mut vm.memory);
        vm.memory = memory![((1, 0), 24)];

        run_context!(vm, 0, 1, 1);

        let ids_data = ids_data!["n_bytes"];
        assert_eq!(
            run_hint!(
                vm,
                ids_data,
                hint_code,
                exec_scopes_ref!(),
                &[(KECCAK_FULL_RATE_IN_BYTES, bigint!(136))]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect()
            ),
            Ok(())
        );
    }
}
