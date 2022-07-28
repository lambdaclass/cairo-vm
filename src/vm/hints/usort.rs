use crate::{
    bigint, bigintusize,
    serde::deserialize_program::ApTracking,
    types::{exec_scope::PyValueType, relocatable::MaybeRelocatable},
    vm::{
        errors::vm_errors::VirtualMachineError,
        hints::hint_utils::{
            get_int_from_scope, get_integer_from_relocatable_plus_offset,
            get_integer_from_var_name, get_key_to_list_map_from_scope_mut, get_list_from_scope_mut,
            get_list_from_scope_ref, get_range_check_builtin, get_relocatable_from_var_name,
            insert_integer_from_var_name,
        },
        vm_core::VirtualMachine,
    },
};
use num_bigint::BigInt;
use num_traits::{FromPrimitive, ToPrimitive};
use std::collections::HashMap;

pub fn usort_enter_scope(vm: &mut VirtualMachine) -> Result<(), VirtualMachineError> {
    let usort_max_size =
        get_int_from_scope(vm, "usort_max_size").map_or(PyValueType::None, PyValueType::BigInt);
    Ok(vm.exec_scopes.enter_scope(HashMap::from([(
        "usort_max_size".to_string(),
        usort_max_size,
    )])))
}

pub fn usort_body(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let _ = get_range_check_builtin(vm)?;
    let input_arr_start_ptr = get_relocatable_from_var_name("input", ids, vm, hint_ap_tracking)?;
    let input_ptr = vm.memory.get_relocatable(&input_arr_start_ptr)?.clone();
    let usort_max_size = get_int_from_scope(vm, "usort_max_size");
    let input_len = get_integer_from_var_name("input_len", ids, vm, hint_ap_tracking)?;
    let input_len_usize = input_len
        .to_usize()
        .ok_or(VirtualMachineError::BigintToUsizeFail)?;

    if let Some(usort_max_size) = usort_max_size {
        if input_len > &usort_max_size {
            return Err(VirtualMachineError::UsortOutOfRange(
                usort_max_size,
                input_len.clone(),
            ));
        }
    }

    let mut positions_dict: HashMap<BigInt, Vec<BigInt>> = HashMap::new();
    let mut output: Vec<BigInt> = Vec::new();
    for i in 0..input_len_usize {
        let val = get_integer_from_relocatable_plus_offset(&input_ptr, i, vm)?;
        if let Err(output_index) = output.binary_search(val) {
            output.insert(output_index, val.clone());
        }
        positions_dict
            .entry(val.clone())
            .or_insert(Vec::new())
            .push(bigintusize!(i));
    }

    let mut multiplicities: Vec<BigInt> = Vec::new();
    for k in output.iter() {
        multiplicities.push(bigintusize!(positions_dict[k].len()));
    }

    vm.exec_scopes
        .assign_or_update_variable("positions_dict", PyValueType::KeyToListMap(positions_dict));
    let mut output_base = vm.segments.add(&mut vm.memory, Some(output.len()));
    let mut multiplicities_base = vm.segments.add(&mut vm.memory, Some(multiplicities.len()));
    let output_len = output.len();

    for sorted_element in output.into_iter() {
        vm.memory
            .insert(
                &MaybeRelocatable::RelocatableValue(output_base.clone()),
                &MaybeRelocatable::Int(sorted_element),
            )
            .map_err(VirtualMachineError::MemoryError)?;
        output_base.offset += 1;
    }

    for repetition_amount in multiplicities.into_iter() {
        vm.memory
            .insert(
                &MaybeRelocatable::RelocatableValue(multiplicities_base.clone()),
                &MaybeRelocatable::Int(repetition_amount),
            )
            .map_err(VirtualMachineError::MemoryError)?;
        multiplicities_base.offset += 1;
    }

    insert_integer_from_var_name(
        "output_len",
        bigintusize!(output_len),
        ids,
        vm,
        hint_ap_tracking,
    )
}

pub fn verify_usort(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let _ = get_range_check_builtin(vm);
    let value = get_integer_from_var_name("value", ids, vm, hint_ap_tracking)?.clone();
    let positions: Vec<BigInt> = get_key_to_list_map_from_scope_mut(vm, "positions_dict")
        .ok_or(VirtualMachineError::UnexpectedPositionsDictFail)?
        .remove(&value)
        .ok_or(VirtualMachineError::UnexpectedPositionsDictFail)?
        .into_iter()
        .rev()
        .collect();

    vm.exec_scopes
        .assign_or_update_variable("positions", PyValueType::List(positions));
    vm.exec_scopes
        .assign_or_update_variable("last_pos", PyValueType::BigInt(bigint!(0)));

    Ok(())
}

pub fn verify_multiplicity_assert(vm: &mut VirtualMachine) -> Result<(), VirtualMachineError> {
    let positions_len = get_list_from_scope_ref(vm, "positions")
        .ok_or(VirtualMachineError::PositionsNotFound)?
        .len();
    if positions_len == 0 {
        Ok(())
    } else {
        Err(VirtualMachineError::PositionsLengthNotZero)
    }
}

pub fn verify_multiplicity_body(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let current_pos = get_list_from_scope_mut(vm, "positions")
        .ok_or(VirtualMachineError::PositionsNotFound)?
        .pop()
        .ok_or(VirtualMachineError::CouldntPopPositions)?;

    let pos_diff = current_pos.clone()
        - get_int_from_scope(vm, "last_pos").ok_or(VirtualMachineError::LastPosNotFound)?;

    let _ = insert_integer_from_var_name("next_item_index", pos_diff, ids, vm, hint_ap_tracking)?;

    vm.exec_scopes
        .assign_or_update_variable("last_pos", PyValueType::BigInt(current_pos + 1));

    Ok(())
}
