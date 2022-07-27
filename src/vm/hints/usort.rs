use crate::{
    bigintusize,
    serde::deserialize_program::ApTracking,
    types::{exec_scope::PyValueType, relocatable::MaybeRelocatable},
    vm::{
        errors::vm_errors::VirtualMachineError,
        hints::hint_utils::{
            get_int_from_scope, get_integer_from_relocatable_plus_offset,
            get_integer_from_var_name, get_relocatable_from_var_name, insert_integer_from_var_name,
        },
        vm_core::VirtualMachine,
    },
};
use num_bigint::BigInt;
use num_traits::{FromPrimitive, ToPrimitive};
use std::collections::HashMap;

pub fn usort_enter_scope(vm: &mut VirtualMachine) {
    let usort_max_size =
        get_int_from_scope(vm, "usort_max_size").map_or(PyValueType::None, PyValueType::BigInt);
    vm.exec_scopes.enter_scope(HashMap::from([(
        "usort_max_size".to_string(),
        usort_max_size,
    )]));
}

pub fn usort_body(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let input_ptr = get_relocatable_from_var_name("input", ids, vm, hint_ap_tracking)?;
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

    for output_iter in output.iter() {
        vm.memory
            .insert(
                &MaybeRelocatable::RelocatableValue(output_base.clone()),
                &MaybeRelocatable::Int(output_iter.clone()),
            )
            .map_err(VirtualMachineError::MemoryError)?;
        output_base.offset += 1;
    }

    for multiplicities_iter in multiplicities.iter() {
        vm.memory
            .insert(
                &MaybeRelocatable::RelocatableValue(multiplicities_base.clone()),
                &MaybeRelocatable::Int(multiplicities_iter.clone()),
            )
            .map_err(VirtualMachineError::MemoryError)?;
        multiplicities_base.offset += 1;
    }

    insert_integer_from_var_name(
        "output_len",
        bigintusize!(output.len()),
        ids,
        vm,
        hint_ap_tracking,
    )
}
