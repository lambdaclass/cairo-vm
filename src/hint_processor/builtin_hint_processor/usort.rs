use crate::{
    bigint,
    hint_processor::{
        builtin_hint_processor::hint_utils::{
            get_integer_from_var_name, get_ptr_from_var_name, insert_value_from_var_name,
        },
        hint_processor_definition::HintReference,
        proxies::exec_scopes_proxy::ExecutionScopesProxy,
    },
    serde::deserialize_program::ApTracking,
    vm::{errors::vm_errors::VirtualMachineError, vm_core::VirtualMachine},
};

use num_bigint::BigInt;
use num_traits::ToPrimitive;
use std::{any::Any, collections::HashMap};

pub fn usort_enter_scope(
    exec_scopes_proxy: &mut ExecutionScopesProxy,
) -> Result<(), VirtualMachineError> {
    if let Ok(usort_max_size) = exec_scopes_proxy.get_int("usort_max_size") {
        let boxed_max_size: Box<dyn Any> = Box::new(usort_max_size);
        exec_scopes_proxy.enter_scope(HashMap::from([(
            "usort_max_size".to_string(),
            boxed_max_size,
        )]));
    } else {
        exec_scopes_proxy.enter_scope(HashMap::new());
    }
    Ok(())
}

pub fn usort_body(
    vm: &mut VirtualMachine,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let input_ptr = get_ptr_from_var_name("input", vm, ids_data, ap_tracking)?;
    let usort_max_size = exec_scopes_proxy.get_u64("usort_max_size");
    let input_len = get_integer_from_var_name("input_len", vm, ids_data, ap_tracking)?;
    let input_len_u64 = input_len
        .to_u64()
        .ok_or(VirtualMachineError::BigintToUsizeFail)?;

    if let Ok(usort_max_size) = usort_max_size {
        if input_len_u64 > usort_max_size {
            return Err(VirtualMachineError::UsortOutOfRange(
                usort_max_size,
                input_len.clone(),
            ));
        }
    }
    let mut positions_dict: HashMap<BigInt, Vec<u64>> = HashMap::new();
    let mut output: Vec<BigInt> = Vec::new();
    for i in 0..input_len_u64 {
        let val = vm.get_integer(&(&input_ptr + i as usize))?;
        if let Err(output_index) = output.binary_search(val) {
            output.insert(output_index, val.clone());
        }
        positions_dict
            .entry(val.clone())
            .or_insert(Vec::new())
            .push(i);
    }

    let mut multiplicities: Vec<usize> = Vec::new();
    for k in output.iter() {
        multiplicities.push(positions_dict[k].len());
    }
    exec_scopes_proxy.insert_value("positions_dict", positions_dict);
    let output_base = vm.add_memory_segment();
    let multiplicities_base = vm.add_memory_segment();
    let output_len = output.len();

    for (i, sorted_element) in output.into_iter().enumerate() {
        vm.insert_value(&(&output_base + i), sorted_element)?;
    }

    for (i, repetition_amount) in multiplicities.into_iter().enumerate() {
        vm.insert_value(&(&multiplicities_base + i), bigint!(repetition_amount))?;
    }

    insert_value_from_var_name("output_len", bigint!(output_len), vm, ids_data, ap_tracking)?;
    insert_value_from_var_name("output", output_base, vm, ids_data, ap_tracking)?;
    insert_value_from_var_name(
        "multiplicities",
        multiplicities_base,
        vm,
        ids_data,
        ap_tracking,
    )
}

pub fn verify_usort(
    vm: &mut VirtualMachine,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let value = get_integer_from_var_name("value", vm, ids_data, ap_tracking)?.clone();
    let mut positions = exec_scopes_proxy
        .get_mut_dict_int_list_u64_ref("positions_dict")?
        .remove(&value)
        .ok_or(VirtualMachineError::UnexpectedPositionsDictFail)?;
    positions.reverse();
    exec_scopes_proxy.insert_value("positions", positions);
    exec_scopes_proxy.insert_value("last_pos", bigint!(0));
    Ok(())
}

pub fn verify_multiplicity_assert(
    exec_scopes_proxy: &mut ExecutionScopesProxy,
) -> Result<(), VirtualMachineError> {
    let positions_len = exec_scopes_proxy.get_listu64_ref("positions")?.len();
    if positions_len == 0 {
        Ok(())
    } else {
        Err(VirtualMachineError::PositionsLengthNotZero)
    }
}

pub fn verify_multiplicity_body(
    vm: &mut VirtualMachine,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let current_pos = exec_scopes_proxy
        .get_mut_listu64_ref("positions")?
        .pop()
        .ok_or(VirtualMachineError::CouldntPopPositions)?;
    let pos_diff = bigint!(current_pos) - exec_scopes_proxy.get_int("last_pos")?;
    insert_value_from_var_name("next_item_index", pos_diff, vm, ids_data, ap_tracking)?;
    exec_scopes_proxy.insert_value("last_pos", bigint!(current_pos + 1));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        any_box,
        hint_processor::{
            builtin_hint_processor::{
                builtin_hint_processor_definition::{BuiltinHintProcessor, HintProcessorData},
                hint_code::USORT_BODY,
            },
            hint_processor_definition::HintProcessor,
            proxies::exec_scopes_proxy::get_exec_scopes_proxy,
        },
        types::{exec_scope::ExecutionScopes, relocatable::MaybeRelocatable},
        utils::test_utils::*,
        vm::{
            errors::memory_errors::MemoryError, runners::builtin_runner::RangeCheckBuiltinRunner,
            vm_core::VirtualMachine, vm_memory::memory::Memory,
        },
    };
    use num_bigint::Sign;

    #[test]
    fn usort_with_max_size() {
        let exec_scopes = &mut scope![("usort_max_size", 1_u64)];
        let mut exec_scopes_proxy = get_exec_scopes_proxy(exec_scopes);
        assert_eq!(usort_enter_scope(&mut exec_scopes_proxy), Ok(()));
    }

    #[test]
    fn usort_out_of_range() {
        let mut vm = vm_with_range_check!();
        vm.run_context.fp = 2;
        add_segments!(vm, 1);
        vm.memory = memory![((1, 0), (2, 1)), ((1, 1), 5)];
        //Create hint_data
        let ids_data = ids_data!["input", "input_len"];
        let mut exec_scopes = scope![("usort_max_size", 1_u64)];
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        assert_eq!(
            run_hint!(vm, ids_data, USORT_BODY, exec_scopes_proxy),
            Err(VirtualMachineError::UsortOutOfRange(1, bigint!(5)))
        );
    }
}
