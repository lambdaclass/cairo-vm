use crate::hint_processor::builtin_hint_processor::hint_utils::get_integer_from_var_name;
use crate::hint_processor::builtin_hint_processor::hint_utils::get_ptr_from_var_name;
use crate::hint_processor::builtin_hint_processor::hint_utils::insert_value_from_var_name;
use crate::hint_processor::proxies::exec_scopes_proxy::ExecutionScopesProxy;
use crate::hint_processor::proxies::vm_proxy::VMProxy;
use crate::{
    bigint, serde::deserialize_program::ApTracking, vm::errors::vm_errors::VirtualMachineError,
};
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use std::{any::Any, collections::HashMap};

use crate::hint_processor::hint_processor_definition::HintReference;

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
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let input_ptr = get_ptr_from_var_name("input", vm_proxy, ids_data, ap_tracking)?;
    let usort_max_size = exec_scopes_proxy.get_u64("usort_max_size");
    let input_len = get_integer_from_var_name("input_len", vm_proxy, ids_data, ap_tracking)?;
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
        let val = vm_proxy.memory.get_integer(&(&input_ptr + i as usize))?;
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
    let output_base = vm_proxy.memory.add_segment(vm_proxy.segments);
    let multiplicities_base = vm_proxy.memory.add_segment(vm_proxy.segments);
    let output_len = output.len();

    for (i, sorted_element) in output.into_iter().enumerate() {
        vm_proxy
            .memory
            .insert_value(&(&output_base + i), sorted_element)?;
    }

    for (i, repetition_amount) in multiplicities.into_iter().enumerate() {
        vm_proxy
            .memory
            .insert_value(&(&multiplicities_base + i), bigint!(repetition_amount))?;
    }

    insert_value_from_var_name(
        "output_len",
        bigint!(output_len),
        vm_proxy,
        ids_data,
        ap_tracking,
    )?;
    insert_value_from_var_name("output", output_base, vm_proxy, ids_data, ap_tracking)?;
    insert_value_from_var_name(
        "multiplicities",
        multiplicities_base,
        vm_proxy,
        ids_data,
        ap_tracking,
    )
}

pub fn verify_usort(
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let value = get_integer_from_var_name("value", vm_proxy, ids_data, ap_tracking)?.clone();
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
    vm_proxy: &mut VMProxy,
    exec_scopes_proxy: &mut ExecutionScopesProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let current_pos = exec_scopes_proxy
        .get_mut_listu64_ref("positions")?
        .pop()
        .ok_or(VirtualMachineError::CouldntPopPositions)?;
    let pos_diff = bigint!(current_pos) - exec_scopes_proxy.get_int("last_pos")?;
    insert_value_from_var_name("next_item_index", pos_diff, vm_proxy, ids_data, ap_tracking)?;
    exec_scopes_proxy.insert_value("last_pos", bigint!(current_pos + 1));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::any_box;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
        BuiltinHintProcessor, HintProcessorData,
    };
    use crate::hint_processor::hint_processor_definition::HintProcessor;
    use crate::hint_processor::proxies::exec_scopes_proxy::get_exec_scopes_proxy;
    use crate::hint_processor::proxies::vm_proxy::get_vm_proxy;
    use crate::types::exec_scope::ExecutionScopes;
    use crate::utils::test_utils::*;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::vm::vm_memory::memory::Memory;
    use crate::{
        types::relocatable::MaybeRelocatable,
        vm::{runners::builtin_runner::RangeCheckBuiltinRunner, vm_core::VirtualMachine},
    };
    use num_bigint::Sign;

    #[test]
    fn usort_out_of_range() {
        let hint = "from collections import defaultdict\n\ninput_ptr = ids.input\ninput_len = int(ids.input_len)\nif __usort_max_size is not None:\n    assert input_len <= __usort_max_size, (\n        f\"usort() can only be used with input_len<={__usort_max_size}. \"\n        f\"Got: input_len={input_len}.\"\n    )\n\npositions_dict = defaultdict(list)\nfor i in range(input_len):\n    val = memory[input_ptr + i]\n    positions_dict[val].append(i)\n\noutput = sorted(positions_dict.keys())\nids.output_len = len(output)\nids.output = segments.gen_arg(output)\nids.multiplicities = segments.gen_arg([len(positions_dict[k]) for k in output])";
        let mut vm = vm_with_range_check!();

        vm.run_context.fp = 2;

        vm.segments.add(&mut vm.memory);
        vm.memory = memory![((1, 0), (2, 1)), ((1, 1), 5)];
        //Create hint_data
        let ids_data = ids_data!["input", "input_len"];
        let hint_data = HintProcessorData::new_default(hint.to_string(), ids_data);
        let mut exec_scopes = ExecutionScopes::new();
        exec_scopes.assign_or_update_variable("usort_max_size", any_box!(1_u64));
        let vm_proxy = &mut get_vm_proxy(&mut vm);
        let exec_scopes_proxy = &mut get_exec_scopes_proxy(&mut exec_scopes);
        let hint_processor = BuiltinHintProcessor::new_empty();
        assert_eq!(
            hint_processor.execute_hint(vm_proxy, exec_scopes_proxy, &any_box!(hint_data)),
            Err(VirtualMachineError::UsortOutOfRange(1, bigint!(5)))
        );
    }
}
