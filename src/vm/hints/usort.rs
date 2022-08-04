use crate::{
    bigint,
    serde::deserialize_program::ApTracking,
    types::exec_scope::PyValueType,
    vm::{
        errors::vm_errors::VirtualMachineError,
        hints::hint_utils::{
            get_dict_int_list_u64_from_scope_mut, get_int_from_scope, get_integer_from_var_name,
            get_list_u64_from_scope_mut, get_list_u64_from_scope_ref,
            get_relocatable_from_var_name, get_u64_from_scope, insert_value_from_var_name,
        },
        vm_core::VirtualMachine,
    },
};
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use std::collections::HashMap;

use super::hint_utils::insert_int_into_scope;

pub fn usort_enter_scope(vm: &mut VirtualMachine) -> Result<(), VirtualMachineError> {
    let usort_max_size = get_u64_from_scope(&vm.exec_scopes, "usort_max_size")
        .map_or(PyValueType::None, PyValueType::U64);
    vm.exec_scopes.enter_scope(HashMap::from([(
        "usort_max_size".to_string(),
        usort_max_size,
    )]));
    Ok(())
}

pub fn usort_body(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let input_arr_start_ptr = get_relocatable_from_var_name(
        "input",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let input_ptr = vm.memory.get_relocatable(&input_arr_start_ptr)?.clone();
    let usort_max_size = get_u64_from_scope(&vm.exec_scopes, "usort_max_size");
    let input_len = get_integer_from_var_name(
        "input_len",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
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
        let val = vm.memory.get_integer(&(&input_ptr + i as usize))?;
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

    vm.exec_scopes.assign_or_update_variable(
        "positions_dict",
        PyValueType::DictBigIntListU64(positions_dict),
    );
    let output_base = vm.segments.add(&mut vm.memory, Some(output.len()));
    let multiplicities_base = vm.segments.add(&mut vm.memory, Some(multiplicities.len()));
    let output_len = output.len();

    for (i, sorted_element) in output.into_iter().enumerate() {
        vm.memory
            .insert_value(&(&output_base + i), sorted_element)?;
    }

    for (i, repetition_amount) in multiplicities.into_iter().enumerate() {
        vm.memory
            .insert_value(&(&multiplicities_base + i), bigint!(repetition_amount))?;
    }

    insert_value_from_var_name(
        "output_len",
        bigint!(output_len),
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    insert_value_from_var_name(
        "output",
        output_base,
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    insert_value_from_var_name(
        "multiplicities",
        multiplicities_base,
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )
}

pub fn verify_usort(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let value = get_integer_from_var_name(
        "value",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?
    .clone();
    let positions: Vec<u64> =
        get_dict_int_list_u64_from_scope_mut(&mut vm.exec_scopes, "positions_dict")?
            .remove(&value)
            .ok_or(VirtualMachineError::UnexpectedPositionsDictFail)?
            .into_iter()
            .rev()
            .collect();

    vm.exec_scopes
        .assign_or_update_variable("positions", PyValueType::ListU64(positions));
    insert_int_into_scope(&mut vm.exec_scopes, "last_pos", bigint!(0));
    Ok(())
}

pub fn verify_multiplicity_assert(vm: &mut VirtualMachine) -> Result<(), VirtualMachineError> {
    let positions_len = get_list_u64_from_scope_ref(&vm.exec_scopes, "positions")?.len();
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
    let current_pos = get_list_u64_from_scope_mut(&mut vm.exec_scopes, "positions")?
        .pop()
        .ok_or(VirtualMachineError::CouldntPopPositions)?;
    let pos_diff = bigint!(current_pos) - get_int_from_scope(&vm.exec_scopes, "last_pos")?;
    insert_value_from_var_name(
        "next_item_index",
        pos_diff,
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    insert_int_into_scope(&mut vm.exec_scopes, "last_pos", bigint!(current_pos + 1));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        types::{instruction::Register, relocatable::MaybeRelocatable},
        vm::{
            hints::execute_hint::{BuiltinHintExecutor, HintReference},
            runners::builtin_runner::RangeCheckBuiltinRunner,
        },
    };
    use num_bigint::Sign;

    static HINT_EXECUTOR: BuiltinHintExecutor = BuiltinHintExecutor {};

    #[test]
    fn usort_out_of_range() {
        let hint = "from collections import defaultdict\n\ninput_ptr = ids.input\ninput_len = int(ids.input_len)\nif __usort_max_size is not None:\n    assert input_len <= __usort_max_size, (\n        f\"usort() can only be used with input_len<={__usort_max_size}. \"\n        f\"Got: input_len={input_len}.\"\n    )\n\npositions_dict = defaultdict(list)\nfor i in range(input_len):\n    val = memory[input_ptr + i]\n    positions_dict[val].append(i)\n\noutput = sorted(positions_dict.keys())\nids.output_len = len(output)\nids.output = segments.gen_arg(output)\nids.multiplicities = segments.gen_arg([len(positions_dict[k]) for k in output])";
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
            false,
            &HINT_EXECUTOR,
        );

        const FP_OFFSET_START: usize = 1;
        vm.run_context.fp = MaybeRelocatable::from((0, FP_OFFSET_START));

        vm.segments.add(&mut vm.memory, None);
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 1)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .expect("Unexpected memory insert fail");

        vm.references = HashMap::new();
        for i in 0..=FP_OFFSET_START {
            vm.references.insert(
                i,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: i as i32 - FP_OFFSET_START as i32,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            );
        }

        let mut ids = HashMap::<String, BigInt>::new();
        for (i, s) in ["input", "input_len"].iter().enumerate() {
            ids.insert(s.to_string(), bigint!(i));
        }

        vm.exec_scopes
            .assign_or_update_variable("usort_max_size", PyValueType::U64(1));

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint, &ids, &ApTracking::new()),
            Err(VirtualMachineError::UsortOutOfRange(1, bigint!(5)))
        );
    }
}
