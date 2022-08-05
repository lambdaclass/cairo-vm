use crate::bigint;
use crate::relocatable;
use crate::serde::deserialize_program::ApTracking;
use crate::types::exec_scope::ExecutionScopes;
use crate::types::exec_scope::PyValueType;
use crate::types::relocatable::Relocatable;
use crate::types::{instruction::Register, relocatable::MaybeRelocatable};
use crate::vm::runners::builtin_runner::BuiltinRunner;
use crate::vm::vm_core::HintVisibleVariables;
use crate::vm::vm_memory::memory::Memory;
use crate::vm::{
    context::run_context::RunContext, errors::vm_errors::VirtualMachineError,
    hints::execute_hint::HintReference, runners::builtin_runner::RangeCheckBuiltinRunner,
};
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive};
use std::collections::HashMap;

//Tries to convert a BigInt value to usize
pub fn bigint_to_usize(bigint: &BigInt) -> Result<usize, VirtualMachineError> {
    bigint
        .to_usize()
        .ok_or(VirtualMachineError::BigintToUsizeFail)
}

//Tries to convert a BigInt value to U32
pub fn bigint_to_u32(bigint: &BigInt) -> Result<u32, VirtualMachineError> {
    bigint.to_u32().ok_or(VirtualMachineError::BigintToU32Fail)
}

//Inserts value into ap
pub fn insert_int_into_ap(
    memory: &mut Memory,
    run_context: &RunContext,
    value: BigInt,
) -> Result<(), VirtualMachineError> {
    memory
        .insert(&run_context.ap, &MaybeRelocatable::from(value))
        .map_err(VirtualMachineError::MemoryError)
}

//Inserts the value in scope as a BigInt value type
pub fn insert_int_into_scope(exec_scopes: &mut ExecutionScopes, name: &str, value: BigInt) {
    exec_scopes.assign_or_update_variable(name, PyValueType::BigInt(value));
}

//Inserts the list in scope as a List value type
pub fn insert_list_into_scope(exec_scopes: &mut ExecutionScopes, name: &str, list: Vec<BigInt>) {
    exec_scopes.assign_or_update_variable(name, PyValueType::List(list));
}

//Returns the value in the current execution scope that matches the name and is of type BigInt
pub fn get_int_from_scope(
    exec_scopes: &ExecutionScopes,
    name: &str,
) -> Result<BigInt, VirtualMachineError> {
    let mut val: Option<BigInt> = None;
    if let Some(variables) = exec_scopes.get_local_variables() {
        if let Some(PyValueType::BigInt(py_val)) = variables.get(name) {
            val = Some(py_val.clone());
        }
    }
    val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError(name.to_string()))
}

//Returns a mutable reference to the value in the current execution scope that matches the name and is of type BigInt
pub fn get_mut_int_ref_from_scope<'a>(
    exec_scopes: &'a mut ExecutionScopes,
    name: &'a str,
) -> Result<&'a mut BigInt, VirtualMachineError> {
    let mut val: Option<&'a mut BigInt> = None;
    if let Some(variables) = exec_scopes.get_local_variables_mut() {
        if let Some(PyValueType::BigInt(py_val)) = variables.get_mut(name) {
            val = Some(py_val);
        }
    }
    val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError(name.to_string()))
}

//Returns a reference to the value in the current execution scope that matches the name and is of type BigInt
pub fn get_int_ref_from_scope<'a>(
    exec_scopes: &'a ExecutionScopes,
    name: &'a str,
) -> Result<&'a BigInt, VirtualMachineError> {
    let mut val: Option<&BigInt> = None;
    if let Some(variables) = exec_scopes.get_local_variables() {
        if let Some(PyValueType::BigInt(py_val)) = variables.get(name) {
            val = Some(py_val);
        }
    }
    val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError(name.to_string()))
}

pub fn get_u64_from_scope(
    exec_scopes: &ExecutionScopes,
    name: &str,
) -> Result<u64, VirtualMachineError> {
    let mut val: Result<u64, VirtualMachineError> = Err(VirtualMachineError::ScopeError);
    if let Some(variables) = exec_scopes.get_local_variables() {
        if let Some(PyValueType::U64(py_val)) = variables.get(name) {
            val = Ok(*py_val);
        }
    }
    val
}

//Returns the value in the current execution scope that matches the name and is of type List
pub fn get_list_from_scope(
    exec_scopes: &ExecutionScopes,
    name: &str,
) -> Result<Vec<BigInt>, VirtualMachineError> {
    let mut val: Option<Vec<BigInt>> = None;
    if let Some(variables) = exec_scopes.get_local_variables() {
        if let Some(PyValueType::List(py_val)) = variables.get(name) {
            val = Some(py_val.clone());
        }
    }
    val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError(name.to_string()))
}

//Returns a reference value in the current execution scope that matches the name and is of type List
pub fn get_list_ref_from_scope<'a>(
    exec_scopes: &'a ExecutionScopes,
    name: &'a str,
) -> Result<&'a Vec<BigInt>, VirtualMachineError> {
    let mut val: Option<&'a Vec<BigInt>> = None;
    if let Some(variables) = exec_scopes.get_local_variables() {
        if let Some(PyValueType::List(py_val)) = variables.get(name) {
            val = Some(py_val);
        }
    }
    val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError(name.to_string()))
}

//Returns a reference value in the current execution scope that matches the name and is of type List
pub fn get_mut_list_ref_from_scope<'a>(
    exec_scopes: &'a mut ExecutionScopes,
    name: &'a str,
) -> Result<&'a mut Vec<BigInt>, VirtualMachineError> {
    let mut val: Option<&'a mut Vec<BigInt>> = None;
    if let Some(variables) = exec_scopes.get_local_variables_mut() {
        if let Some(PyValueType::List(py_val)) = variables.get_mut(name) {
            val = Some(py_val);
        }
    }
    val.ok_or_else(|| VirtualMachineError::VariableNotInScopeError(name.to_string()))
}

pub fn get_list_u64_from_scope_ref<'a>(
    exec_scopes: &'a ExecutionScopes,
    name: &'a str,
) -> Result<&'a Vec<u64>, VirtualMachineError> {
    let mut val: Result<&'a Vec<u64>, VirtualMachineError> = Err(VirtualMachineError::ScopeError);
    if let Some(variables) = exec_scopes.get_local_variables() {
        if let Some(PyValueType::ListU64(py_val)) = variables.get(name) {
            val = Ok(py_val);
        }
    }
    val
}

pub fn get_list_u64_from_scope_mut<'a>(
    exec_scopes: &'a mut ExecutionScopes,
    name: &'a str,
) -> Result<&'a mut Vec<u64>, VirtualMachineError> {
    let mut val: Result<&'a mut Vec<u64>, VirtualMachineError> =
        Err(VirtualMachineError::ScopeError);
    if let Some(variables) = exec_scopes.get_local_variables_mut() {
        if let Some(PyValueType::ListU64(py_val)) = variables.get_mut(name) {
            val = Ok(py_val);
        }
    }
    val
}

pub fn get_dict_int_list_u64_from_scope_mut<'a>(
    exec_scopes: &'a mut ExecutionScopes,
    name: &'a str,
) -> Result<&'a mut HashMap<BigInt, Vec<u64>>, VirtualMachineError> {
    let mut val: Result<&'a mut HashMap<BigInt, Vec<u64>>, VirtualMachineError> =
        Err(VirtualMachineError::ScopeError);
    if let Some(variables) = exec_scopes.get_local_variables_mut() {
        if let Some(PyValueType::DictBigIntListU64(py_val)) = variables.get_mut(name) {
            val = Ok(py_val);
        }
    }
    val
}

//Returns a reference to the  RangeCheckBuiltinRunner struct if range_check builtin is present
pub fn get_range_check_builtin(
    builtin_runners: &Vec<(String, Box<dyn BuiltinRunner>)>,
) -> Result<&RangeCheckBuiltinRunner, VirtualMachineError> {
    for (name, builtin) in builtin_runners {
        if name == &String::from("range_check") {
            if let Some(range_check_builtin) =
                builtin.as_any().downcast_ref::<RangeCheckBuiltinRunner>()
            {
                return Ok(range_check_builtin);
            };
        }
    }
    Err(VirtualMachineError::NoRangeCheckBuiltin)
}

pub fn get_ptr_from_var_name(
    var_name: &str,
    ids: &HashMap<String, BigInt>,
    memory: &Memory,
    references: &HashMap<usize, HintReference>,
    run_context: &RunContext,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<Relocatable, VirtualMachineError> {
    let var_addr = get_relocatable_from_var_name(
        var_name,
        ids,
        memory,
        references,
        run_context,
        hint_ap_tracking,
    )?;
    let value = memory.get_relocatable(&var_addr)?;
    //Add immediate if present in reference
    let index = ids
        .get(&String::from(var_name))
        .ok_or(VirtualMachineError::FailedToGetIds)?;
    let hint_reference = references
        .get(
            &index
                .to_usize()
                .ok_or(VirtualMachineError::BigintToUsizeFail)?,
        )
        .ok_or(VirtualMachineError::FailedToGetIds)?;
    if let Some(immediate) = &hint_reference.immediate {
        let modified_value = relocatable!(
            value.segment_index,
            value.offset + bigint_to_usize(immediate)?
        );
        return Ok(modified_value);
    }
    Ok(value.clone())
}

fn apply_ap_tracking_correction(
    ap: &Relocatable,
    ref_ap_tracking: &ApTracking,
    hint_ap_tracking: &ApTracking,
) -> Result<MaybeRelocatable, VirtualMachineError> {
    // check that both groups are the same
    if ref_ap_tracking.group != hint_ap_tracking.group {
        return Err(VirtualMachineError::InvalidTrackingGroup(
            ref_ap_tracking.group,
            hint_ap_tracking.group,
        ));
    }
    let ap_diff = hint_ap_tracking.offset - ref_ap_tracking.offset;

    Ok(MaybeRelocatable::from((
        ap.segment_index,
        ap.offset - ap_diff,
    )))
}

///Computes the memory address indicated by the HintReference
pub fn compute_addr_from_reference(
    hint_reference: &HintReference,
    run_context: &RunContext,
    memory: &Memory,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<Option<MaybeRelocatable>, VirtualMachineError> {
    let base_addr = match hint_reference.register {
        Register::FP => run_context.fp.clone(),
        Register::AP => {
            if hint_ap_tracking.is_none() || hint_reference.ap_tracking_data.is_none() {
                return Err(VirtualMachineError::NoneApTrackingData);
            }

            if let MaybeRelocatable::RelocatableValue(ref relocatable) = run_context.ap {
                apply_ap_tracking_correction(
                    relocatable,
                    // it is safe to call these unrwaps here, since it has been checked
                    // they are not None's
                    // this could be refactored to use pattern match but it will be
                    // unnecesarily verbose
                    hint_reference.ap_tracking_data.as_ref().unwrap(),
                    hint_ap_tracking.unwrap(),
                )?
            } else {
                return Err(VirtualMachineError::InvalidApValue(run_context.ap.clone()));
            }
        }
    };

    if let MaybeRelocatable::RelocatableValue(relocatable) = base_addr {
        if hint_reference.offset1.is_negative()
            && relocatable.offset < hint_reference.offset1.abs() as usize
        {
            return Ok(None);
        }
        if !hint_reference.inner_dereference {
            return Ok(Some(MaybeRelocatable::from((
                relocatable.segment_index,
                (relocatable.offset as i32 + hint_reference.offset1 + hint_reference.offset2)
                    as usize,
            ))));
        } else {
            let addr = MaybeRelocatable::from((
                relocatable.segment_index,
                (relocatable.offset as i32 + hint_reference.offset1) as usize,
            ));

            match memory.get(&addr) {
                Ok(Some(&MaybeRelocatable::RelocatableValue(ref dereferenced_addr))) => {
                    return Ok(Some(MaybeRelocatable::from((
                        dereferenced_addr.segment_index,
                        (dereferenced_addr.offset as i32 + hint_reference.offset2) as usize,
                    ))))
                }

                _none_or_error => return Ok(None),
            }
        }
    }

    Ok(None)
}

///Computes the memory address given by the reference id
pub fn get_address_from_reference(
    reference_id: &BigInt,
    references: &HashMap<usize, HintReference>,
    run_context: &RunContext,
    memory: &Memory,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<Option<MaybeRelocatable>, VirtualMachineError> {
    if let Some(index) = reference_id.to_usize() {
        if index < references.len() {
            if let Some(hint_reference) = references.get(&index) {
                return compute_addr_from_reference(
                    hint_reference,
                    run_context,
                    memory,
                    hint_ap_tracking,
                );
            }
        }
    }
    Ok(None)
}

pub fn get_address_from_var_name(
    var_name: &str,
    ids: &HashMap<String, BigInt>,
    memory: &Memory,
    references: &HashMap<usize, HintReference>,
    run_context: &RunContext,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<MaybeRelocatable, VirtualMachineError> {
    let var_ref = ids
        .get(&String::from(var_name))
        .ok_or(VirtualMachineError::FailedToGetIds)?;
    get_address_from_reference(var_ref, references, run_context, memory, hint_ap_tracking)
        .map_err(|_| VirtualMachineError::FailedToGetIds)?
        .ok_or(VirtualMachineError::FailedToGetIds)
}

pub fn insert_integer_from_var_name(
    var_name: &str,
    int: BigInt,
    ids: &HashMap<String, BigInt>,
    memory: &mut Memory,
    references: &HashMap<usize, HintReference>,
    run_context: &RunContext,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let var_address = get_relocatable_from_var_name(
        var_name,
        ids,
        memory,
        references,
        run_context,
        hint_ap_tracking,
    )?;
    memory.insert_integer(&var_address, int)
}

pub fn insert_relocatable_from_var_name(
    var_name: &str,
    relocatable: Relocatable,
    ids: &HashMap<String, BigInt>,
    memory: &mut Memory,
    references: &HashMap<usize, HintReference>,
    run_context: &RunContext,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let var_address = get_relocatable_from_var_name(
        var_name,
        ids,
        memory,
        references,
        run_context,
        hint_ap_tracking,
    )?;
    memory.insert_relocatable(&var_address, &relocatable)
}

//Gets the address of a variable name.
//If the address is an MaybeRelocatable::Relocatable(Relocatable) return Relocatable
//else raises Err
pub fn get_relocatable_from_var_name(
    var_name: &str,
    ids: &HashMap<String, BigInt>,
    memory: &Memory,
    references: &HashMap<usize, HintReference>,
    run_context: &RunContext,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<Relocatable, VirtualMachineError> {
    match get_address_from_var_name(
        var_name,
        ids,
        memory,
        references,
        run_context,
        hint_ap_tracking,
    )? {
        MaybeRelocatable::RelocatableValue(relocatable) => Ok(relocatable),
        address => Err(VirtualMachineError::ExpectedRelocatable(address)),
    }
}

//Gets the value of a variable name.
//If the value is an MaybeRelocatable::Int(Bigint) return &Bigint
//else raises Err
pub fn get_integer_from_var_name<'a>(
    var_name: &str,
    ids: &HashMap<String, BigInt>,
    memory: &'a Memory,
    references: &HashMap<usize, HintReference>,
    run_context: &RunContext,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<&'a BigInt, VirtualMachineError> {
    let relocatable = get_relocatable_from_var_name(
        var_name,
        ids,
        memory,
        references,
        run_context,
        hint_ap_tracking,
    )?;
    memory.get_integer(&relocatable)
}

///Implements hint: memory[ap] = segments.add()
pub fn add_segment(variables: &mut HintVisibleVariables) -> Result<(), VirtualMachineError> {
    let new_segment_base =
        MaybeRelocatable::RelocatableValue(variables.segments.add(variables.memory, None));
    variables
        .memory
        .insert(&variables.run_context.ap, &new_segment_base)
        .map_err(VirtualMachineError::MemoryError)
}

//Implements hint: vm_enter_scope()
pub fn enter_scope(variables: &mut HintVisibleVariables) -> Result<(), VirtualMachineError> {
    variables.exec_scopes.enter_scope(HashMap::new());
    Ok(())
}

//  Implements hint:
//  %{ vm_exit_scope() %}
pub fn exit_scope(variables: &mut HintVisibleVariables) -> Result<(), VirtualMachineError> {
    variables
        .exec_scopes
        .exit_scope()
        .map_err(VirtualMachineError::MainScopeError)
}

//  Implements hint:
//  %{ vm_enter_scope({'n': ids.len}) %}
pub fn memcpy_enter_scope(
    variables: &mut HintVisibleVariables,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let len = get_integer_from_var_name(
        "len",
        ids,
        variables.memory,
        variables.references,
        variables.run_context,
        hint_ap_tracking,
    )?
    .clone();
    variables.exec_scopes.enter_scope(HashMap::from([(
        String::from("n"),
        PyValueType::BigInt(len),
    )]));

    Ok(())
}

// Implements hint:
// %{
//     n -= 1
//     ids.continue_copying = 1 if n > 0 else 0
// %}
pub fn memcpy_continue_copying(
    variables: &mut HintVisibleVariables,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    // get `n` variable from vm scope
    let n = get_int_ref_from_scope(variables.exec_scopes, "n")?;
    // this variable will hold the value of `n - 1`
    let new_n = n - 1_i32;
    // if it is positive, insert 1 in the address of `continue_copying`
    // else, insert 0
    if new_n.is_positive() {
        insert_integer_from_var_name(
            "continue_copying",
            bigint!(1),
            ids,
            variables.memory,
            variables.references,
            variables.run_context,
            hint_ap_tracking,
        )?;
    } else {
        insert_integer_from_var_name(
            "continue_copying",
            bigint!(0),
            ids,
            variables.memory,
            variables.references,
            variables.run_context,
            hint_ap_tracking,
        )?;
    }
    variables
        .exec_scopes
        .assign_or_update_variable("n", PyValueType::BigInt(new_n));
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::vm::{hints::execute_hint::get_hint_variables, vm_core::VirtualMachine};

    use super::*;
    use num_bigint::Sign;

    #[test]
    fn get_integer_from_var_name_valid() {
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 2));

        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -2,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);

        let var_name: &str = "variable";

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("variable"), bigint!(0));

        //Insert ids.prev_locs.exp into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .unwrap();
        let variables = get_hint_variables(&mut vm);
        assert_eq!(
            get_integer_from_var_name(
                var_name,
                &ids,
                variables.memory,
                variables.references,
                variables.run_context,
                None
            ),
            Ok(&bigint!(10))
        );
    }

    #[test]
    fn get_integer_from_var_name_invalid_expected_integer() {
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        // initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 2));

        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -2,
                offset2: 0,
                inner_dereference: false,
                ap_tracking_data: None,
                immediate: None,
            },
        )]);

        let var_name: &str = "variable";

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("variable"), bigint!(0));

        //Insert ids.variable into memory as a RelocatableValue
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((0, 1)),
            )
            .unwrap();
        let variables = get_hint_variables(&mut vm);
        assert_eq!(
            get_integer_from_var_name(
                var_name,
                &ids,
                variables.memory,
                variables.references,
                variables.run_context,
                None
            ),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }
}
