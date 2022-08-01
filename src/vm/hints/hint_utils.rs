use crate::bigint;
use crate::math_utils::as_int;
use crate::math_utils::isqrt;
use crate::relocatable;
use crate::serde::deserialize_program::ApTracking;
use crate::types::exec_scope::PyValueType;
use crate::types::relocatable::Relocatable;
use crate::types::{instruction::Register, relocatable::MaybeRelocatable};
use crate::vm::{
    context::run_context::RunContext, errors::vm_errors::VirtualMachineError,
    hints::execute_hint::HintReference, runners::builtin_runner::RangeCheckBuiltinRunner,
    vm_core::VirtualMachine,
};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{FromPrimitive, Signed, ToPrimitive, Zero};
use std::collections::HashMap;
use std::ops::{Neg, Shl, Shr};

//Returns the value in the current execution scope that matches the name and is of type BigInt
pub fn get_int_from_scope(
    vm: &mut VirtualMachine,
    name: &str,
) -> Result<BigInt, VirtualMachineError> {
    let mut val: Option<BigInt> = None;
    if let Some(variables) = vm.exec_scopes.get_local_variables() {
        if let Some(PyValueType::BigInt(py_val)) = variables.get(name) {
            val = Some(py_val.clone());
        }
    }
    val.ok_or_else(|| VirtualMachineError::NoLocalVariable(name.to_string()))
}

//Returns a mutable reference to the value in the current execution scope that matches the name and is of type BigInt
pub fn get_mut_int_ref_from_scope<'a>(
    vm: &'a mut VirtualMachine,
    name: &'a str,
) -> Result<&'a mut BigInt, VirtualMachineError> {
    let mut val: Option<&'a mut BigInt> = None;
    if let Some(variables) = vm.exec_scopes.get_local_variables() {
        if let Some(PyValueType::BigInt(py_val)) = variables.get_mut(name) {
            val = Some(py_val);
        }
    }
    val.ok_or_else(|| VirtualMachineError::NoLocalVariable(name.to_string()))
}

//Returns a reference to the value in the current execution scope that matches the name and is of type BigInt
pub fn get_int_ref_from_scope<'a>(
    vm: &'a mut VirtualMachine,
    name: &'a str,
) -> Result<&'a BigInt, VirtualMachineError> {
    let mut val: Option<&BigInt> = None;
    if let Some(variables) = vm.exec_scopes.get_local_variables() {
        if let Some(PyValueType::BigInt(py_val)) = variables.get(name) {
            val = Some(py_val);
        }
    }
    val.ok_or_else(|| VirtualMachineError::NoLocalVariable(name.to_string()))
}

pub fn get_u64_from_scope(vm: &mut VirtualMachine, name: &str) -> Result<u64, VirtualMachineError> {
    let mut val: Result<u64, VirtualMachineError> = Err(VirtualMachineError::ScopeError);
    if let Some(variables) = vm.exec_scopes.get_local_variables() {
        if let Some(PyValueType::U64(py_val)) = variables.get(name) {
            val = Ok(*py_val);
        }
    }
    val
}

//Returns the value in the current execution scope that matches the name and is of type List
pub fn get_list_from_scope(
    vm: &mut VirtualMachine,
    name: &str,
) -> Result<Vec<BigInt>, VirtualMachineError> {
    let mut val: Option<Vec<BigInt>> = None;
    if let Some(variables) = vm.exec_scopes.get_local_variables() {
        if let Some(PyValueType::List(py_val)) = variables.get(name) {
            val = Some(py_val.clone());
        }
    }
    val.ok_or_else(|| VirtualMachineError::NoLocalVariable(name.to_string()))
}

//Returns a reference value in the current execution scope that matches the name and is of type List
pub fn get_list_ref_from_scope<'a>(
    vm: &'a mut VirtualMachine,
    name: &'a str,
) -> Result<&'a Vec<BigInt>, VirtualMachineError> {
    let mut val: Option<&'a Vec<BigInt>> = None;
    if let Some(variables) = vm.exec_scopes.get_local_variables() {
        if let Some(PyValueType::List(py_val)) = variables.get(name) {
            val = Some(py_val);
        }
    }
    val.ok_or_else(|| VirtualMachineError::NoLocalVariable(name.to_string()))
}

//Returns a reference value in the current execution scope that matches the name and is of type List
pub fn get_mut_list_ref_from_scope<'a>(
    vm: &'a mut VirtualMachine,
    name: &'a str,
) -> Result<&'a mut Vec<BigInt>, VirtualMachineError> {
    let mut val: Option<&'a mut Vec<BigInt>> = None;
    if let Some(variables) = vm.exec_scopes.get_local_variables() {
        if let Some(PyValueType::List(py_val)) = variables.get_mut(name) {
            val = Some(py_val);
        }
    }
    val.ok_or_else(|| VirtualMachineError::NoLocalVariable(name.to_string()))
}

pub fn get_list_u64_from_scope_ref<'a>(
    vm: &'a mut VirtualMachine,
    name: &'a str,
) -> Result<&'a Vec<u64>, VirtualMachineError> {
    let mut val: Result<&'a Vec<u64>, VirtualMachineError> = Err(VirtualMachineError::ScopeError);
    if let Some(variables) = vm.exec_scopes.get_local_variables() {
        if let Some(PyValueType::ListU64(py_val)) = variables.get(name) {
            val = Ok(py_val);
        }
    }
    val
}

pub fn get_list_u64_from_scope_mut<'a>(
    vm: &'a mut VirtualMachine,
    name: &'a str,
) -> Result<&'a mut Vec<u64>, VirtualMachineError> {
    let mut val: Result<&'a mut Vec<u64>, VirtualMachineError> =
        Err(VirtualMachineError::ScopeError);
    if let Some(variables) = vm.exec_scopes.get_local_variables() {
        if let Some(PyValueType::ListU64(py_val)) = variables.get_mut(name) {
            val = Ok(py_val);
        }
    }
    val
}

pub fn get_dict_int_list_u64_from_scope_mut<'a>(
    vm: &'a mut VirtualMachine,
    name: &'a str,
) -> Result<&'a mut HashMap<BigInt, Vec<u64>>, VirtualMachineError> {
    let mut val: Result<&'a mut HashMap<BigInt, Vec<u64>>, VirtualMachineError> =
        Err(VirtualMachineError::ScopeError);
    if let Some(variables) = vm.exec_scopes.get_local_variables() {
        if let Some(PyValueType::DictBigIntListU64(py_val)) = variables.get_mut(name) {
            val = Ok(py_val);
        }
    }
    val
}

//Returns a reference to the  RangeCheckBuiltinRunner struct if range_check builtin is present
pub fn get_range_check_builtin(
    vm: &VirtualMachine,
) -> Result<&RangeCheckBuiltinRunner, VirtualMachineError> {
    for (name, builtin) in &vm.builtin_runners {
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
    vm: &VirtualMachine,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<Relocatable, VirtualMachineError> {
    let var_addr = get_relocatable_from_var_name(var_name, ids, vm, hint_ap_tracking)?;
    let value = vm.memory.get_relocatable(&var_addr)?;
    //Add immediate if present in reference
    let index = ids
        .get(&String::from(var_name))
        .ok_or(VirtualMachineError::FailedToGetIds)?;
    let hint_reference = vm
        .references
        .get(
            &index
                .to_usize()
                .ok_or(VirtualMachineError::BigintToUsizeFail)?,
        )
        .ok_or(VirtualMachineError::FailedToGetIds)?;
    if let Some(immediate) = &hint_reference.immediate {
        let modified_value = relocatable!(
            value.segment_index,
            value.offset
                + immediate
                    .to_usize()
                    .ok_or(VirtualMachineError::BigintToUsizeFail)?
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
    vm: &VirtualMachine,
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

            match vm.memory.get(&addr) {
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
    vm: &VirtualMachine,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<Option<MaybeRelocatable>, VirtualMachineError> {
    if let Some(index) = reference_id.to_usize() {
        if index < references.len() {
            if let Some(hint_reference) = references.get(&index) {
                return compute_addr_from_reference(
                    hint_reference,
                    run_context,
                    vm,
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
    vm: &VirtualMachine,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<MaybeRelocatable, VirtualMachineError> {
    let var_ref = ids
        .get(&String::from(var_name))
        .ok_or(VirtualMachineError::FailedToGetIds)?;
    get_address_from_reference(
        var_ref,
        &vm.references,
        &vm.run_context,
        vm,
        hint_ap_tracking,
    )
    .map_err(|_| VirtualMachineError::FailedToGetIds)?
    .ok_or(VirtualMachineError::FailedToGetIds)
}

pub fn insert_integer_from_var_name(
    var_name: &str,
    int: BigInt,
    ids: &HashMap<String, BigInt>,
    vm: &mut VirtualMachine,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let var_address = get_address_from_var_name(var_name, ids, vm, hint_ap_tracking)?;
    vm.memory
        .insert(&var_address, &MaybeRelocatable::Int(int))
        .map_err(VirtualMachineError::MemoryError)
}

pub fn insert_relocatable_from_var_name(
    var_name: &str,
    relocatable: Relocatable,
    ids: &HashMap<String, BigInt>,
    vm: &mut VirtualMachine,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let var_address = get_address_from_var_name(var_name, ids, vm, hint_ap_tracking)?;
    vm.memory
        .insert(
            &var_address,
            &MaybeRelocatable::RelocatableValue(relocatable),
        )
        .map_err(VirtualMachineError::MemoryError)
}

//Gets the address of a variable name.
//If the address is an MaybeRelocatable::Relocatable(Relocatable) return Relocatable
//else raises Err
pub fn get_relocatable_from_var_name(
    var_name: &str,
    ids: &HashMap<String, BigInt>,
    vm: &VirtualMachine,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<Relocatable, VirtualMachineError> {
    match get_address_from_var_name(var_name, ids, vm, hint_ap_tracking)? {
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
    vm: &'a VirtualMachine,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<&'a BigInt, VirtualMachineError> {
    let relocatable = get_relocatable_from_var_name(var_name, ids, vm, hint_ap_tracking)?;
    vm.memory.get_integer(&relocatable)
}

// Given a memory address and an offset
// Gets the value of the address + offset
//If the value is an MaybeRelocatable::Int(Bigint) return &Bigint
//else raises Err
pub fn get_integer_from_relocatable_plus_offset<'a>(
    relocatable: &Relocatable,
    field_offset: usize,
    vm: &'a VirtualMachine,
) -> Result<&'a BigInt, VirtualMachineError> {
    vm.memory.get_integer(&(relocatable + field_offset))
}

pub fn get_u64_from_relocatable_plus_offset(
    relocatable: &Relocatable,
    field_offset_u64: u64,
    vm: &VirtualMachine,
) -> Result<u64, VirtualMachineError> {
    let field_offset: usize = field_offset_u64 as usize;
    let int = vm.memory.get_integer(&(relocatable + field_offset))?;
    int.to_u64().ok_or(VirtualMachineError::BigintToU64Fail)
}

pub fn insert_integer_at_relocatable_plus_offset(
    int: BigInt,
    relocatable: &Relocatable,
    field_offset: usize,
    vm: &mut VirtualMachine,
) -> Result<(), VirtualMachineError> {
    vm.memory
        .insert(
            &MaybeRelocatable::RelocatableValue(relocatable + field_offset),
            &MaybeRelocatable::from(int),
        )
        .map_err(VirtualMachineError::MemoryError)
}

///Implements hint: memory[ap] = segments.add()
pub fn add_segment(vm: &mut VirtualMachine) -> Result<(), VirtualMachineError> {
    let new_segment_base =
        MaybeRelocatable::RelocatableValue(vm.segments.add(&mut vm.memory, None));
    vm.memory
        .insert(&vm.run_context.ap, &new_segment_base)
        .map_err(VirtualMachineError::MemoryError)
}

//Implements hint: memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1
pub fn is_nn(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a = get_integer_from_var_name("a", &ids, vm, hint_ap_tracking)?;
    let range_check_builtin = get_range_check_builtin(vm)?;
    //Main logic (assert a is not negative and within the expected range)
    let value = if a.mod_floor(&vm.prime) >= bigint!(0)
        && a.mod_floor(&vm.prime) < range_check_builtin._bound
    {
        bigint!(0)
    } else {
        bigint!(1)
    };
    vm.memory
        .insert(&vm.run_context.ap, &MaybeRelocatable::from(value))
        .map_err(VirtualMachineError::MemoryError)
}

//Implements hint: memory[ap] = 0 if 0 <= ((-ids.a - 1) % PRIME) < range_check_builtin.bound else 1
pub fn is_nn_out_of_range(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a = get_integer_from_var_name("a", &ids, vm, hint_ap_tracking)?;
    let range_check_builtin = get_range_check_builtin(vm)?;
    //Main logic (assert a is not negative and within the expected range)
    let value = if (-a.clone() - 1usize).mod_floor(&vm.prime) < range_check_builtin._bound {
        bigint!(0)
    } else {
        bigint!(1)
    };
    vm.memory
        .insert(&vm.run_context.ap, &MaybeRelocatable::from(value))
        .map_err(VirtualMachineError::MemoryError)
}
//Implements hint:from starkware.cairo.common.math_utils import assert_integer
//        assert_integer(ids.a)
//        assert_integer(ids.b)
//        a = ids.a % PRIME
//        b = ids.b % PRIME
//        assert a <= b, f'a = {a} is not less than or equal to b = {b}.'

//        ids.small_inputs = int(
//            a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)
pub fn assert_le_felt(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a = get_integer_from_var_name("a", &ids, vm, hint_ap_tracking)?;
    let b = get_integer_from_var_name("b", &ids, vm, hint_ap_tracking)?;
    let range_check_builtin = get_range_check_builtin(vm)?;
    //Assert a <= b
    if a.mod_floor(&vm.prime) > b.mod_floor(&vm.prime) {
        return Err(VirtualMachineError::NonLeFelt(a.clone(), b.clone()));
    }
    //Calculate value of small_inputs
    let value = if *a < range_check_builtin._bound && (a - b) < range_check_builtin._bound {
        bigint!(1)
    } else {
        bigint!(0)
    };
    insert_integer_from_var_name("small_inputs", value, &ids, vm, hint_ap_tracking)
}

//Implements hint:from starkware.cairo.common.math_cmp import is_le_felt
//    memory[ap] = 0 if (ids.a % PRIME) <= (ids.b % PRIME) else 1
pub fn is_le_felt(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a_mod = get_integer_from_var_name("a", &ids, vm, hint_ap_tracking)?.mod_floor(&vm.prime);
    let b_mod = get_integer_from_var_name("b", &ids, vm, hint_ap_tracking)?.mod_floor(&vm.prime);
    let value = if a_mod > b_mod {
        bigint!(1)
    } else {
        bigint!(0)
    };
    vm.memory
        .insert(&vm.run_context.ap, &MaybeRelocatable::from(value))
        .map_err(VirtualMachineError::MemoryError)
}

//Implements hint: from starkware.cairo.lang.vm.relocatable import RelocatableValue
//        both_ints = isinstance(ids.a, int) and isinstance(ids.b, int)
//        both_relocatable = (
//            isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and
//            ids.a.segment_index == ids.b.segment_index)
//        assert both_ints or both_relocatable, \
//            f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'
//        assert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'
pub fn assert_not_equal(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a_addr = get_address_from_var_name("a", &ids, vm, hint_ap_tracking)?;
    let b_addr = get_address_from_var_name("b", &ids, vm, hint_ap_tracking)?;
    //Check that the ids are in memory
    match (vm.memory.get(&a_addr), vm.memory.get(&b_addr)) {
        (Ok(Some(maybe_rel_a)), Ok(Some(maybe_rel_b))) => match (maybe_rel_a, maybe_rel_b) {
            (MaybeRelocatable::Int(ref a), MaybeRelocatable::Int(ref b)) => {
                if (a - b).is_multiple_of(&vm.prime) {
                    return Err(VirtualMachineError::AssertNotEqualFail(
                        maybe_rel_a.clone(),
                        maybe_rel_b.clone(),
                    ));
                };
                Ok(())
            }
            (MaybeRelocatable::RelocatableValue(a), MaybeRelocatable::RelocatableValue(b)) => {
                if a.segment_index != b.segment_index {
                    return Err(VirtualMachineError::DiffIndexComp(a.clone(), b.clone()));
                };
                if a.offset == b.offset {
                    return Err(VirtualMachineError::AssertNotEqualFail(
                        maybe_rel_a.clone(),
                        maybe_rel_b.clone(),
                    ));
                };
                Ok(())
            }
            _ => Err(VirtualMachineError::DiffTypeComparison(
                maybe_rel_a.clone(),
                maybe_rel_b.clone(),
            )),
        },
        _ => Err(VirtualMachineError::FailedToGetIds),
    }
}

//Implements hint:
// %{
//     from starkware.cairo.common.math_utils import assert_integer
//     assert_integer(ids.a)
//     assert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'
// %}
pub fn assert_nn(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a = get_integer_from_var_name("a", &ids, vm, hint_ap_tracking)?;
    let range_check_builtin = get_range_check_builtin(vm)?;
    // assert 0 <= ids.a % PRIME < range_check_builtin.bound
    // as prime > 0, a % prime will always be > 0
    if a.mod_floor(&vm.prime) >= range_check_builtin._bound {
        return Err(VirtualMachineError::ValueOutOfRange(a.clone()));
    };
    Ok(())
}

//Implements hint:from starkware.cairo.common.math.cairo
// %{
// from starkware.cairo.common.math_utils import assert_integer
// assert_integer(ids.value)
// assert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'
// %}
pub fn assert_not_zero(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let value = get_integer_from_var_name("value", &ids, vm, hint_ap_tracking)?;
    if value.is_multiple_of(&vm.prime) {
        return Err(VirtualMachineError::AssertNotZero(
            value.clone(),
            vm.prime.clone(),
        ));
    };
    Ok(())
}

//Implements hint: assert ids.value == 0, 'split_int(): value is out of range.'
pub fn split_int_assert_range(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let value = get_integer_from_var_name("value", &ids, vm, hint_ap_tracking)?;
    //Main logic (assert value == 0)
    if !value.is_zero() {
        return Err(VirtualMachineError::SplitIntNotZero);
    }
    Ok(())
}

//Implements hint: memory[ids.output] = res = (int(ids.value) % PRIME) % ids.base
//        assert res < ids.bound, f'split_int(): Limb {res} is out of range.'
pub fn split_int(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let value = get_integer_from_var_name("value", &ids, vm, hint_ap_tracking)?;
    let base = get_integer_from_var_name("base", &ids, vm, hint_ap_tracking)?;
    let bound = get_integer_from_var_name("bound", &ids, vm, hint_ap_tracking)?;
    //Main Logic
    let res = (value.mod_floor(&vm.prime)).mod_floor(base);
    if res > *bound {
        return Err(VirtualMachineError::SplitIntLimbOutOfRange(res));
    }
    insert_integer_from_var_name("output", res, &ids, vm, hint_ap_tracking)
}

//from starkware.cairo.common.math_utils import is_positive
//ids.is_positive = 1 if is_positive(
//    value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0
pub fn is_positive(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let value = get_integer_from_var_name("value", &ids, vm, hint_ap_tracking)?;
    let range_check_builtin = get_range_check_builtin(vm)?;
    //Main logic (assert a is positive)
    let int_value = as_int(value, &vm.prime);
    if int_value.abs() > range_check_builtin._bound {
        return Err(VirtualMachineError::ValueOutsideValidRange(int_value));
    }
    let result = if int_value.is_positive() {
        bigint!(1)
    } else {
        bigint!(0)
    };
    insert_integer_from_var_name("is_positive", result, &ids, vm, hint_ap_tracking)
}

//Implements hint:
// %{
//     from starkware.cairo.common.math_utils import assert_integer
//     assert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128
//     assert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW
//     assert_integer(ids.value)
//     ids.low = ids.value & ((1 << 128) - 1)
//     ids.high = ids.value >> 128
// %}
pub fn split_felt(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let value = get_integer_from_var_name("value", &ids, vm, hint_ap_tracking)?;
    //Main logic
    //assert_integer(ids.value) (done by match)
    // ids.low = ids.value & ((1 << 128) - 1)
    // ids.high = ids.value >> 128
    let low: BigInt = value & ((bigint!(1).shl(128_u8)) - bigint!(1));
    let high: BigInt = value.shr(128_u8);
    insert_integer_from_var_name("high", high, &ids, vm, hint_ap_tracking)?;
    insert_integer_from_var_name("low", low, &ids, vm, hint_ap_tracking)
}

//Implements hint: from starkware.python.math_utils import isqrt
//        value = ids.value % PRIME
//        assert value < 2 ** 250, f"value={value} is outside of the range [0, 2**250)."
//        assert 2 ** 250 < PRIME
//        ids.root = isqrt(value)
pub fn sqrt(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let mod_value =
        get_integer_from_var_name("value", &ids, vm, hint_ap_tracking)?.mod_floor(&vm.prime);
    //This is equal to mod_value > bigint!(2).pow(250)
    if (&mod_value).shr(250_i32).is_positive() {
        return Err(VirtualMachineError::ValueOutside250BitRange(mod_value));
    }
    insert_integer_from_var_name("root", isqrt(&mod_value)?, &ids, vm, hint_ap_tracking)
}

pub fn signed_div_rem(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let div = get_integer_from_var_name("div", &ids, vm, hint_ap_tracking)?;
    let value = get_integer_from_var_name("value", &ids, vm, hint_ap_tracking)?;
    let bound = get_integer_from_var_name("bound", &ids, vm, hint_ap_tracking)?;
    let builtin = get_range_check_builtin(vm)?;
    // Main logic
    if !div.is_positive() || div > &(&vm.prime / &builtin._bound) {
        return Err(VirtualMachineError::OutOfValidRange(
            div.clone(),
            &vm.prime / &builtin._bound,
        ));
    }
    // Divide by 2
    if bound > &(&builtin._bound).shr(1_i32) {
        return Err(VirtualMachineError::OutOfValidRange(
            bound.clone(),
            (&builtin._bound).shr(1_i32),
        ));
    }

    let int_value = &as_int(value, &vm.prime);
    let (q, r) = int_value.div_mod_floor(div);
    if bound.neg() > q || &q >= bound {
        return Err(VirtualMachineError::OutOfValidRange(q, bound.clone()));
    }
    let biased_q = q + bound;
    insert_integer_from_var_name("r", r, &ids, vm, hint_ap_tracking)?;
    insert_integer_from_var_name("biased_q", biased_q, &ids, vm, hint_ap_tracking)
}

/*
Implements hint:

from starkware.cairo.common.math_utils import assert_integer
assert_integer(ids.div)
assert 0 < ids.div <= PRIME // range_check_builtin.bound, \
    f'div={hex(ids.div)} is out of the valid range.'
ids.q, ids.r = divmod(ids.value, ids.div)
*/
pub fn unsigned_div_rem(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let div = get_integer_from_var_name("div", &ids, vm, hint_ap_tracking)?;
    let value = get_integer_from_var_name("value", &ids, vm, hint_ap_tracking)?;
    let builtin = get_range_check_builtin(vm)?;
    // Main logic
    if !div.is_positive() || div > &(&vm.prime / &builtin._bound) {
        return Err(VirtualMachineError::OutOfValidRange(
            div.clone(),
            &vm.prime / &builtin._bound,
        ));
    }
    let (q, r) = value.div_mod_floor(div);
    insert_integer_from_var_name("r", r, &ids, vm, hint_ap_tracking)?;
    insert_integer_from_var_name("q", q, &ids, vm, hint_ap_tracking)
}

//Implements hint: vm_enter_scope()
pub fn enter_scope(vm: &mut VirtualMachine) -> Result<(), VirtualMachineError> {
    vm.exec_scopes.enter_scope(HashMap::new());
    Ok(())
}

//  Implements hint:
//  %{ vm_exit_scope() %}
pub fn exit_scope(vm: &mut VirtualMachine) -> Result<(), VirtualMachineError> {
    vm.exec_scopes
        .exit_scope()
        .map_err(VirtualMachineError::MainScopeError)
}

//  Implements hint:
//  %{ vm_enter_scope({'n': ids.len}) %}
pub fn memcpy_enter_scope(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let len = get_integer_from_var_name("len", &ids, vm, hint_ap_tracking)?.clone();
    vm.exec_scopes.enter_scope(HashMap::from([(
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
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    // get `n` variable from vm scope
    let n = get_int_ref_from_scope(vm, "n")?;
    // this variable will hold the value of `n - 1`
    let new_n = n - bigint!(1_i32);
    // if it is positive, insert 1 in the address of `continue_copying`
    // else, insert 0
    if n.is_positive() {
        insert_integer_from_var_name("continue_copying", bigint!(1), ids, vm, hint_ap_tracking)?;
    } else {
        insert_integer_from_var_name("continue_copying", bigint!(0), ids, vm, hint_ap_tracking)?;
    }
    vm.exec_scopes
        .assign_or_update_variable("n", PyValueType::BigInt(new_n));
    Ok(())
}

//Implements hint: from starkware.cairo.common.math_utils import as_int
//        # Correctness check.
//        value = as_int(ids.value, PRIME) % PRIME
//        assert value < ids.UPPER_BOUND, f'{value} is outside of the range [0, 2**250).'
//        # Calculation for the assertion.
//        ids.high, ids.low = divmod(ids.value, ids.SHIFT)
pub fn assert_250_bit(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    //Declare constant values
    let upper_bound = bigint!(1).shl(250_i32);
    let shift = bigint!(1).shl(128_i32);
    let value = get_integer_from_var_name("value", &ids, vm, hint_ap_tracking)?;
    //Main logic
    let int_value = as_int(value, &vm.prime).mod_floor(&vm.prime);
    if int_value > upper_bound {
        return Err(VirtualMachineError::ValueOutside250BitRange(int_value));
    }
    let (high, low) = int_value.div_rem(&shift);
    insert_integer_from_var_name("high", high, &ids, vm, hint_ap_tracking)?;
    insert_integer_from_var_name("low", high, &ids, vm, hint_ap_tracking)
}

/*
Implements hint:
%{
    from starkware.cairo.common.math_utils import assert_integer
    assert_integer(ids.a)
    assert_integer(ids.b)
    assert (ids.a % PRIME) < (ids.b % PRIME), \
        f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'
%}
*/
pub fn assert_lt_felt(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a = get_integer_from_var_name("a", &ids, vm, hint_ap_tracking)?;
    let b = get_integer_from_var_name("b", &ids, vm, hint_ap_tracking)?;
    // Main logic
    // assert_integer(ids.a)
    // assert_integer(ids.b)
    // assert (ids.a % PRIME) < (ids.b % PRIME), \
    //     f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'
    if a.mod_floor(&vm.prime) >= b.mod_floor(&vm.prime) {
        return Err(VirtualMachineError::AssertLtFelt(a.clone(), b.clone()));
    };
    Ok(())
}

#[cfg(test)]
mod tests {
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

        assert_eq!(
            get_integer_from_var_name(var_name, &ids, &vm, None),
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

        assert_eq!(
            get_integer_from_var_name(var_name, &ids, &vm, None),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn get_integer_from_relocatable_plus_offset_valid() {
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        //Insert value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .unwrap();

        assert_eq!(
            get_integer_from_relocatable_plus_offset(&Relocatable::from((0, 0)), 1, &vm),
            Ok(&bigint!(10))
        );
    }

    #[test]
    fn get_integer_from_relocatable_plus_offset_invalid_expectected_integer() {
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
            false,
        );
        // initialize memory segments
        vm.segments.add(&mut vm.memory, None);

        assert_eq!(
            get_integer_from_relocatable_plus_offset(&Relocatable::from((0, 0)), 1, &vm),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 1))
            ))
        );
    }
}
