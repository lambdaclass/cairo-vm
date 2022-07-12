use crate::types::{instruction::Register, relocatable::MaybeRelocatable};
use crate::vm::{
    context::run_context::RunContext, errors::vm_errors::VirtualMachineError,
    runners::builtin_runner::RangeCheckBuiltinRunner, vm_core::VirtualMachine,
};
use crate::{bigint, vm::hints::execute_hint::HintReference};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{FromPrimitive, ToPrimitive};
use num_traits::{Signed, Zero};
use std::collections::HashMap;

///Computes the memory address indicated by the HintReference
fn compute_addr_from_reference(
    hint_reference: &HintReference,
    run_context: &RunContext,
) -> Option<MaybeRelocatable> {
    let register = match hint_reference.register {
        Register::FP => run_context.fp.clone(),
        Register::AP => run_context.ap.clone(),
    };
    if let MaybeRelocatable::RelocatableValue(relocatable) = register {
        if hint_reference.offset.is_negative()
            && relocatable.offset < hint_reference.offset.abs() as usize
        {
            return None;
        }
        return Some(MaybeRelocatable::from((
            relocatable.segment_index,
            (relocatable.offset as i32 + hint_reference.offset) as usize,
        )));
    }
    None
}

///Computes the memory address given by the reference id
fn get_address_from_reference(
    reference_id: &BigInt,
    references: &Vec<HintReference>,
    run_context: &RunContext,
) -> Option<MaybeRelocatable> {
    if let Some(index) = reference_id.to_usize() {
        if index < references.len() {
            return compute_addr_from_reference(&references[index], run_context);
        }
    }
    None
}

///Implements hint: memory[ap] = segments.add()
pub fn add_segment(vm: &mut VirtualMachine) -> Result<(), VirtualMachineError> {
    let new_segment_base =
        MaybeRelocatable::RelocatableValue(vm.segments.add(&mut vm.memory, None));
    match vm.memory.insert(&vm.run_context.ap, &new_segment_base) {
        Ok(_) => Ok(()),
        Err(memory_error) => Err(VirtualMachineError::MemoryError(memory_error)),
    }
}

//Implements hint: memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1
pub fn is_nn(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    //Check that ids contains the reference id for each variable used by the hint
    let a_ref = if let Some(a_ref) = ids.get(&String::from("a")) {
        a_ref
    } else {
        return Err(VirtualMachineError::IncorrectIds(
            vec![String::from("a")],
            ids.into_keys().collect(),
        ));
    };
    //Check that each reference id corresponds to a value in the reference manager
    let a_addr =
        if let Some(a_addr) = get_address_from_reference(a_ref, &vm.references, &vm.run_context) {
            a_addr
        } else {
            return Err(VirtualMachineError::FailedToGetReference(a_ref.clone()));
        };
    //Check that the ids are in memory
    match vm.memory.get(&a_addr) {
        Ok(Some(maybe_rel_a)) => {
            //Check that the value at the ids address is an Int
            let a = if let MaybeRelocatable::Int(ref a) = maybe_rel_a {
                a
            } else {
                return Err(VirtualMachineError::ExpectedInteger(a_addr.clone()));
            };
            for (name, builtin) in &vm.builtin_runners {
                //Check that range_check_builtin is present
                if name == &String::from("range_check") {
                    let range_check_builtin = if let Some(range_check_builtin) =
                        builtin.as_any().downcast_ref::<RangeCheckBuiltinRunner>()
                    {
                        range_check_builtin
                    } else {
                        return Err(VirtualMachineError::NoRangeCheckBuiltin);
                    };
                    //Main logic (assert a is not negative and within the expected range)
                    let mut value = bigint!(1);
                    if a.mod_floor(&vm.prime) >= bigint!(0)
                        && a.mod_floor(&vm.prime) < range_check_builtin._bound
                    {
                        value = bigint!(0);
                    }
                    return match vm
                        .memory
                        .insert(&vm.run_context.ap, &MaybeRelocatable::from(value))
                    {
                        Ok(_) => Ok(()),
                        Err(memory_error) => Err(VirtualMachineError::MemoryError(memory_error)),
                    };
                }
            }
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        }
        Ok(None) => Err(VirtualMachineError::MemoryGet(a_addr.clone())),
        Err(memory_error) => Err(VirtualMachineError::MemoryError(memory_error)),
    }
}

//Implements hint: memory[ap] = 0 if 0 <= ((-ids.a - 1) % PRIME) < range_check_builtin.bound else 1
pub fn is_nn_out_of_range(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    //Check that ids contains the reference id for each variable used by the hint
    let a_ref = if let Some(a_ref) = ids.get(&String::from("a")) {
        a_ref
    } else {
        return Err(VirtualMachineError::IncorrectIds(
            vec![String::from("a")],
            ids.into_keys().collect(),
        ));
    };
    //Check that each reference id corresponds to a value in the reference manager
    let a_addr =
        if let Some(a_addr) = get_address_from_reference(a_ref, &vm.references, &vm.run_context) {
            a_addr
        } else {
            return Err(VirtualMachineError::FailedToGetReference(a_ref.clone()));
        };
    //Check that the ids are in memory
    match vm.memory.get(&a_addr) {
        Ok(Some(maybe_rel_a)) => {
            //Check that the value at the ids address is an Int
            let a = if let MaybeRelocatable::Int(ref a) = maybe_rel_a {
                a
            } else {
                return Err(VirtualMachineError::ExpectedInteger(a_addr.clone()));
            };
            for (name, builtin) in &vm.builtin_runners {
                //Check that range_check_builtin is present
                if name == &String::from("range_check") {
                    let range_check_builtin = if let Some(range_check_builtin) =
                        builtin.as_any().downcast_ref::<RangeCheckBuiltinRunner>()
                    {
                        range_check_builtin
                    } else {
                        return Err(VirtualMachineError::NoRangeCheckBuiltin);
                    };
                    //Main logic (assert a is not negative and within the expected range)
                    let mut value = bigint!(1);
                    if (-a.clone() - bigint!(1)).mod_floor(&vm.prime) >= bigint!(0)
                        && (-a.clone() - bigint!(1)).mod_floor(&vm.prime)
                            < range_check_builtin._bound
                    {
                        value = bigint!(0);
                    }
                    return match vm
                        .memory
                        .insert(&vm.run_context.ap, &MaybeRelocatable::from(value))
                    {
                        Ok(_) => Ok(()),
                        Err(memory_error) => Err(VirtualMachineError::MemoryError(memory_error)),
                    };
                }
            }
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        }
        Ok(None) => Err(VirtualMachineError::MemoryGet(a_addr.clone())),
        Err(memory_error) => Err(VirtualMachineError::MemoryError(memory_error)),
    }
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
) -> Result<(), VirtualMachineError> {
    //Check that ids contains the reference id for each variable used by the hint
    let (a_ref, b_ref, small_inputs_ref) =
        if let (Some(a_ref), Some(b_ref), Some(small_inputs_ref)) = (
            ids.get(&String::from("a")),
            ids.get(&String::from("b")),
            ids.get(&String::from("small_inputs")),
        ) {
            (a_ref, b_ref, small_inputs_ref)
        } else {
            return Err(VirtualMachineError::IncorrectIds(
                vec![
                    String::from("a"),
                    String::from("b"),
                    String::from("small_inputs"),
                ],
                ids.into_keys().collect(),
            ));
        };
    //Check that each reference id corresponds to a value in the reference manager
    let (a_addr, b_addr, small_inputs_addr) =
        if let (Some(a_addr), Some(b_addr), Some(small_inputs_addr)) = (
            get_address_from_reference(a_ref, &vm.references, &vm.run_context),
            get_address_from_reference(b_ref, &vm.references, &vm.run_context),
            get_address_from_reference(small_inputs_ref, &vm.references, &vm.run_context),
        ) {
            (a_addr, b_addr, small_inputs_addr)
        } else {
            return Err(VirtualMachineError::FailedToGetIds);
        };
    //Check that the ids are in memory (except for small_inputs which is local, and should contain None)
    //small_inputs needs to be None, as we cant change it value otherwise
    match (
        vm.memory.get(&a_addr),
        vm.memory.get(&b_addr),
        vm.memory.get(&small_inputs_addr),
    ) {
        (Ok(Some(maybe_rel_a)), Ok(Some(maybe_rel_b)), Ok(None)) => {
            //Check that the values at the ids address are Int
            let a = if let &MaybeRelocatable::Int(ref a) = maybe_rel_a {
                a
            } else {
                return Err(VirtualMachineError::ExpectedInteger(a_addr.clone()));
            };
            let b = if let MaybeRelocatable::Int(ref b) = maybe_rel_b {
                b
            } else {
                return Err(VirtualMachineError::ExpectedInteger(b_addr.clone()));
            };
            for (name, builtin) in &vm.builtin_runners {
                //Check that range_check_builtin is present
                if name == &String::from("range_check") {
                    match builtin.as_any().downcast_ref::<RangeCheckBuiltinRunner>() {
                        None => return Err(VirtualMachineError::NoRangeCheckBuiltin),
                        Some(builtin) => {
                            //Assert a <= b
                            if a.mod_floor(&vm.prime) > b.mod_floor(&vm.prime) {
                                return Err(VirtualMachineError::NonLeFelt(a.clone(), b.clone()));
                            }
                            //Calculate value of small_inputs
                            let mut value = bigint!(0);
                            if *a < builtin._bound && (a - b) < builtin._bound {
                                value = bigint!(1);
                            }
                            match vm
                                .memory
                                .insert(&small_inputs_addr, &MaybeRelocatable::from(value))
                            {
                                Ok(_) => return Ok(()),
                                Err(memory_error) => {
                                    return Err(VirtualMachineError::MemoryError(memory_error))
                                }
                            }
                        }
                    }
                }
            }
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        }
        _ => Err(VirtualMachineError::FailedToGetIds),
    }
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
) -> Result<(), VirtualMachineError> {
    //Check that ids contains the reference id for each variable used by the hint
    let (a_ref, b_ref) = if let (Some(a_ref), Some(b_ref)) =
        (ids.get(&String::from("a")), ids.get(&String::from("b")))
    {
        (a_ref, b_ref)
    } else {
        return Err(VirtualMachineError::IncorrectIds(
            vec![String::from("a"), String::from("b")],
            ids.into_keys().collect(),
        ));
    };
    //Check that each reference id corresponds to a value in the reference manager
    let (a_addr, b_addr) = if let (Some(a_addr), Some(b_addr)) = (
        get_address_from_reference(a_ref, &vm.references, &vm.run_context),
        get_address_from_reference(b_ref, &vm.references, &vm.run_context),
    ) {
        (a_addr, b_addr)
    } else {
        return Err(VirtualMachineError::FailedToGetIds);
    };
    //Check that the ids are in memory
    match (vm.memory.get(&a_addr), vm.memory.get(&b_addr)) {
        (Ok(Some(maybe_rel_a)), Ok(Some(maybe_rel_b))) => match (maybe_rel_a, maybe_rel_b) {
            (MaybeRelocatable::Int(ref a), MaybeRelocatable::Int(ref b)) => {
                if (a - b).mod_floor(&vm.prime) == bigint!(0) {
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
) -> Result<(), VirtualMachineError> {
    //Check that ids contains the reference id for 'a' variable used by the hint
    let a_ref = if let Some(a_ref) = ids.get(&String::from("a")) {
        a_ref
    } else {
        return Err(VirtualMachineError::IncorrectIds(
            vec![String::from("a")],
            ids.into_keys().collect(),
        ));
    };
    //Check that 'a' reference id corresponds to a value in the reference manager
    let a_addr =
        if let Some(a_addr) = get_address_from_reference(a_ref, &vm.references, &vm.run_context) {
            a_addr
        } else {
            return Err(VirtualMachineError::FailedToGetIds);
        };

    //Check that the 'a' id is in memory
    let maybe_rel_a = if let Ok(Some(maybe_rel_a)) = vm.memory.get(&a_addr) {
        maybe_rel_a
    } else {
        return Err(VirtualMachineError::FailedToGetIds);
    };

    //assert_integer(ids.a)
    let a = if let &MaybeRelocatable::Int(ref a) = maybe_rel_a {
        a
    } else {
        return Err(VirtualMachineError::ExpectedInteger(a_addr.clone()));
    };

    for (name, builtin) in &vm.builtin_runners {
        //Check that range_check_builtin is present
        if name == &String::from("range_check") {
            let range_check_builtin = if let Some(range_check_builtin) =
                builtin.as_any().downcast_ref::<RangeCheckBuiltinRunner>()
            {
                range_check_builtin
            } else {
                return Err(VirtualMachineError::NoRangeCheckBuiltin);
            };

            // assert 0 <= ids.a % PRIME < range_check_builtin.bound
            if a.mod_floor(&vm.prime).is_positive()
                && a.mod_floor(&vm.prime) < range_check_builtin._bound
            {
                return Ok(());
            } else {
                return Err(VirtualMachineError::ValueOutOfRange(a.clone()));
            }
        }
    }
    Err(VirtualMachineError::NoRangeCheckBuiltin)
}
//Implements hint: assert ids.value == 0, 'split_int(): value is out of range.'
pub fn split_int_assert_range(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    //Check that ids contains the reference id for each variable used by the hint
    let value_ref = if let Some(value_ref) = ids.get(&String::from("value")) {
        value_ref
    } else {
        return Err(VirtualMachineError::IncorrectIds(
            vec![String::from("value")],
            ids.into_keys().collect(),
        ));
    };
    //Check that each reference id corresponds to a value in the reference manager
    let value_addr = if let Some(value_addr) =
        get_address_from_reference(value_ref, &vm.references, &vm.run_context)
    {
        value_addr
    } else {
        return Err(VirtualMachineError::FailedToGetReference(value_ref.clone()));
    };
    //Check that the ids are in memory
    match vm.memory.get(&value_addr) {
        Ok(Some(maybe_rel_value)) => {
            //Check that the value at the ids address is an Int
            let value = if let MaybeRelocatable::Int(ref value) = maybe_rel_value {
                value
            } else {
                return Err(VirtualMachineError::ExpectedInteger(value_addr.clone()));
            };
            //Main logic (assert value == 0)
            if !value.is_zero() {
                return Err(VirtualMachineError::SplitIntNotZero);
            }
            Ok(())
        }
        Ok(None) => Err(VirtualMachineError::MemoryGet(value_addr.clone())),
        Err(memory_error) => Err(VirtualMachineError::MemoryError(memory_error)),
    }
}

//Implements hint: memory[ids.output] = res = (int(ids.value) % PRIME) % ids.base
//        assert res < ids.bound, f'split_int(): Limb {res} is out of range.'
pub fn split_int(
    vm: &mut VirtualMachine,
    ids: HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    //Check that ids contains the reference id for each variable used by the hint
    let (output_ref, value_ref, base_ref, bound_ref) =
        if let (Some(output_ref), Some(value_ref), Some(base_ref), Some(bound_ref)) = (
            ids.get(&String::from("output")),
            ids.get(&String::from("value")),
            ids.get(&String::from("base")),
            ids.get(&String::from("bound")),
        ) {
            (output_ref, value_ref, base_ref, bound_ref)
        } else {
            return Err(VirtualMachineError::IncorrectIds(
                vec![
                    String::from("output"),
                    String::from("value"),
                    String::from("base"),
                    String::from("bound"),
                ],
                ids.into_keys().collect(),
            ));
        };
    //Check that each reference id corresponds to a value in the reference manager
    let (output_addr, value_addr, base_addr, bound_addr) =
        if let (Some(output_addr), Some(value_addr), Some(base_addr), Some(bound_addr)) = (
            get_address_from_reference(output_ref, &vm.references, &vm.run_context),
            get_address_from_reference(value_ref, &vm.references, &vm.run_context),
            get_address_from_reference(base_ref, &vm.references, &vm.run_context),
            get_address_from_reference(bound_ref, &vm.references, &vm.run_context),
        ) {
            (output_addr, value_addr, base_addr, bound_addr)
        } else {
            return Err(VirtualMachineError::FailedToGetIds);
        };
    //Check that the ids are in memory
    let (mr_output, mr_value, mr_base, mr_bound) =
        if let (Ok(Some(mr_output)), Ok(Some(mr_value)), Ok(Some(mr_base)), Ok(Some(mr_bound))) = (
            vm.memory.get(&output_addr),
            vm.memory.get(&value_addr),
            vm.memory.get(&base_addr),
            vm.memory.get(&bound_addr),
        ) {
            (mr_output, mr_value, mr_base, mr_bound)
        } else {
            return Err(VirtualMachineError::FailedToGetIds);
        };
    //Check that the type of the ids
    let (output, value, base, bound) = if let (
        MaybeRelocatable::RelocatableValue(output),
        MaybeRelocatable::Int(value),
        MaybeRelocatable::Int(base),
        MaybeRelocatable::Int(bound),
    ) = (mr_output, mr_value, mr_base, mr_bound)
    {
        (output, value, base, bound)
    } else {
        return Err(VirtualMachineError::FailedToGetIds);
    };
    //Main Logic
    let res = (value.mod_floor(&vm.prime)).mod_floor(base);
    if res > *bound {
        return Err(VirtualMachineError::SplitIntLimbOutOfRange(res));
    }
    let output_base = MaybeRelocatable::RelocatableValue(output.to_owned());
    vm.memory
        .insert(&output_base, &MaybeRelocatable::Int(res))
        .map_err(VirtualMachineError::MemoryError)
}
