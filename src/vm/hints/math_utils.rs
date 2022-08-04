use std::{
    collections::HashMap,
    ops::{Neg, Shl, Shr},
};

use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{Signed, Zero};

use super::hint_utils::{
    get_address_from_var_name, get_integer_from_var_name, get_ptr_from_var_name,
    get_range_check_builtin, insert_int_into_ap, insert_value_from_var_name,
};
use crate::{
    bigint,
    math_utils::{as_int, isqrt},
    serde::deserialize_program::ApTracking,
    types::relocatable::MaybeRelocatable,
    vm::{errors::vm_errors::VirtualMachineError, vm_core::VirtualMachine},
};

//Implements hint: memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1
pub fn is_nn(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a = get_integer_from_var_name(
        "a",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let range_check_builtin = get_range_check_builtin(&vm.builtin_runners)?;
    //Main logic (assert a is not negative and within the expected range)
    let value = if a.mod_floor(&vm.prime) >= bigint!(0)
        && a.mod_floor(&vm.prime) < range_check_builtin._bound
    {
        bigint!(0)
    } else {
        bigint!(1)
    };
    insert_int_into_ap(&mut vm.memory, &vm.run_context, value)
}

//Implements hint: memory[ap] = 0 if 0 <= ((-ids.a - 1) % PRIME) < range_check_builtin.bound else 1
pub fn is_nn_out_of_range(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a = get_integer_from_var_name(
        "a",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let range_check_builtin = get_range_check_builtin(&vm.builtin_runners)?;
    //Main logic (assert a is not negative and within the expected range)
    let value = if (-a - 1usize).mod_floor(&vm.prime) < range_check_builtin._bound {
        bigint!(0)
    } else {
        bigint!(1)
    };
    insert_int_into_ap(&mut vm.memory, &vm.run_context, value)
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
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a = get_integer_from_var_name(
        "a",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let b = get_integer_from_var_name(
        "b",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let range_check_builtin = get_range_check_builtin(&vm.builtin_runners)?;
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
    insert_value_from_var_name(
        "small_inputs",
        value,
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )
}

//Implements hint:from starkware.cairo.common.math_cmp import is_le_felt
//    memory[ap] = 0 if (ids.a % PRIME) <= (ids.b % PRIME) else 1
pub fn is_le_felt(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a_mod = get_integer_from_var_name(
        "a",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?
    .mod_floor(&vm.prime);
    let b_mod = get_integer_from_var_name(
        "b",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?
    .mod_floor(&vm.prime);
    let value = if a_mod > b_mod {
        bigint!(1)
    } else {
        bigint!(0)
    };
    insert_int_into_ap(&mut vm.memory, &vm.run_context, value)
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
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a_addr = get_address_from_var_name(
        "a",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let b_addr = get_address_from_var_name(
        "b",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
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
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a = get_integer_from_var_name(
        "a",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let range_check_builtin = get_range_check_builtin(&vm.builtin_runners)?;
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
    )?;
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
    )?;
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
    )?;
    let base = get_integer_from_var_name(
        "base",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let bound = get_integer_from_var_name(
        "bound",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let output = get_ptr_from_var_name(
        "output",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    //Main Logic
    let res = (value.mod_floor(&vm.prime)).mod_floor(base);
    if res > *bound {
        return Err(VirtualMachineError::SplitIntLimbOutOfRange(res));
    }
    vm.memory.insert_value(&output, res)
}

//from starkware.cairo.common.math_utils import is_positive
//ids.is_positive = 1 if is_positive(
//    value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0
pub fn is_positive(
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
    )?;
    let range_check_builtin = get_range_check_builtin(&vm.builtin_runners)?;
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
    insert_value_from_var_name(
        "is_positive",
        result,
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )
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
    )?;
    //Main logic
    //assert_integer(ids.value) (done by match)
    // ids.low = ids.value & ((1 << 128) - 1)
    // ids.high = ids.value >> 128
    let low: BigInt = value & ((bigint!(1).shl(128_u8)) - bigint!(1));
    let high: BigInt = value.shr(128_u8);
    insert_value_from_var_name(
        "high",
        high,
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    insert_value_from_var_name(
        "low",
        low,
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )
}

//Implements hint: from starkware.python.math_utils import isqrt
//        value = ids.value % PRIME
//        assert value < 2 ** 250, f"value={value} is outside of the range [0, 2**250)."
//        assert 2 ** 250 < PRIME
//        ids.root = isqrt(value)
pub fn sqrt(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let mod_value = get_integer_from_var_name(
        "value",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?
    .mod_floor(&vm.prime);
    //This is equal to mod_value > bigint!(2).pow(250)
    if (&mod_value).shr(250_i32).is_positive() {
        return Err(VirtualMachineError::ValueOutside250BitRange(mod_value));
    }
    insert_value_from_var_name(
        "root",
        isqrt(&mod_value)?,
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )
}

pub fn signed_div_rem(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let div = get_integer_from_var_name(
        "div",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let value = get_integer_from_var_name(
        "value",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let bound = get_integer_from_var_name(
        "bound",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let builtin = get_range_check_builtin(&vm.builtin_runners)?;
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
    insert_value_from_var_name(
        "r",
        r,
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    insert_value_from_var_name(
        "biased_q",
        biased_q,
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )
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
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let div = get_integer_from_var_name(
        "div",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let value = get_integer_from_var_name(
        "value",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let builtin = get_range_check_builtin(&vm.builtin_runners)?;
    // Main logic
    if !div.is_positive() || div > &(&vm.prime / &builtin._bound) {
        return Err(VirtualMachineError::OutOfValidRange(
            div.clone(),
            &vm.prime / &builtin._bound,
        ));
    }
    let (q, r) = value.div_mod_floor(div);
    insert_value_from_var_name(
        "r",
        r,
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    insert_value_from_var_name(
        "q",
        q,
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )
}

//Implements hint: from starkware.cairo.common.math_utils import as_int
//        # Correctness check.
//        value = as_int(ids.value, PRIME) % PRIME
//        assert value < ids.UPPER_BOUND, f'{value} is outside of the range [0, 2**250).'
//        # Calculation for the assertion.
//        ids.high, ids.low = divmod(ids.value, ids.SHIFT)
pub fn assert_250_bit(
    vm: &mut VirtualMachine,
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    //Declare constant values
    let upper_bound = bigint!(1).shl(250_i32);
    let shift = bigint!(1).shl(128_i32);
    let value = get_integer_from_var_name(
        "value",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    //Main logic
    let int_value = as_int(value, &vm.prime).mod_floor(&vm.prime);
    if int_value > upper_bound {
        return Err(VirtualMachineError::ValueOutside250BitRange(int_value));
    }
    let (high, low) = int_value.div_rem(&shift);
    insert_value_from_var_name(
        "high",
        high,
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    insert_value_from_var_name(
        "low",
        low,
        ids,
        &mut vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )
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
    ids: &HashMap<String, BigInt>,
    hint_ap_tracking: Option<&ApTracking>,
) -> Result<(), VirtualMachineError> {
    let a = get_integer_from_var_name(
        "a",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
    let b = get_integer_from_var_name(
        "b",
        ids,
        &vm.memory,
        &vm.references,
        &vm.run_context,
        hint_ap_tracking,
    )?;
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
    use crate::types::instruction::Register;
    use crate::types::relocatable::Relocatable;
    use crate::utils::test_utils::*;
    use crate::vm::hints::execute_hint::BuiltinHintExecutor;
    use crate::{
        bigint_str, relocatable,
        vm::{
            errors::memory_errors::MemoryError, hints::execute_hint::HintReference,
            runners::builtin_runner::RangeCheckBuiltinRunner,
        },
    };
    use num_bigint::Sign;

    static HINT_EXECUTOR: BuiltinHintExecutor = BuiltinHintExecutor {};

    use super::*;
    #[test]
    fn run_is_nn_hint_false() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(-1)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a"];
        //Create references
        vm.references = references!(1);
        //Execute the hint
        vm.hint_executor
            .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new())
            .expect("Error while executing hint");
        //Check that ap now contains false (0)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1))))
        );
    }

    #[test]
    fn run_is_nn_hint_true() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a"];
        //Create references
        vm.references = references!(1);
        //Execute the hint
        vm.hint_executor
            .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new())
            .expect("Error while executing hint");
        //Check that ap now contains true (1)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
    }

    #[test]
    //This test contemplates the case when the number itself is negative, but it is within the range (-prime, -range_check_bound)
    //Making the comparison return 1 (true)
    fn run_is_nn_hint_true_border_case() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                //(-prime) + 1
                &MaybeRelocatable::from(
                    BigInt::new(Sign::Minus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]) + bigint!(1),
                ),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a"];
        //Create references
        vm.references = references!(1);
        //Execute the hint
        vm.hint_executor
            .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new())
            .expect("Error while executing hint");
        //Check that ap now contains true (1)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
    }

    #[test]
    fn run_is_nn_hint_no_range_check_builtin() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a"];
        //Create references
        vm.references = references!(1);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &&hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn run_is_nn_hint_incorrect_ids() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("b"), bigint!(0));
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_is_nn_hint_cant_get_ids_from_memory() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Dont insert ids into memory
        //Create ids
        let ids = ids!["a"];
        //Create references
        vm.references = references!(1);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn run_is_nn_hint_ids_are_relocatable_values() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((2, 3)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a"];
        //Create references
        vm.references = references!(1);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn run_assert_le_felt_valid() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)"
            ;
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //ids.b
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //create memory gap, so ids.small_inputs contains None
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(4)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a", "b", "small_inputs"];
        //Create references
        vm.references = HashMap::from([
            (0, HintReference::new_simple(-4)),
            (1, HintReference::new_simple(-3)),
            (2, HintReference::new_simple(-2)),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Ok(())
        );
        //Hint would return an error if the assertion fails
    }

    #[test]
    fn is_le_felt_hint_true() {
        let hint_code = "memory[ap] = 0 if (ids.a % PRIME) <= (ids.b % PRIME) else 1";
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .expect("Unexpected memory insert fail");
        //ids.b
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let ids = ids!["a", "b"];
        //Create references
        vm.references = references!(2);
        //Execute the hint
        assert!(vm
            .hint_executor
            .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new())
            .is_ok());
    }

    #[test]
    fn run_is_le_felt_hint_inconsistent_memory() {
        let hint_code = "memory[ap] = 0 if (ids.a % PRIME) <= (ids.b % PRIME) else 1";
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((0, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));

        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .expect("Unexpected memroy insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .expect("Unexpected memroy insert fail");

        let ids = ids!["a", "b"];
        //Create references
        vm.references = references!(2);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((0, 0)),
                    MaybeRelocatable::Int(bigint!(1)),
                    MaybeRelocatable::Int(bigint!(0))
                )
            ))
        );
    }

    #[test]
    fn run_is_le_felt_hint_incorrect_ids() {
        let hint_code = "memory[ap] = 0 if (ids.a % PRIME) <= (ids.b % PRIME) else 1";
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }

        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));

        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .expect("Unexpected memroy insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .expect("Unexpected memroy insert fail");

        let ids = ids!["a", "c"];
        //Create references
        vm.references = references!(2);
        // Since the ids are a map, the order might not always match and so the error returned
        // sometimes might be different
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &&hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_assert_nn_valid() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            ;
        let mut vm = vm_with_range_check!();

        vm.segments.add(&mut vm.memory, None);

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a"];
        //Create references
        vm.references = HashMap::from([(0, HintReference::new_simple(-4))]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Ok(())
        );
        //Hint would return an error if the assertion fails
    }

    #[test]
    fn run_assert_nn_invalid() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            ;
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(-1)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a"];
        //Create references
        vm.references = HashMap::from([(0, HintReference::new_simple(-4))]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ValueOutOfRange(bigint!(-1)))
        );
    }

    #[test]
    fn run_assert_nn_incorrect_ids() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            ;
        let mut vm = vm_with_range_check!();

        vm.segments.add(&mut vm.memory, None);

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(-1)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("incorrect_id"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(0, HintReference::new_simple(-4))]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds),
        );
    }

    #[test]
    fn run_assert_nn_incorrect_reference() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            ;
        let mut vm = vm_with_range_check!();

        vm.segments.add(&mut vm.memory, None);

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(-1)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(2));
        //Create references
        vm.references = HashMap::from([(0, HintReference::new_simple(10))]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_assert_nn_a_is_not_integer() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            ;
        let mut vm = vm_with_range_check!();

        vm.segments.add(&mut vm.memory, None);

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((10, 10)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a"];
        //Create references
        vm.references = HashMap::from([(0, HintReference::new_simple(-4))]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn run_assert_nn_no_range_check_builtin() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            ;
        let mut vm = vm!();

        vm.segments.add(&mut vm.memory, None);

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a"];
        //Create references
        vm.references = HashMap::from([(0, HintReference::new_simple(-4))]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn run_assert_nn_reference_is_not_in_memory() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            ;
        let mut vm = vm_with_range_check!();

        vm.segments.add(&mut vm.memory, None);

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Create ids
        let ids = ids!["a"];
        //Create references
        vm.references = HashMap::from([(0, HintReference::new_simple(-4))]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn run_is_assert_le_felt_invalid() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)"
            ;
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //ids.b
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //create memory gap, so ids.small_inputs contains None
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(4)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a", "b", "small_inputs"];
        //Create references
        vm.references = references!(3);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::NonLeFelt(bigint!(2), bigint!(1)))
        );
    }

    #[test]
    fn run_is_assert_le_felt_small_inputs_not_local() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)"
            ;
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //ids.b
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //ids.small_inputs (insert into memory, instead of leaving a gap for it (local var))
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(4)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a", "b", "small_inputs"];
        //Create references
        vm.references = references!(3);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((0, 2)),
                    MaybeRelocatable::from(bigint!(4)),
                    MaybeRelocatable::from(bigint!(1))
                )
            ))
        );
    }

    #[test]
    fn run_is_assert_le_felt_a_is_not_integer() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)"
            ;
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((0, 0)),
            )
            .unwrap();
        //ids.b
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //create memory gap, so ids.small_inputs contains None
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(4)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a", "b", "small_inputs"];
        //Create references
        vm.references = references!(3);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn run_is_assert_le_felt_b_is_not_integer() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)"
            ;
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        //Insert ids into memory
        //ids.a
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //ids.b
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from((0, 0)),
            )
            .unwrap();
        //create memory gap, so ids.small_inputs contains None
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(4)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a", "b", "small_inputs"];
        //Create references
        vm.references = references!(3);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 1))
            ))
        );
    }

    #[test]
    fn run_is_nn_hint_out_of_range_false() {
        let hint_code =
            "memory[ap] = 0 if 0 <= ((-ids.a - 1) % PRIME) < range_check_builtin.bound else 1";
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a"];
        //Create references
        vm.references = references!(1);
        //Execute the hint
        vm.hint_executor
            .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new())
            .expect("Error while executing hint");
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1))))
        );
    }

    #[test]
    fn run_is_nn_hint_out_of_range_true() {
        let hint_code =
            "memory[ap] = 0 if 0 <= ((-ids.a - 1) % PRIME) < range_check_builtin.bound else 1";
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(-1)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a"];
        //Create references
        vm.references = references!(1);
        //Execute the hint
        vm.hint_executor
            .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new())
            .expect("Error while executing hint");
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
    }
    #[test]
    fn run_assert_not_equal_int_false() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'"
            ;
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a", "b"];
        //Create references
        vm.references = references!(2);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::AssertNotEqualFail(
                MaybeRelocatable::from(bigint!(1)),
                MaybeRelocatable::from(bigint!(1))
            ))
        );
    }

    #[test]
    fn run_assert_not_equal_int_true() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'"
            ;
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(3)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a", "b"];
        //Create references
        vm.references = references!(2);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Ok(())
        );
    }

    #[test]
    fn run_assert_not_equal_int_false_mod() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'"
            ;
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                //-1 % prime = prime -1
                &MaybeRelocatable::from(bigint!(-1)),
            )
            .unwrap();
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                //prime -1
                &MaybeRelocatable::from(bigint_str!(
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020480"
                )),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a", "b"];
        //Create references
        vm.references = references!(2);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::AssertNotEqualFail(
                MaybeRelocatable::from(bigint!(-1)),
                MaybeRelocatable::from(bigint_str!(
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020480"
                ))
            ))
        );
    }

    #[test]
    fn run_assert_not_equal_relocatable_false() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'"
            ;
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((0, 0)),
            )
            .unwrap();
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from((0, 0)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a", "b"];
        //Create references
        vm.references = references!(2);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::AssertNotEqualFail(
                MaybeRelocatable::from((0, 0)),
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn run_assert_not_equal_relocatable_true() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'"
            ;
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((0, 1)),
            )
            .unwrap();
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from((0, 0)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a", "b"];
        //Create references
        vm.references = references!(2);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Ok(())
        );
    }

    #[test]
    fn run_assert_non_equal_relocatable_diff_index() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'"
            ;
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from((0, 0)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a", "b"];
        //Create references
        vm.references = references!(2);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::DiffIndexComp(
                relocatable!(1, 0),
                relocatable!(0, 0)
            ))
        );
    }

    #[test]
    fn run_assert_not_equal_relocatable_and_integer() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'"
            ;
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["a", "b"];
        //Create references
        vm.references = references!(2);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::DiffTypeComparison(
                MaybeRelocatable::from((1, 0)),
                MaybeRelocatable::from(bigint!(1))
            ))
        );
    }

    #[test]
    fn run_assert_not_zero_true() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'";
        let mut vm = vm!();
        //Create references
        vm.references = references!(1);
        vm.segments.add(&mut vm.memory, None);
        // }
        // //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Ok(())
        );
    }

    #[test]
    fn run_assert_not_zero_false() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'";
        let mut vm = vm!();
        //Create references
        vm.references = references!(1);
        vm.segments.add(&mut vm.memory, None);
        // }
        // //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::AssertNotZero(bigint!(0), vm.prime))
        );
    }

    #[test]
    fn run_assert_not_zero_false_with_prime() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'";
        let mut vm = vm!();
        //Create references
        vm.references = references!(1);
        vm.segments.add(&mut vm.memory, None);
        // }
        // //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(vm.prime.clone()),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::AssertNotZero(
                vm.prime.clone(),
                vm.prime
            ))
        );
    }

    #[test]
    fn run_assert_not_zero_failed_to_get_reference() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'";
        let mut vm = vm!();
        //Create references
        vm.references = references!(1);
        vm.segments.add(&mut vm.memory, None);
        // }
        // //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .unwrap();
        //Create invalid id value
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(10));

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_assert_not_zero_incorrect_id() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'";
        let mut vm = vm!();
        //Create references
        vm.references = references!(1);
        vm.segments.add(&mut vm.memory, None);
        // }
        // //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();
        //Create invalid id key
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("incorrect_id"), bigint!(0));

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_assert_not_zero_expected_integer_error() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'";
        let mut vm = vm!();
        vm.references = references!(1);
        vm.segments.add(&mut vm.memory, None);
        // }
        // //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((0, 0)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn run_split_int_assertion_invalid() {
        let hint_code = "assert ids.value == 0, 'split_int(): value is out of range.'";
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        //Create references
        vm.references = references!(1);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::SplitIntNotZero)
        );
    }

    #[test]
    fn run_split_int_assertion_valid() {
        let hint_code = "assert ids.value == 0, 'split_int(): value is out of range.'";
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(0)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        //Create references
        vm.references = references!(1);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Ok(())
        );
    }

    #[test]
    fn run_split_int_valid() {
        let hint_code = "memory[ids.output] = res = (int(ids.value) % PRIME) % ids.base\nassert res < ids.bound, f'split_int(): Limb {res} is out of range.'";
        let mut vm = vm!();
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.output
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((2, 0)),
            )
            .unwrap();
        //ids.value
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //ids.base
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .unwrap();
        //ids.bound
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(100)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["output", "value", "base", "bound"];
        //Create references
        vm.references = references!(4);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Ok(())
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((2, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(2))))
        );
    }

    #[test]
    fn run_split_int_invalid() {
        let hint_code = "memory[ids.output] = res = (int(ids.value) % PRIME) % ids.base\nassert res < ids.bound, f'split_int(): Limb {res} is out of range.'";
        let mut vm = vm!();
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        //ids.output
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from((2, 0)),
            )
            .unwrap();
        //ids.value
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(100)),
            )
            .unwrap();
        //ids.base
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(10000)),
            )
            .unwrap();
        //ids.bound
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .unwrap();
        //Create ids
        let ids = ids!["output", "value", "base", "bound"];
        //Create references
        vm.references = references!(4);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::SplitIntLimbOutOfRange(bigint!(100)))
        );
    }

    #[test]
    fn run_is_positive_hint_true() {
        let hint_code =
        "from starkware.cairo.common.math_utils import is_positive\nids.is_positive = 1 if is_positive(\n    value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0"
        ;
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(250)),
            )
            .unwrap();
        //Dont insert ids.is_positive as we need to modify it inside the hint
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("is_positive"), bigint!(1));
        //Create references
        vm.references = references!(2);
        //Execute the hint
        vm.hint_executor
            .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new())
            .expect("Error while executing hint");
        //Check that is_positive now contains 1 (true)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1))))
        );
    }

    #[test]
    fn run_is_positive_hint_false() {
        let hint_code =
        "from starkware.cairo.common.math_utils import is_positive\nids.is_positive = 1 if is_positive(\n    value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0"
        ;
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(-250)),
            )
            .unwrap();
        //Dont insert ids.is_positive as we need to modify it inside the hint
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("is_positive"), bigint!(1));
        //Create references
        vm.references = references!(2);
        //Execute the hint
        vm.hint_executor
            .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new())
            .expect("Error while executing hint");
        //Check that is_positive now contains 0 (false)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
    }

    #[test]
    fn run_is_positive_hint_outside_valid_range() {
        let hint_code =
        "from starkware.cairo.common.math_utils import is_positive\nids.is_positive = 1 if is_positive(\n    value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0"
        ;
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(BigInt::new(
                    Sign::Plus,
                    vec![1, 0, 0, 0, 0, 0, 17, 134217727],
                )),
            )
            .unwrap();
        //Dont insert ids.is_positive as we need to modify it inside the hint
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("is_positive"), bigint!(1));
        //Create references
        vm.references = references!(2);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ValueOutsideValidRange(as_int(
                &BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217727]),
                &vm.prime
            )))
        );
    }

    #[test]
    fn run_is_positive_hint_is_positive_not_empty() {
        let hint_code ="from starkware.cairo.common.math_utils import is_positive\nids.is_positive = 1 if is_positive(\n    value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0"
        ;
        let mut vm = vm_with_range_check!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();
        //Insert ids.is_positive into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(4)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("is_positive"), bigint!(1));
        //Create references
        vm.references = references!(2);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((0, 1)),
                    MaybeRelocatable::from(bigint!(4)),
                    MaybeRelocatable::from(bigint!(1))
                )
            ))
        );
    }

    #[test]
    fn run_sqrt_valid() {
        let hint_code = "from starkware.python.math_utils import isqrt\nvalue = ids.value % PRIME\nassert value < 2 ** 250, f\"value={value} is outside of the range [0, 2**250).\"\nassert 2 ** 250 < PRIME\nids.root = isqrt(value)"
            ;
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(81)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("root"), bigint!(1));
        //Create references
        vm.references = references!(2);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Ok(())
        );
        //Check that root (0,1) has the square root of 81
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(9))))
        );
    }

    #[test]
    fn run_sqrt_invalid_negative_number() {
        let hint_code = "from starkware.python.math_utils import isqrt\nvalue = ids.value % PRIME\nassert value < 2 ** 250, f\"value={value} is outside of the range [0, 2**250).\"\nassert 2 ** 250 < PRIME\nids.root = isqrt(value)"
            ;
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(-81)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("root"), bigint!(1));
        //Create references
        vm.references = references!(2);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ValueOutside250BitRange(bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020400"
            )))
        );
    }

    #[test]
    fn run_sqrt_invalid_mismatched_root() {
        let hint_code = "from starkware.python.math_utils import isqrt\nvalue = ids.value % PRIME\nassert value < 2 ** 250, f\"value={value} is outside of the range [0, 2**250).\"\nassert 2 ** 250 < PRIME\nids.root = isqrt(value)"
            ;
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 2));
        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(81)),
            )
            .unwrap();
        //Insert ids.root into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(7)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("root"), bigint!(1));
        //Create references
        vm.references = references!(2);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((0, 1)),
                    MaybeRelocatable::from(bigint!(7)),
                    MaybeRelocatable::from(bigint!(9))
                )
            ))
        );
    }

    #[test]
    fn unsigned_div_rem_success() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\nids.q, ids.r = divmod(ids.value, ids.div)";
        let mut vm = vm_with_range_check!();
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(7)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("r"), bigint!(0));
        ids.insert(String::from("q"), bigint!(1));
        ids.insert(String::from("div"), bigint!(2));
        ids.insert(String::from("value"), bigint!(3));
        //Create references
        vm.references = references!(4);
        //Execute the hint
        assert!(vm
            .hint_executor
            .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new())
            .is_ok());
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(2))))
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1))))
        );
    }

    #[test]
    fn unsigned_div_rem_out_of_range() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\nids.q, ids.r = divmod(ids.value, ids.div)";
        let mut vm = vm_with_range_check!();
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(-5)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(7)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("r"), bigint!(0));
        ids.insert(String::from("q"), bigint!(1));
        ids.insert(String::from("div"), bigint!(2));
        ids.insert(String::from("value"), bigint!(3));
        //Create references
        vm.references = references!(4);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::OutOfValidRange(
                bigint!(-5),
                bigint_str!(b"10633823966279327296825105735305134080")
            ))
        )
    }

    #[test]
    fn unsigned_div_rem_no_range_check_builtin() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\nids.q, ids.r = divmod(ids.value, ids.div)";
        let mut vm = vm!();
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(7)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("r"), bigint!(0));
        ids.insert(String::from("q"), bigint!(1));
        ids.insert(String::from("div"), bigint!(2));
        ids.insert(String::from("value"), bigint!(3));
        //Create references
        vm.references = references!(4);

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &&hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn unsigned_div_rem_inconsitent_memory() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\nids.q, ids.r = divmod(ids.value, ids.div)";
        let mut vm = vm_with_range_check!();
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .expect("unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .expect("unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(7)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("r"), bigint!(0));
        ids.insert(String::from("q"), bigint!(1));
        ids.insert(String::from("div"), bigint!(2));
        ids.insert(String::from("value"), bigint!(3));
        //Create references
        vm.references = references!(4);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((0, 0)),
                    MaybeRelocatable::Int(bigint!(5)),
                    MaybeRelocatable::Int(bigint!(2))
                )
            ))
        );
    }

    #[test]
    fn unsigned_div_rem_incorrect_ids() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\nids.q, ids.r = divmod(ids.value, ids.div)";
        let mut vm = vm_with_range_check!();
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(7)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let ids = ids!["a", "b", "iv", "vlue"];
        //Create references
        vm.references = references!(4);
        //Execute the hint
        assert!(matches!(
            vm.hint_executor
                .execute_hint(&mut vm, &&hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        ))
    }

    #[test]
    fn signed_div_rem_success() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound";
        let mut vm = vm_with_range_check!();
        for _ in 0..5 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 6));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 5)),
                &MaybeRelocatable::from(bigint!(29)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let ids = ids!["r", "biased_q", "range_check_ptr", "div", "value", "bound"];
        //Create references
        vm.references = references!(6);
        //Execute the hint
        assert!(vm
            .hint_executor
            .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new())
            .is_ok());
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(31))))
        );
    }

    #[test]
    fn signed_div_rem_negative_quotient() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound";
        let mut vm = vm_with_range_check!();
        for _ in 0..5 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 6));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(7)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(bigint!(-10)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 5)),
                &MaybeRelocatable::from(bigint!(29)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let ids = ids!["r", "biased_q", "range_check_ptr", "div", "value", "bound"];
        //Create references
        vm.references = references!(6);
        //Execute the hint
        assert!(vm
            .hint_executor
            .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new())
            .is_ok());
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(4))))
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(27))))
        );
    }

    #[test]
    fn signed_div_rem_out_of_range() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound";
        let mut vm = vm_with_range_check!();
        for _ in 0..5 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 6));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(-5)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 5)),
                &MaybeRelocatable::from(bigint!(29)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let ids = ids!["r", "biased_q", "range_check_ptr", "div", "value", "bound"];
        //Create references
        vm.references = references!(6);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::OutOfValidRange(
                bigint!(-5),
                bigint_str!(b"10633823966279327296825105735305134080")
            ))
        )
    }

    #[test]
    fn signed_div_rem_no_range_check_builtin() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound";
        let mut vm = vm!();
        for _ in 0..5 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 6));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 5)),
                &MaybeRelocatable::from(bigint!(29)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let ids = ids!["r", "biased_q", "range_check_ptr", "div", "value", "bound"];
        //Create references
        vm.references = references!(6);

        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &&hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn signed_div_rem_inconsitent_memory() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound";
        let mut vm = vm_with_range_check!();
        for _ in 0..5 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 6));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 1)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 5)),
                &MaybeRelocatable::from(bigint!(29)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let ids = ids!["r", "biased_q", "range_check_ptr", "div", "value", "bound"];
        //Create references
        vm.references = references!(6);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((0, 1)),
                    MaybeRelocatable::Int(bigint!(10)),
                    MaybeRelocatable::Int(bigint!(31))
                )
            ))
        );
    }

    #[test]
    fn signed_div_rem_incorrect_ids() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound";
        let mut vm = vm_with_range_check!();
        for _ in 0..5 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 6));
        //Insert ids into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 3)),
                &MaybeRelocatable::from(bigint!(5)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 4)),
                &MaybeRelocatable::from(bigint!(10)),
            )
            .expect("Unexpected memory insert fail");
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 5)),
                &MaybeRelocatable::from(bigint!(29)),
            )
            .expect("Unexpected memory insert fail");
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("r"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        ids.insert(String::from("r"), bigint!(2));
        ids.insert(String::from("d"), bigint!(3));
        ids.insert(String::from("v"), bigint!(4));
        ids.insert(String::from("b"), bigint!(5));
        //Create references
        vm.references = references!(6);
        //Execute the hint
        assert!(matches!(
            vm.hint_executor
                .execute_hint(&mut vm, &&hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        ))
    }

    #[test]
    fn run_assert_250_bit_valid() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int\n\n# Correctness check.\nvalue = as_int(ids.value, PRIME) % PRIME\nassert value < ids.UPPER_BOUND, f'{value} is outside of the range [0, 2**250).'\n\n# Calculation for the assertion.\nids.high, ids.low = divmod(ids.value, ids.SHIFT)"
             ;
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        //Insert ids into memory
        //ids.value
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("high"), bigint!(1));
        ids.insert(String::from("low"), bigint!(2));
        //Create references
        vm.references = references!(3);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Ok(())
        );
        //Hint would return an error if the assertion fails
        //Check ids.high and ids.low values
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 2))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1))))
        );
    }

    #[test]
    fn run_assert_250_bit_invalid() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int\n\n# Correctness check.\nvalue = as_int(ids.value, PRIME) % PRIME\nassert value < ids.UPPER_BOUND, f'{value} is outside of the range [0, 2**250).'\n\n# Calculation for the assertion.\nids.high, ids.low = divmod(ids.value, ids.SHIFT)"
             ;
        let mut vm = vm!();
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 3));
        //Insert ids into memory
        //ids.value
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 0)),
                &MaybeRelocatable::from(bigint!(1).shl(251i32)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("high"), bigint!(1));
        ids.insert(String::from("low"), bigint!(2));
        //Create references
        vm.references = references!(3);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ValueOutside250BitRange(
                bigint!(1).shl(251i32)
            ))
        );
    }

    #[test]
    fn run_split_felt_ok() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128"
        ;
        let mut vm = vm_with_range_check!();
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 7));

        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from(bigint_str!(b"7335438970432432812899076431678123043273")),
            )
            .unwrap();

        //Insert ids.low pointer into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from((2, 0)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("low"), bigint!(1));
        ids.insert(String::from("high"), bigint!(2));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: true,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 1,
                    inner_dereference: true,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Ok(())
        );

        //Check hint memory inserts
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((2, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint_str!(
                b"189509265092725080168209675610990602697"
            ))))
        );
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((2, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(21))))
        );
    }

    #[test]
    fn run_split_felt_incorrect_ids() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128"
        ;
        let mut vm = vm_with_range_check!();
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 7));

        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from(bigint_str!(b"7335438970432432812899076431678123043273")),
            )
            .unwrap();

        //Insert ids.low pointer into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from((2, 0)),
            )
            .unwrap();

        //Create incomplete ids
        let mut incomplete_ids = HashMap::<String, BigInt>::new();
        incomplete_ids.insert(String::from("value"), bigint!(0));

        //Create references
        vm.references = HashMap::from([
            (0, HintReference::new_simple(-4)),
            (1, HintReference::new_simple(-3)),
            (2, HintReference::new_simple(-3)),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, hint_code, &incomplete_ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }
    #[test]
    fn run_split_felt_failed_to_get_ids() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128"
        ;
        let mut vm = vm_with_range_check!();
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 7));

        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from(bigint_str!(b"7335438970432432812899076431678123043273")),
            )
            .unwrap();

        //Insert ids.low pointer into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from((2, 0)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("low"), bigint!(1));
        ids.insert(String::from("high"), bigint!(2));

        //Create incorrect references
        vm.references = HashMap::from([
            // Incorrect reference
            (1, HintReference::new_simple(-3)),
            (2, HintReference::new_simple(-3)),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_split_felt_fails_first_insert() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128"
        ;
        let mut vm = vm_with_range_check!();
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 7));

        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from(bigint_str!(b"7335438970432432812899076431678123043273")),
            )
            .unwrap();

        //Insert ids.low pointer into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from((2, 0)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("low"), bigint!(1));
        ids.insert(String::from("high"), bigint!(2));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: true,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 1,
                    inner_dereference: true,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);

        // Override MaybeRelocatable::from((2, 0)) memory address so, the hint vm.memory.insert fails
        vm.memory
            .insert(
                &MaybeRelocatable::from((2, 0)),
                &MaybeRelocatable::from(bigint!(99)),
            )
            .unwrap();

        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((2, 0)),
                    MaybeRelocatable::from(bigint!(99)),
                    MaybeRelocatable::from(bigint_str!(b"189509265092725080168209675610990602697"))
                )
            ))
        );
    }

    #[test]
    fn run_split_felt_fails_second_insert() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128"
        ;
        let mut vm = vm_with_range_check!();
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 7));

        //Insert ids.value into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from(bigint_str!(b"7335438970432432812899076431678123043273")),
            )
            .unwrap();

        //Insert ids.low pointer into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from((2, 0)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("low"), bigint!(1));
        ids.insert(String::from("high"), bigint!(2));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                1,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: true,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
            (
                2,
                HintReference {
                    dereference: true,
                    register: Register::FP,
                    offset1: -3,
                    offset2: 1,
                    inner_dereference: true,
                    ap_tracking_data: None,
                    immediate: None,
                },
            ),
        ]);

        // Override MaybeRelocatable::from((2, 1)) memory address so, the hint vm.memory.insert fails
        vm.memory
            .insert(
                &MaybeRelocatable::from((2, 1)),
                &MaybeRelocatable::from(bigint!(99)),
            )
            .unwrap();

        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((2, 1)),
                    MaybeRelocatable::from(bigint!(99)),
                    MaybeRelocatable::from(bigint!(21))
                )
            ))
        );
    }

    #[test]
    fn run_split_felt_value_is_not_integer() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128"
        ;
        let mut vm = vm_with_range_check!();
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 7));

        //Insert insert RelocatableValue in ids.value memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 3)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();

        //Insert ids.low pointer into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 4)),
                &MaybeRelocatable::from((2, 0)),
            )
            .unwrap();

        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("low"), bigint!(1));
        ids.insert(String::from("high"), bigint!(2));

        //Create references
        vm.references = HashMap::from([
            (0, HintReference::new_simple(-4)),
            (1, HintReference::new_simple(-3)),
            (2, HintReference::new_simple(-3)),
        ]);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 3))
            ))
        );
    }

    #[test]
    fn run_assert_lt_felt_ok() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"
        ;
        let mut vm = vm_with_range_check!();
        //Initialize memory segements
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 3));

        //Insert ids.a into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        //Insert ids.b into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();

        //Create ids
        let ids = ids!["a", "b"];

        //Create references
        vm.references = references!(2);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Ok(())
        );
    }

    #[test]
    fn run_assert_lt_felt_assert_fails() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"
        ;
        let mut vm = vm_with_range_check!();
        //Initialize memory segements
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 3));

        //Insert ids.a into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(3)),
            )
            .unwrap();

        //Insert ids.b into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();

        //Create ids
        let ids = ids!["a", "b"];

        //Create references
        vm.references = references!(2);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::AssertLtFelt(bigint!(3), bigint!(2)))
        );
    }

    #[test]
    fn run_assert_lt_felt_incorrect_ids() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"
        ;
        let mut vm = vm_with_range_check!();
        //Initialize memory segements
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 3));

        //Insert ids.a into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        //Insert ids.b into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();

        //Create Incorrects ids
        let ids = ids!["a"];

        //Create references
        vm.references = references!(2);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_assert_lt_felt_a_is_not_integer() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"
        ;
        let mut vm = vm_with_range_check!();
        //Initialize memory segements
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 3));

        //Insert ids.a into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();

        //Insert ids.b into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from(bigint!(2)),
            )
            .unwrap();

        //Create ids
        let ids = ids!["a", "b"];

        //Create references
        vm.references = references!(2);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 1))
            ))
        );
    }

    #[test]
    fn run_assert_lt_felt_b_is_not_integer() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"
        ;
        let mut vm = vm_with_range_check!();
        //Initialize memory segements
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 3));

        //Insert ids.a into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        //Insert ids.b into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 2)),
                &MaybeRelocatable::from((1, 0)),
            )
            .unwrap();

        //Create ids
        let ids = ids!["a", "b"];

        //Create references
        vm.references = references!(2);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 2))
            ))
        );
    }

    #[test]
    fn run_assert_lt_felt_ok_failed_to_get_ids() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"
        ;
        let mut vm = vm_with_range_check!();
        //Initialize memory segements
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((1, 3));

        //Insert ids.a into memory
        vm.memory
            .insert(
                &MaybeRelocatable::from((1, 1)),
                &MaybeRelocatable::from(bigint!(1)),
            )
            .unwrap();

        //Skip insert ids.b into memory
        // vm.memory
        //     .insert(
        //         &MaybeRelocatable::from((1, 2)),
        //         &MaybeRelocatable::from(bigint!(2)),
        //     )
        //     .unwrap();

        //Create incorrects ids
        let ids = ids!["a", "b"];

        //Create references
        vm.references = references!(2);
        //Execute the hint
        assert_eq!(
            vm.hint_executor
                .execute_hint(&mut vm, &hint_code, &ids, &ApTracking::new()),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 2))
            ))
        );
    }
}
