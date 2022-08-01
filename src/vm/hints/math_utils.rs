use std::{
    collections::HashMap,
    ops::{Neg, Shl, Shr},
};

use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{FromPrimitive, Signed, Zero};

use super::hint_utils::{
    get_address_from_var_name, get_integer_from_var_name, get_ptr_from_var_name,
    get_range_check_builtin, insert_integer_from_var_name,
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
    let output = get_ptr_from_var_name("output", &ids, vm, hint_ap_tracking)?;
    //Main Logic
    let res = (value.mod_floor(&vm.prime)).mod_floor(base);
    if res > *bound {
        return Err(VirtualMachineError::SplitIntLimbOutOfRange(res));
    }
    vm.memory
        .insert(
            &MaybeRelocatable::RelocatableValue(output),
            &MaybeRelocatable::from(res),
        )
        .map_err(VirtualMachineError::MemoryError)
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
    insert_integer_from_var_name("low", low, &ids, vm, hint_ap_tracking)
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
