use crate::hint_processor::hint_processor_utils::get_range_check_builtin;
use crate::hint_processor::{hint_processor_definition::HintReference, proxies::vm_proxy::VMProxy};
use std::{
    collections::HashMap,
    ops::{Neg, Shl, Shr},
};

use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{Signed, Zero};

use crate::hint_processor::builtin_hint_processor::hint_utils::{
    get_address_from_var_name, get_integer_from_var_name, get_ptr_from_var_name,
    insert_value_from_var_name, insert_value_into_ap,
};
use crate::{
    bigint,
    math_utils::{as_int, isqrt},
    serde::deserialize_program::ApTracking,
    types::relocatable::MaybeRelocatable,
    vm::errors::vm_errors::VirtualMachineError,
};

//Implements hint: memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1
pub fn is_nn(
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let a = get_integer_from_var_name("a", vm_proxy, ids_data, ap_tracking)?;
    let range_check_builtin = get_range_check_builtin(vm_proxy.builtin_runners)?;
    //Main logic (assert a is not negative and within the expected range)
    let value = if a.mod_floor(vm_proxy.get_prime()) >= bigint!(0)
        && a.mod_floor(vm_proxy.get_prime()) < range_check_builtin._bound
    {
        bigint!(0)
    } else {
        bigint!(1)
    };
    insert_value_into_ap(vm_proxy, value)
}

//Implements hint: memory[ap] = 0 if 0 <= ((-ids.a - 1) % PRIME) < range_check_builtin.bound else 1
pub fn is_nn_out_of_range(
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let a = get_integer_from_var_name("a", vm_proxy, ids_data, ap_tracking)?;
    let range_check_builtin = get_range_check_builtin(vm_proxy.builtin_runners)?;
    //Main logic (assert a is not negative and within the expected range)
    let value = if (-a - 1usize).mod_floor(vm_proxy.get_prime()) < range_check_builtin._bound {
        bigint!(0)
    } else {
        bigint!(1)
    };
    insert_value_into_ap(vm_proxy, value)
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
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let a = get_integer_from_var_name("a", vm_proxy, ids_data, ap_tracking)?;
    let b = get_integer_from_var_name("b", vm_proxy, ids_data, ap_tracking)?;
    let range_check_builtin = get_range_check_builtin(vm_proxy.builtin_runners)?;
    //Assert a <= b
    if a.mod_floor(vm_proxy.get_prime()) > b.mod_floor(vm_proxy.get_prime()) {
        return Err(VirtualMachineError::NonLeFelt(a.clone(), b.clone()));
    }
    //Calculate value of small_inputs
    let value = if *a < range_check_builtin._bound && (a - b) < range_check_builtin._bound {
        bigint!(1)
    } else {
        bigint!(0)
    };
    insert_value_from_var_name("small_inputs", value, vm_proxy, ids_data, ap_tracking)
}

//Implements hint:from starkware.cairo.common.math_cmp import is_le_felt
//    memory[ap] = 0 if (ids.a % PRIME) <= (ids.b % PRIME) else 1
pub fn is_le_felt(
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let a_mod = get_integer_from_var_name("a", vm_proxy, ids_data, ap_tracking)?
        .mod_floor(vm_proxy.get_prime());
    let b_mod = get_integer_from_var_name("b", vm_proxy, ids_data, ap_tracking)?
        .mod_floor(vm_proxy.get_prime());
    let value = if a_mod > b_mod {
        bigint!(1)
    } else {
        bigint!(0)
    };
    insert_value_into_ap(vm_proxy, value)
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
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let a_addr = get_address_from_var_name("a", vm_proxy, ids_data, ap_tracking)?;
    let b_addr = get_address_from_var_name("b", vm_proxy, ids_data, ap_tracking)?;
    //Check that the ids are in memory
    match (vm_proxy.memory.get(&a_addr), vm_proxy.memory.get(&b_addr)) {
        (Ok(Some(maybe_rel_a)), Ok(Some(maybe_rel_b))) => match (maybe_rel_a, maybe_rel_b) {
            (MaybeRelocatable::Int(ref a), MaybeRelocatable::Int(ref b)) => {
                if (a - b).is_multiple_of(vm_proxy.get_prime()) {
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
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let a = get_integer_from_var_name("a", vm_proxy, ids_data, ap_tracking)?;
    let range_check_builtin = get_range_check_builtin(vm_proxy.builtin_runners)?;
    // assert 0 <= ids.a % PRIME < range_check_builtin.bound
    // as prime > 0, a % prime will always be > 0
    if a.mod_floor(vm_proxy.get_prime()) >= range_check_builtin._bound {
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
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let value = get_integer_from_var_name("value", vm_proxy, ids_data, ap_tracking)?;
    if value.is_multiple_of(vm_proxy.get_prime()) {
        return Err(VirtualMachineError::AssertNotZero(
            value.clone(),
            vm_proxy.get_prime().clone(),
        ));
    };
    Ok(())
}

//Implements hint: assert ids.value == 0, 'split_int(): value is out of range.'
pub fn split_int_assert_range(
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let value = get_integer_from_var_name("value", vm_proxy, ids_data, ap_tracking)?;
    //Main logic (assert value == 0)
    if !value.is_zero() {
        return Err(VirtualMachineError::SplitIntNotZero);
    }
    Ok(())
}

//Implements hint: memory[ids.output] = res = (int(ids.value) % PRIME) % ids.base
//        assert res < ids.bound, f'split_int(): Limb {res} is out of range.'
pub fn split_int(
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let value = get_integer_from_var_name("value", vm_proxy, ids_data, ap_tracking)?;
    let base = get_integer_from_var_name("base", vm_proxy, ids_data, ap_tracking)?;
    let bound = get_integer_from_var_name("bound", vm_proxy, ids_data, ap_tracking)?;
    let output = get_ptr_from_var_name("output", vm_proxy, ids_data, ap_tracking)?;
    //Main Logic
    let res = (value.mod_floor(vm_proxy.get_prime())).mod_floor(base);
    if res > *bound {
        return Err(VirtualMachineError::SplitIntLimbOutOfRange(res));
    }
    vm_proxy.insert_value(&output, res)
}

//from starkware.cairo.common.math_utils import is_positive
//ids.is_positive = 1 if is_positive(
//    value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0
pub fn is_positive(
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let value = get_integer_from_var_name("value", vm_proxy, ids_data, ap_tracking)?;
    let range_check_builtin = get_range_check_builtin(vm_proxy.builtin_runners)?;
    //Main logic (assert a is positive)
    let int_value = as_int(value, vm_proxy.get_prime());
    if int_value.abs() > range_check_builtin._bound {
        return Err(VirtualMachineError::ValueOutsideValidRange(int_value));
    }
    let result = if int_value.is_positive() {
        bigint!(1)
    } else {
        bigint!(0)
    };
    insert_value_from_var_name("is_positive", result, vm_proxy, ids_data, ap_tracking)
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
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let value = get_integer_from_var_name("value", vm_proxy, ids_data, ap_tracking)?;
    //Main logic
    //assert_integer(ids.value) (done by match)
    // ids.low = ids.value & ((1 << 128) - 1)
    // ids.high = ids.value >> 128
    let low: BigInt = value & ((bigint!(1).shl(128_u8)) - bigint!(1));
    let high: BigInt = value.shr(128_u8);
    insert_value_from_var_name("high", high, vm_proxy, ids_data, ap_tracking)?;
    insert_value_from_var_name("low", low, vm_proxy, ids_data, ap_tracking)
}

//Implements hint: from starkware.python.math_utils import isqrt
//        value = ids.value % PRIME
//        assert value < 2 ** 250, f"value={value} is outside of the range [0, 2**250)."
//        assert 2 ** 250 < PRIME
//        ids.root = isqrt(value)
pub fn sqrt(
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let mod_value = get_integer_from_var_name("value", vm_proxy, ids_data, ap_tracking)?
        .mod_floor(vm_proxy.get_prime());
    //This is equal to mod_value > bigint!(2).pow(250)
    if (&mod_value).shr(250_i32).is_positive() {
        return Err(VirtualMachineError::ValueOutside250BitRange(mod_value));
    }
    insert_value_from_var_name("root", isqrt(&mod_value)?, vm_proxy, ids_data, ap_tracking)
}

pub fn signed_div_rem(
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let div = get_integer_from_var_name("div", vm_proxy, ids_data, ap_tracking)?;
    let value = get_integer_from_var_name("value", vm_proxy, ids_data, ap_tracking)?;
    let bound = get_integer_from_var_name("bound", vm_proxy, ids_data, ap_tracking)?;
    let builtin = get_range_check_builtin(vm_proxy.builtin_runners)?;
    // Main logic
    if !div.is_positive() || div > &(vm_proxy.get_prime() / &builtin._bound) {
        return Err(VirtualMachineError::OutOfValidRange(
            div.clone(),
            vm_proxy.get_prime() / &builtin._bound,
        ));
    }
    // Divide by 2
    if bound > &(&builtin._bound).shr(1_i32) {
        return Err(VirtualMachineError::OutOfValidRange(
            bound.clone(),
            (&builtin._bound).shr(1_i32),
        ));
    }

    let int_value = &as_int(value, vm_proxy.get_prime());
    let (q, r) = int_value.div_mod_floor(div);
    if bound.neg() > q || &q >= bound {
        return Err(VirtualMachineError::OutOfValidRange(q, bound.clone()));
    }
    let biased_q = q + bound;
    insert_value_from_var_name("r", r, vm_proxy, ids_data, ap_tracking)?;
    insert_value_from_var_name("biased_q", biased_q, vm_proxy, ids_data, ap_tracking)
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
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let div = get_integer_from_var_name("div", vm_proxy, ids_data, ap_tracking)?;
    let value = get_integer_from_var_name("value", vm_proxy, ids_data, ap_tracking)?;
    let builtin = get_range_check_builtin(vm_proxy.builtin_runners)?;
    // Main logic
    if !div.is_positive() || div > &(vm_proxy.get_prime() / &builtin._bound) {
        return Err(VirtualMachineError::OutOfValidRange(
            div.clone(),
            vm_proxy.get_prime() / &builtin._bound,
        ));
    }
    let (q, r) = value.div_mod_floor(div);
    insert_value_from_var_name("r", r, vm_proxy, ids_data, ap_tracking)?;
    insert_value_from_var_name("q", q, vm_proxy, ids_data, ap_tracking)
}

//Implements hint: from starkware.cairo.common.math_utils import as_int
//        # Correctness check.
//        value = as_int(ids.value, PRIME) % PRIME
//        assert value < ids.UPPER_BOUND, f'{value} is outside of the range [0, 2**250).'
//        # Calculation for the assertion.
//        ids.high, ids.low = divmod(ids.value, ids.SHIFT)
pub fn assert_250_bit(
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    //Declare constant values
    let upper_bound = bigint!(1).shl(250_i32);
    let shift = bigint!(1).shl(128_i32);
    let value = get_integer_from_var_name("value", vm_proxy, ids_data, ap_tracking)?;
    //Main logic
    let int_value = as_int(value, vm_proxy.get_prime()).mod_floor(vm_proxy.get_prime());
    if int_value > upper_bound {
        return Err(VirtualMachineError::ValueOutside250BitRange(int_value));
    }
    let (high, low) = int_value.div_rem(&shift);
    insert_value_from_var_name("high", high, vm_proxy, ids_data, ap_tracking)?;
    insert_value_from_var_name("low", low, vm_proxy, ids_data, ap_tracking)
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
    vm_proxy: &mut VMProxy,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), VirtualMachineError> {
    let a = get_integer_from_var_name("a", vm_proxy, ids_data, ap_tracking)?;
    let b = get_integer_from_var_name("b", vm_proxy, ids_data, ap_tracking)?;
    // Main logic
    // assert_integer(ids.a)
    // assert_integer(ids.b)
    // assert (ids.a % PRIME) < (ids.b % PRIME), \
    //     f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'
    if a.mod_floor(vm_proxy.get_prime()) >= b.mod_floor(vm_proxy.get_prime()) {
        return Err(VirtualMachineError::AssertLtFelt(a.clone(), b.clone()));
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::any_box;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData;
    use crate::hint_processor::hint_processor_definition::HintProcessor;
    use crate::hint_processor::proxies::exec_scopes_proxy::get_exec_scopes_proxy;
    use crate::hint_processor::proxies::vm_proxy::get_vm_proxy;
    use crate::types::exec_scope::ExecutionScopes;
    use crate::types::relocatable::Relocatable;
    use crate::utils::test_utils::*;
    use crate::vm::vm_core::VirtualMachine;
    use crate::vm::vm_memory::memory::Memory;
    use crate::{
        bigint, bigint_str, relocatable,
        vm::{
            errors::memory_errors::MemoryError, runners::builtin_runner::RangeCheckBuiltinRunner,
        },
    };
    use num_bigint::Sign;
    use std::any::Any;

    from_bigint_str![39, 40, 77];
    #[test]
    fn run_is_nn_hint_false() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 10;
        //Insert ids into memory
        vm.memory = memory![((1, 9), (-1))];
        add_segments!(vm, 1);
        //Create ids_data & hint_data
        let ids_data = ids_data!["a"];
        //Execute the hint
        run_hint!(vm, ids_data, hint_code).expect("Error while executing hint");
        //Check that ap now contains false (1)
        check_memory![vm.memory, ((1, 0), 1)];
    }

    #[test]
    fn run_is_nn_hint_true() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 5;
        //Insert ids into memory
        vm.memory = memory![((1, 4), 1)];
        add_segments!(vm, 1);
        //Create ids_data
        let ids_data = ids_data!["a"];
        //Execute the hint
        run_hint!(vm, ids_data, hint_code).expect("Error while executing hint");
        //Check that ap now contains true (0)
        check_memory![vm.memory, ((1, 0), 0)];
    }

    #[test]
    //This test contemplates the case when the number itself is negative, but it is within the range (-prime, -range_check_bound)
    //Making the comparison return 1 (true)
    fn run_is_nn_hint_true_border_case() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 5;
        //Insert ids into memory
        vm.memory = memory![(
            (1, 4),
            (
                b"-3618502788666131213697322783095070105623107215331596699973092056135872020480",
                10
            )
        )];
        //Create ids_data
        let ids_data = ids_data!["a"];
        //Execute the hint
        run_hint!(vm, ids_data, hint_code).expect("Error while executing hint");
        //Check that ap now contains true (0)
        check_memory![vm.memory, ((1, 0), 0)];
    }

    #[test]
    fn run_is_nn_hint_no_range_check_builtin() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 5;
        //Insert ids into memory
        vm.memory = memory![((1, 4), 1)];
        //Create ids_data
        let ids_data = ids_data!["a"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn run_is_nn_hint_incorrect_ids() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = vm_with_range_check!();
        add_segments!(vm, 2);
        //Initialize ap
        //Create ids_data & hint_data
        let ids_data = ids_data!["b"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_is_nn_hint_cant_get_ids_from_memory() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = vm_with_range_check!();
        add_segments!(vm, 2);
        //Initialize fp
        vm.run_context.fp = 5;
        //Dont insert ids into memory
        //Create ids_data
        let ids_data = ids_data!["a"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 4))
            ))
        );
    }

    #[test]
    fn run_is_nn_hint_ids_are_relocatable_values() {
        let hint_code = "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 5;
        //Insert ids into memory
        vm.memory = memory![((1, 4), (2, 3))];
        //Create ids_data
        let ids_data = ids_data!["a"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 4))
            ))
        );
    }

    #[test]
    fn run_assert_le_felt_valid() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 3;
        //Insert ids into memory
        vm.memory = memory![((1, 0), 1), ((1, 1), 2), ((1, 3), 4)];
        //Create ids_data & hint_data
        let ids_data = ids_data!["a", "b", "small_inputs"];
        //Execute the hint
        assert_eq!(run_hint!(vm, ids_data, hint_code), Ok(()));
        //Hint would return an error if the assertion fails
    }

    #[test]
    fn is_le_felt_hint_true() {
        let hint_code = "memory[ap] = 0 if (ids.a % PRIME) <= (ids.b % PRIME) else 1";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 10;
        //Insert ids into memory
        vm.memory = memory![((1, 8), 1), ((1, 9), 2)];
        add_segments!(vm, 1);
        let ids_data = ids_data!["a", "b"];
        //Execute the hint
        assert_eq!(run_hint!(vm, ids_data, hint_code), Ok(()));
        //Check result
        check_memory![vm.memory, ((1, 0), 0)];
    }

    #[test]
    fn run_is_le_felt_hint_inconsistent_memory() {
        let hint_code = "memory[ap] = 0 if (ids.a % PRIME) <= (ids.b % PRIME) else 1";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 2;
        vm.memory = memory![((1, 0), 1), ((1, 1), 2)];
        //Create ids_data & hint_data
        let ids_data = ids_data!["a", "b"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((1, 0)),
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
        vm.run_context.fp = 10;
        vm.memory = memory![((1, 8), 1), ((1, 9), 2)];
        //Create ids_data & hint_data
        let ids_data = ids_data!["a", "c"];
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_assert_nn_valid() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 1;
        //Insert ids into memory
        vm.memory = memory![((1, 0), 1)];
        //Create ids_data & hint_data
        let ids_data = ids_data!["a"];
        //Execute the hint
        assert_eq!(run_hint!(vm, ids_data, hint_code), Ok(()));
        //Hint would return an error if the assertion fails
    }

    #[test]
    fn run_assert_nn_invalid() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 1;
        //Insert ids into memory
        vm.memory = memory![((1, 0), (-1))];
        //Create ids_data & hint_data
        let ids_data = ids_data!["a"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ValueOutOfRange(bigint!(-1)))
        );
    }

    #[test]
    fn run_assert_nn_incorrect_ids() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 4;
        //Insert ids into memory
        vm.memory = memory![((1, 0), (-1))];
        let ids_data = ids_data!["incorrect_id"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::FailedToGetIds),
        );
    }

    #[test]
    fn run_assert_nn_a_is_not_integer() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 4;
        //Insert ids into memory
        vm.memory = memory![((1, 0), (10, 10))];
        let ids_data = ids_data!["a"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 3))
            ))
        );
    }

    #[test]
    fn run_assert_nn_no_range_check_builtin() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 1;
        //Insert ids into memory
        vm.memory = memory![((1, 0), 1)];
        let ids_data = ids_data!["a"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn run_assert_nn_reference_is_not_in_memory() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'";
        let mut vm = vm_with_range_check!();
        add_segments!(vm, 1);
        //Initialize fp
        vm.run_context.fp = 4;
        let ids_data = ids_data!["a"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 3))
            ))
        );
    }

    #[test]
    fn run_is_assert_le_felt_invalid() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 3;
        //Insert ids into memory
        vm.memory = memory![((1, 0), 2), ((1, 1), 1), ((1, 3), 4)];
        let ids_data = ids_data!["a", "b", "small_inputs"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::NonLeFelt(bigint!(2), bigint!(1)))
        );
    }

    #[test]
    fn run_is_assert_le_felt_small_inputs_not_local() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 3;
        //Insert ids into memory
        vm.memory = memory![((1, 0), 1), ((1, 1), 2), ((1, 2), 4)];
        let ids_data = ids_data!["a", "b", "small_inputs"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((1, 2)),
                    MaybeRelocatable::from(bigint!(4)),
                    MaybeRelocatable::from(bigint!(1))
                )
            ))
        );
    }

    #[test]
    fn run_is_assert_le_felt_a_is_not_integer() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 3;
        //Insert ids into memory
        vm.memory = memory![((1, 0), (1, 0)), ((1, 1), 1), ((1, 3), 4)];
        let ids_data = ids_data!["a", "b", "small_inputs"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 0))
            ))
        );
    }

    #[test]
    fn run_is_assert_le_felt_b_is_not_integer() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 3;
        //Insert ids into memory
        vm.memory = memory![((1, 0), 1), ((1, 1), (1, 0)), ((1, 3), 4)];
        let ids_data = ids_data!["a", "b", "small_inputs"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 1))
            ))
        );
    }

    #[test]
    fn run_is_nn_hint_out_of_range_false() {
        let hint_code =
            "memory[ap] = 0 if 0 <= ((-ids.a - 1) % PRIME) < range_check_builtin.bound else 1";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 5;
        //Insert ids into memory
        vm.memory = memory![((1, 4), 2)];
        add_segments!(vm, 1);
        //Create ids_data
        let ids_data = ids_data!["a"];
        //Execute the hint
        run_hint!(vm, ids_data, hint_code).expect("Error while executing hint");
        check_memory![vm.memory, ((1, 0), 1)];
    }

    #[test]
    fn run_is_nn_hint_out_of_range_true() {
        let hint_code =
            "memory[ap] = 0 if 0 <= ((-ids.a - 1) % PRIME) < range_check_builtin.bound else 1";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 5;
        //Insert ids into memory
        vm.memory = memory![((1, 4), (-1))];
        add_segments!(vm, 1);
        //Create ids_data
        let ids_data = ids_data!["a"];
        //Execute the hint
        run_hint!(vm, ids_data, hint_code).expect("Error while executing hint");
        check_memory![vm.memory, ((1, 0), 0)];
    }
    #[test]
    fn run_assert_not_equal_int_false() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 10;
        //Insert ids into memory
        vm.memory = memory![((1, 8), 1), ((1, 9), 1)];
        let ids_data = ids_data!["a", "b"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::AssertNotEqualFail(
                MaybeRelocatable::from(bigint!(1)),
                MaybeRelocatable::from(bigint!(1))
            ))
        );
    }

    #[test]
    fn run_assert_not_equal_int_true() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 10;
        //Insert ids into memory
        vm.memory = memory![((1, 8), 1), ((1, 9), 3)];
        let ids_data = ids_data!["a", "b"];
        //Execute the hint
        assert_eq!(run_hint!(vm, ids_data, hint_code), Ok(()));
    }

    #[test]
    fn run_assert_not_equal_int_false_mod() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'";
        let mut vm = vm!();
        add_segments!(vm, 2);
        //Initialize fp
        vm.run_context.fp = 10;
        //Insert ids into memory
        vm.memory = memory![
            ((1, 8), (-1)),
            (
                (1, 9),
                (
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020480",
                    10
                )
            )
        ];
        let ids_data = ids_data!["a", "b"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
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
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 10;
        //Insert ids into memory
        vm.memory = memory![((1, 8), (1, 0)), ((1, 9), (1, 0))];
        let ids_data = ids_data!["a", "b"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::AssertNotEqualFail(
                MaybeRelocatable::from((1, 0)),
                MaybeRelocatable::from((1, 0))
            ))
        );
    }

    #[test]
    fn run_assert_not_equal_relocatable_true() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 10;
        //Insert ids into memory
        vm.memory = memory![((1, 8), (0, 1)), ((1, 9), (0, 0))];
        let ids_data = ids_data!["a", "b"];
        //Execute the hint
        assert_eq!(run_hint!(vm, ids_data, hint_code), Ok(()));
    }

    #[test]
    fn run_assert_non_equal_relocatable_diff_index() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 10;
        //Insert ids into memory
        vm.memory = memory![((1, 8), (2, 0)), ((1, 9), (1, 0))];
        let ids_data = ids_data!["a", "b"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::DiffIndexComp(
                relocatable!(2, 0),
                relocatable!(1, 0)
            ))
        );
    }

    #[test]
    fn run_assert_not_equal_relocatable_and_integer() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 10;
        //Insert ids into memory
        vm.memory = memory![((1, 8), (1, 0)), ((1, 9), 1)];
        let ids_data = ids_data!["a", "b"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
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
        // //Initialize fp
        vm.run_context.fp = 5;
        //Insert ids into memory
        vm.memory = memory![((1, 4), 5)];
        //Create ids
        let ids_data = ids_data!["value"];

        assert_eq!(run_hint!(vm, ids_data, hint_code), Ok(()));
    }

    #[test]
    fn run_assert_not_zero_false() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'";
        let mut vm = vm!();
        // //Initialize fp
        vm.run_context.fp = 5;
        //Insert ids into memory
        vm.memory = memory![((1, 4), 0)];
        //Create ids
        let ids_data = ids_data!["value"];
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::AssertNotZero(bigint!(0), vm.prime))
        );
    }

    #[test]
    fn run_assert_not_zero_false_with_prime() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'";
        let mut vm = vm!();
        add_segments!(vm, 2);
        //Initialize fp
        vm.run_context.fp = 5;
        //Insert ids into memory
        vm.memory = memory![(
            (1, 4),
            (
                b"3618502788666131213697322783095070105623107215331596699973092056135872020481",
                10
            )
        )];
        //Create ids_data & hint_data
        let ids_data = ids_data!["value"];
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::AssertNotZero(
                vm.prime.clone(),
                vm.prime
            ))
        );
    }

    #[test]
    fn run_assert_not_zero_incorrect_id() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'";
        let mut vm = vm!();
        // //Initialize fp
        vm.run_context.fp = 5;
        //Insert ids into memory
        vm.memory = memory![((1, 4), 0)];
        //Create invalid id key
        let ids_data = ids_data!["incorrect_id"];
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_assert_not_zero_expected_integer_error() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'";
        let mut vm = vm!();
        // //Initialize fp
        vm.run_context.fp = 5;
        //Insert ids into memory
        vm.memory = memory![((1, 4), (1, 0))];
        //Create ids_data & hint_data
        let ids_data = ids_data!["value"];
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 4))
            ))
        );
    }

    #[test]
    fn run_split_int_assertion_invalid() {
        let hint_code = "assert ids.value == 0, 'split_int(): value is out of range.'";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 5;
        //Insert ids into memory
        vm.memory = memory![((1, 4), 1)];
        let ids_data = ids_data!["value"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::SplitIntNotZero)
        );
    }

    #[test]
    fn run_split_int_assertion_valid() {
        let hint_code = "assert ids.value == 0, 'split_int(): value is out of range.'";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 5;
        //Insert ids into memory
        vm.memory = memory![((1, 4), 0)];
        let ids_data = ids_data!["value"];
        //Execute the hint
        assert_eq!(run_hint!(vm, ids_data, hint_code), Ok(()));
    }

    #[test]
    fn run_split_int_valid() {
        let hint_code = "memory[ids.output] = res = (int(ids.value) % PRIME) % ids.base\nassert res < ids.bound, f'split_int(): Limb {res} is out of range.'";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 4;
        //Insert ids into memory
        vm.memory = memory![((1, 0), (2, 0)), ((1, 1), 2), ((1, 2), 10), ((1, 3), 100)];
        add_segments!(vm, 2);
        let ids_data = ids_data!["output", "value", "base", "bound"];
        //Execute the hint
        assert_eq!(run_hint!(vm, ids_data, hint_code), Ok(()));
        check_memory![vm.memory, ((2, 0), 2)];
    }

    #[test]
    fn run_split_int_invalid() {
        let hint_code = "memory[ids.output] = res = (int(ids.value) % PRIME) % ids.base\nassert res < ids.bound, f'split_int(): Limb {res} is out of range.'";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 4;
        //Insert ids into memory
        vm.memory = memory![
            ((1, 0), (2, 0)),
            ((1, 1), 100),
            ((1, 2), 10000),
            ((1, 3), 10)
        ];
        add_segments!(vm, 2);
        let ids_data = ids_data!["output", "value", "base", "bound"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::SplitIntLimbOutOfRange(bigint!(100)))
        );
    }

    #[test]
    fn run_is_positive_hint_true() {
        let hint_code =
        "from starkware.cairo.common.math_utils import is_positive\nids.is_positive = 1 if is_positive(\n    value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 2;
        //Insert ids.value into memory
        vm.memory = memory![((1, 0), 250)];
        //Dont insert ids.is_positive as we need to modify it inside the hint
        //Create ids
        let ids_data = ids_data!["value", "is_positive"];
        //Execute the hint
        run_hint!(vm, ids_data, hint_code).expect("Error while executing hint");
        //Check that is_positive now contains 1 (true)
        check_memory![vm.memory, ((1, 1), 1)];
    }

    #[test]
    fn run_is_positive_hint_false() {
        let hint_code =
        "from starkware.cairo.common.math_utils import is_positive\nids.is_positive = 1 if is_positive(\n    value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 2;
        //Insert ids.value into memory
        vm.memory = memory![((1, 0), (-250))];
        //Dont insert ids.is_positive as we need to modify it inside the hint
        let ids_data = ids_data!["value", "is_positive"];
        //Execute the hint
        run_hint!(vm, ids_data, hint_code).expect("Error while executing hint");
        //Check that is_positive now contains 0 (false)
        check_memory![vm.memory, ((1, 1), 0)];
    }

    #[test]
    fn run_is_positive_hint_outside_valid_range() {
        let hint_code =
        "from starkware.cairo.common.math_utils import is_positive\nids.is_positive = 1 if is_positive(\n    value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 2;
        //Insert ids.value into memory
        vm.memory = memory![(
            (1, 0),
            (
                b"3618502761706184546546682988428055018603476541694452277432519575032261771265",
                10
            )
        )];
        //Dont insert ids.is_positive as we need to modify it inside the hint
        let ids_data = ids_data!["value", "is_positive"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ValueOutsideValidRange(as_int(
                &BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217727]),
                &vm.prime
            )))
        );
    }

    #[test]
    fn run_is_positive_hint_is_positive_not_empty() {
        let hint_code ="from starkware.cairo.common.math_utils import is_positive\nids.is_positive = 1 if is_positive(\n    value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0";
        let mut vm = vm_with_range_check!();
        add_segments!(vm, 2);
        //Initialize fp
        vm.run_context.fp = 2;
        //Insert ids into memory
        vm.memory = memory![((1, 0), 2), ((1, 1), 4)];
        let ids_data = ids_data!["value", "is_positive"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((1, 1)),
                    MaybeRelocatable::from(bigint!(4)),
                    MaybeRelocatable::from(bigint!(1))
                )
            ))
        );
    }

    #[test]
    fn run_sqrt_valid() {
        let hint_code = "from starkware.python.math_utils import isqrt\nvalue = ids.value % PRIME\nassert value < 2 ** 250, f\"value={value} is outside of the range [0, 2**250).\"\nassert 2 ** 250 < PRIME\nids.root = isqrt(value)";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 2;
        //Insert ids.value into memory
        vm.memory = memory![((1, 0), 81)];
        //Create ids
        let ids_data = ids_data!["value", "root"];
        //Execute the hint
        assert_eq!(run_hint!(vm, ids_data, hint_code), Ok(()));
        //Check that root (0,1) has the square root of 81
        check_memory![vm.memory, ((1, 1), 9)];
    }

    #[test]
    fn run_sqrt_invalid_negative_number() {
        let hint_code = "from starkware.python.math_utils import isqrt\nvalue = ids.value % PRIME\nassert value < 2 ** 250, f\"value={value} is outside of the range [0, 2**250).\"\nassert 2 ** 250 < PRIME\nids.root = isqrt(value)";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 2;
        //Insert ids.value into memory
        vm.memory = memory![((1, 0), (-81))];
        //Create ids
        let ids_data = ids_data!["value", "root"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ValueOutside250BitRange(bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020400"
            )))
        );
    }

    #[test]
    fn run_sqrt_invalid_mismatched_root() {
        let hint_code = "from starkware.python.math_utils import isqrt\nvalue = ids.value % PRIME\nassert value < 2 ** 250, f\"value={value} is outside of the range [0, 2**250).\"\nassert 2 ** 250 < PRIME\nids.root = isqrt(value)";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 2;
        //Insert ids.value into memory
        vm.memory = memory![((1, 0), 81), ((1, 1), 7)];
        //Create ids
        let ids_data = ids_data!["value", "root"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((1, 1)),
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
        //Initialize fp
        vm.run_context.fp = 4;
        //Insert ids into memory
        vm.memory = memory![((1, 2), 5), ((1, 3), 7)];
        //Create ids
        let ids_data = ids_data!["r", "q", "div", "value"];
        //Execute the hint
        assert!(run_hint!(vm, ids_data, hint_code).is_ok());
        check_memory![vm.memory, ((1, 0), 2), ((1, 1), 1)];
    }

    #[test]
    fn unsigned_div_rem_out_of_range() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\nids.q, ids.r = divmod(ids.value, ids.div)";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 4;
        //Insert ids into memory
        vm.memory = memory![((1, 2), (-5)), ((1, 3), 7)];
        //Create ids
        let ids_data = ids_data!["r", "q", "div", "value"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
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
        //Initialize fp
        vm.run_context.fp = 4;
        //Insert ids into memory
        vm.memory = memory![((1, 2), 5), ((1, 3), 7)];
        //Create ids_data
        let ids_data = ids_data!["r", "q", "div", "value"];
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn unsigned_div_rem_inconsitent_memory() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\nids.q, ids.r = divmod(ids.value, ids.div)";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 4;
        //Insert ids into memory
        vm.memory = memory![((1, 0), 5), ((1, 2), 5), ((1, 3), 7)];
        //Create ids_data
        let ids_data = ids_data!["r", "q", "div", "value"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((1, 0)),
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
        //Initialize fp
        vm.run_context.fp = 4;
        //Insert ids into memory
        vm.memory = memory![((1, 2), 5), ((1, 3), 7)];
        //Create ids
        let ids_data = ids_data!["a", "b", "iv", "vlue"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::FailedToGetIds)
        )
    }

    #[test]
    fn signed_div_rem_success() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 6;
        //Insert ids into memory
        vm.memory = memory![((1, 3), 5), ((1, 4), 10), ((1, 5), 29)];
        //Create ids
        let ids_data = ids_data!["r", "biased_q", "range_check_ptr", "div", "value", "bound"];
        //Execute the hint
        assert!(run_hint!(vm, ids_data, hint_code).is_ok());
        check_memory![vm.memory, ((1, 0), 0), ((1, 1), 31)];
    }

    #[test]
    fn signed_div_rem_negative_quotient() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 6;
        //Insert ids into memory
        vm.memory = memory![((1, 3), 7), ((1, 4), (-10)), ((1, 5), 29)];
        //Create ids
        let ids_data = ids_data!["r", "biased_q", "range_check_ptr", "div", "value", "bound"];
        //Execute the hint
        assert!(run_hint!(vm, ids_data, hint_code).is_ok());
        check_memory![vm.memory, ((1, 0), 4), ((1, 1), 27)];
    }

    #[test]
    fn signed_div_rem_out_of_range() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 6;
        //Insert ids into memory
        vm.memory = memory![((1, 3), (-5)), ((1, 4), 10), ((1, 5), 29)];
        //Create ids
        let ids_data = ids_data!["r", "biased_q", "range_check_ptr", "div", "value", "bound"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
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
        //Initialize fp
        vm.run_context.fp = 6;
        //Insert ids into memory
        vm.memory = memory![((1, 3), 5), ((1, 4), 10), ((1, 5), 29)];
        //Create ids
        let ids_data = ids_data!["r", "biased_q", "range_check_ptr", "div", "value", "bound"];
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn signed_div_rem_inconsitent_memory() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 6;
        //Insert ids into memory
        vm.memory = memory![((1, 1), 10), ((1, 3), 5), ((1, 4), 10), ((1, 5), 29)];
        //Create ids
        let ids_data = ids_data!["r", "biased_q", "range_check_ptr", "div", "value", "bound"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((1, 1)),
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
        //Initialize fp
        vm.run_context.fp = 6;
        //Insert ids into memory
        vm.memory = memory![((1, 3), 5), ((1, 4), 10), ((1, 5), 29)];
        //Create ids
        let ids_data = ids_data!["r", "b", "r", "d", "v", "b"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::FailedToGetIds)
        )
    }

    #[test]
    fn run_assert_250_bit_valid() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int\n\n# Correctness check.\nvalue = as_int(ids.value, PRIME) % PRIME\nassert value < ids.UPPER_BOUND, f'{value} is outside of the range [0, 2**250).'\n\n# Calculation for the assertion.\nids.high, ids.low = divmod(ids.value, ids.SHIFT)";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 3;
        //Insert ids into memory
        vm.memory = memory![((1, 0), 1)];
        //Create ids
        let ids_data = ids_data!["value", "high", "low"];
        //Execute the hint
        assert_eq!(run_hint!(vm, ids_data, hint_code), Ok(()));
        //Hint would return an error if the assertion fails
        //Check ids.high and ids.low values
        check_memory![vm.memory, ((1, 1), 0), ((1, 2), 1)];
    }

    #[test]
    fn run_assert_250_bit_invalid() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int\n\n# Correctness check.\nvalue = as_int(ids.value, PRIME) % PRIME\nassert value < ids.UPPER_BOUND, f'{value} is outside of the range [0, 2**250).'\n\n# Calculation for the assertion.\nids.high, ids.low = divmod(ids.value, ids.SHIFT)";
        let mut vm = vm!();
        //Initialize fp
        vm.run_context.fp = 3;
        //Insert ids into memory
        //ids.value
        vm.memory = memory![(
            (1, 0),
            (
                b"3618502788666131106986593281521497120414687020801267626233049500247285301248",
                10
            )
        )];
        //Create ids
        let ids_data = ids_data!["value", "high", "low"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ValueOutside250BitRange(
                bigint!(1).shl(251i32)
            ))
        );
    }

    #[test]
    fn run_split_felt_ok() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128";
        let mut vm = vm_with_range_check!();
        vm.memory = memory![
            ((1, 3), (b"7335438970432432812899076431678123043273", 10)),
            ((1, 4), (2, 0))
        ];
        add_segments!(vm, 1);
        //Initialize fp
        vm.run_context.fp = 7;
        //Create ids
        let ids_data = HashMap::from([
            ("value".to_string(), HintReference::new_simple(-4)),
            ("low".to_string(), HintReference::new(-3, 0, true, true)),
            ("high".to_string(), HintReference::new(-3, 1, true, true)),
        ]);
        //Execute the hint
        assert_eq!(run_hint!(vm, ids_data, hint_code), Ok(()));
        //Check hint memory inserts
        check_memory![
            vm.memory,
            ((2, 0), (b"189509265092725080168209675610990602697", 10)),
            ((2, 1), 21)
        ];
    }

    #[test]
    fn run_split_felt_incorrect_ids() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128";
        let mut vm = vm_with_range_check!();
        vm.memory = memory![
            ((1, 3), (b"7335438970432432812899076431678123043273", 10)),
            ((1, 4), (2, 0))
        ];
        //Initialize fp
        vm.run_context.fp = 7;
        //Create incomplete ids
        //Create ids_data & hint_data
        let ids_data = ids_data!["low"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_split_felt_fails_first_insert() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128";
        let mut vm = vm_with_range_check!();
        vm.memory = memory![
            ((1, 3), (b"7335438970432432812899076431678123043273", 10)),
            ((1, 4), (2, 0)),
            ((2, 0), 99)
        ];
        //Initialize fp
        vm.run_context.fp = 7;
        //Create ids_data & hint_data
        let ids_data = HashMap::from([
            ("value".to_string(), HintReference::new_simple(-4)),
            ("low".to_string(), HintReference::new(-3, 0, true, true)),
            ("high".to_string(), HintReference::new(-3, 1, true, true)),
        ]);

        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
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
        "from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128";
        let mut vm = vm_with_range_check!();
        vm.memory = memory![
            ((1, 4), (2, 0)),
            ((1, 3), (b"7335438970432432812899076431678123043273", 10)),
            ((2, 1), 99)
        ];
        add_segments!(vm, 1);
        //Initialize fp
        vm.run_context.fp = 7;
        //Create ids_data & hint_data
        let ids_data = HashMap::from([
            ("value".to_string(), HintReference::new_simple(-4)),
            ("low".to_string(), HintReference::new(-3, 0, true, true)),
            ("high".to_string(), HintReference::new(-3, 1, true, true)),
        ]);
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
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
        "from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128";
        let mut vm = vm_with_range_check!();
        vm.memory = memory![((1, 3), (1, 0)), ((1, 4), (2, 0))];
        //Initialize fp
        vm.run_context.fp = 7;
        //Create ids_data & hint_data
        let ids_data = HashMap::from([
            ("value".to_string(), HintReference::new_simple(-4)),
            ("low".to_string(), HintReference::new(-3, 0, true, true)),
            ("high".to_string(), HintReference::new(-3, 1, true, true)),
        ]);
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 3))
            ))
        );
    }

    #[test]
    fn run_assert_lt_felt_ok() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 3;
        //Insert ids into memory
        vm.memory = memory![((1, 1), 1), ((1, 2), 2)];
        //Create ids
        let ids_data = ids_data!["a", "b"];
        //Execute the hint
        assert_eq!(run_hint!(vm, ids_data, hint_code), Ok(()));
    }

    #[test]
    fn run_assert_lt_felt_assert_fails() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 3;
        vm.memory = memory![((1, 1), 3), ((1, 2), 2)];
        let ids_data = ids_data!["a", "b"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::AssertLtFelt(bigint!(3), bigint!(2)))
        );
    }

    #[test]
    fn run_assert_lt_felt_incorrect_ids() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 3;
        vm.memory = memory![((1, 1), 1), ((1, 2), 2)];
        //Create Incorrects ids
        let ids_data = ids_data!["a"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_assert_lt_felt_a_is_not_integer() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 3;
        vm.memory = memory![((1, 1), (1, 0)), ((1, 2), 2)];
        let ids_data = ids_data!["a", "b"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 1))
            ))
        );
    }

    #[test]
    fn run_assert_lt_felt_b_is_not_integer() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 3;
        vm.memory = memory![((1, 1), 1), ((1, 2), (1, 0))];
        let ids_data = ids_data!["a", "b"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 2))
            ))
        );
    }

    #[test]
    fn run_assert_lt_felt_ok_failed_to_get_ids() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'";
        let mut vm = vm_with_range_check!();
        //Initialize fp
        vm.run_context.fp = 3;
        //Insert ids.a into memory
        vm.memory = memory![((1, 1), 1)];
        let ids_data = ids_data!["a", "b"];
        //Execute the hint
        assert_eq!(
            run_hint!(vm, ids_data, hint_code),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 2))
            ))
        );
    }
}
