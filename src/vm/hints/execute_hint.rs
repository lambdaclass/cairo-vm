use std::collections::HashMap;

use num_bigint::BigInt;

use crate::types::instruction::Register;
use crate::vm::errors::vm_errors::VirtualMachineError;
use crate::vm::hints::hint_utils::{
    add_segment, assert_250_bit, assert_le_felt, assert_lt_felt, assert_nn, assert_not_equal,
    assert_not_zero, is_le_felt, is_nn, is_nn_out_of_range, is_positive, signed_div_rem,
    split_felt, split_int, split_int_assert_range, sqrt, unsigned_div_rem,
};
use crate::vm::hints::set::set_add;
use crate::vm::vm_core::VirtualMachine;

#[derive(Debug, PartialEq, Clone)]
pub struct HintReference {
    pub register: Register,
    pub offset1: i32,
    pub offset2: i32,
    pub inner_dereference: bool,
}

pub fn execute_hint(
    vm: &mut VirtualMachine,
    hint_code: &[u8],
    ids: HashMap<String, BigInt>,
) -> Result<(), VirtualMachineError> {
    match std::str::from_utf8(hint_code) {
        Ok("memory[ap] = segments.add()") => add_segment(vm),
        Ok("memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1") => is_nn(vm, ids),
        Ok("memory[ap] = 0 if 0 <= ((-ids.a - 1) % PRIME) < range_check_builtin.bound else 1") => {
            is_nn_out_of_range(vm, ids)
        }
        Ok("memory[ap] = 0 if (ids.a % PRIME) <= (ids.b % PRIME) else 1") => is_le_felt(vm, ids),
        Ok("from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)",
        ) => assert_le_felt(vm, ids),
        Ok("from starkware.cairo.common.math_utils import as_int\n\n# Correctness check.\nvalue = as_int(ids.value, PRIME) % PRIME\nassert value < ids.UPPER_BOUND, f'{value} is outside of the range [0, 2**250).'\n\n# Calculation for the assertion.\nids.high, ids.low = divmod(ids.value, ids.SHIFT)",
        ) => assert_250_bit(vm, ids),
        Ok("from starkware.cairo.common.math_utils import is_positive\nids.is_positive = 1 if is_positive(\n    value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0"
        ) => is_positive(vm, ids),
        Ok("assert ids.value == 0, 'split_int(): value is out of range.'"
        ) => split_int_assert_range(vm, ids),
        Ok("memory[ids.output] = res = (int(ids.value) % PRIME) % ids.base\nassert res < ids.bound, f'split_int(): Limb {res} is out of range.'"
        ) => split_int(vm, ids),
        Ok("from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'"
        ) => assert_not_equal(vm, ids),
        Ok("from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
        ) => assert_nn(vm, ids),
        Ok("from starkware.python.math_utils import isqrt\nvalue = ids.value % PRIME\nassert value < 2 ** 250, f\"value={value} is outside of the range [0, 2**250).\"\nassert 2 ** 250 < PRIME\nids.root = isqrt(value)"
        ) => sqrt(vm, ids),
        Ok("from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'"
        ) => assert_not_zero(vm, ids),
        Ok("from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128"
        ) => split_felt(vm, ids),
        Ok("from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\nids.q, ids.r = divmod(ids.value, ids.div)") => unsigned_div_rem(vm, ids),
        Ok("from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound") => signed_div_rem(vm, ids),
        Ok("from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'") => assert_lt_felt(vm, ids),
        Ok("assert ids.elm_size > 0\n        assert ids.set_ptr <= ids.set_end_ptr\n        elm_list = memory.get_range(ids.elm_ptr, ids.elm_size)\n        for i in range(0, ids.set_end_ptr - ids.set_ptr, ids.elm_size):\n            if memory.get_range(ids.set_ptr + i, ids.elm_size) == elm_list:\n                ids.index = i // ids.elm_size\n                ids.is_elm_in_set = 1\n                break\n        else:\n            ids.is_elm_in_set = 0") => set_add(vm, ids),\n        Ok(hint_code) => Err(VirtualMachineError::UnknownHint(String::from(hint_code))),
        Err(_) => Err(VirtualMachineError::InvalidHintEncoding(
            vm.run_context.pc.clone(),
        )),
    }
}
#[cfg(test)]
mod tests {
    use std::ops::Shl;

    use crate::bigint_str;
    use crate::math_utils::as_int;
    use crate::relocatable;
    use crate::types::relocatable::MaybeRelocatable;
    use crate::types::relocatable::Relocatable;
    use crate::vm::errors::memory_errors::MemoryError;
    use crate::{bigint, vm::runners::builtin_runner::RangeCheckBuiltinRunner};
    use num_bigint::{BigInt, Sign};
    use num_traits::FromPrimitive;

    use super::*;

    #[test]
    fn run_alloc_hint_empty_memory() {
        let hint_code = "memory[ap] = segments.add()".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            //ap value is (0,0)
            Vec::new(),
        );
        //ids and references are not needed for this test
        execute_hint(&mut vm, hint_code, HashMap::new()).expect("Error while executing hint");
        //first new segment is added
        assert_eq!(vm.segments.num_segments, 1);
        //new segment base (0,0) is inserted into ap (0,0)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Ok(Some(&MaybeRelocatable::from((0, 0))))
        );
    }

    #[test]
    fn run_alloc_hint_preset_memory() {
        let hint_code = "memory[ap] = segments.add()".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
        //Add 3 segments to the memory
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        vm.run_context.ap = MaybeRelocatable::from((2, 6));
        //ids and references are not needed for this test
        execute_hint(&mut vm, hint_code, HashMap::new()).expect("Error while executing hint");
        //Segment N°4 is added
        assert_eq!(vm.segments.num_segments, 4);
        //new segment base (3,0) is inserted into ap (2,6)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((2, 6))),
            Ok(Some(&MaybeRelocatable::from((3, 0))))
        );
    }

    #[test]
    fn run_alloc_hint_ap_is_not_empty() {
        let hint_code = "memory[ap] = segments.add()".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
        //Add 3 segments to the memory
        for _ in 0..3 {
            vm.segments.add(&mut vm.memory, None);
        }
        vm.run_context.ap = MaybeRelocatable::from((2, 6));
        //Insert something into ap
        vm.memory
            .insert(
                &MaybeRelocatable::from((2, 6)),
                &MaybeRelocatable::from((2, 6)),
            )
            .unwrap();
        //ids and references are not needed for this test
        assert_eq!(
            execute_hint(&mut vm, hint_code, HashMap::new()),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((2, 6)),
                    MaybeRelocatable::from((2, 6)),
                    MaybeRelocatable::from((3, 0))
                )
            ))
        );
    }

    #[test]
    fn run_unknown_hint() {
        let hint_code = "random_invalid_code".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
        assert_eq!(
            execute_hint(&mut vm, hint_code, HashMap::new()),
            Err(VirtualMachineError::UnknownHint(
                String::from_utf8(hint_code.to_vec()).unwrap()
            ))
        );
    }

    #[test]
    fn run_is_nn_hint_false() {
        let hint_code =
            "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
        //Execute the hint
        execute_hint(&mut vm, hint_code, ids).expect("Error while executing hint");
        //Check that ap now contains false (0)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1))))
        );
    }

    #[test]
    fn run_is_nn_hint_true() {
        let hint_code =
            "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
        //Execute the hint
        execute_hint(&mut vm, hint_code, ids).expect("Error while executing hint");
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
        let hint_code =
            "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
        //Execute the hint
        execute_hint(&mut vm, hint_code, ids).expect("Error while executing hint");
        //Check that ap now contains true (1)
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
    }

    #[test]
    fn run_invalid_encoding_hint() {
        let hint_code = [0x80];
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
        assert_eq!(
            execute_hint(&mut vm, &hint_code, HashMap::new()),
            Err(VirtualMachineError::InvalidHintEncoding(vm.run_context.pc))
        );
    }

    #[test]
    fn run_is_nn_hint_no_range_check_builtin() {
        let hint_code =
            "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, &hint_code, ids),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn run_is_nn_hint_incorrect_ids() {
        let hint_code =
            "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::IncorrectIds(
                vec![String::from("a")],
                vec![String::from("b")]
            ))
        );
    }

    #[test]
    fn run_is_nn_hint_cant_get_ids_from_memory() {
        let hint_code =
            "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
        for _ in 0..2 {
            vm.segments.add(&mut vm.memory, None);
        }
        //Initialize ap, fp
        vm.run_context.ap = MaybeRelocatable::from((1, 0));
        vm.run_context.fp = MaybeRelocatable::from((0, 1));
        //Dont insert ids into memory
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::MemoryGet(MaybeRelocatable::from((
                0, 0
            ))))
        );
    }

    #[test]
    fn run_is_nn_hint_ids_are_relocatable_values() {
        let hint_code =
            "memory[ap] = 0 if 0 <= (ids.a % PRIME) < range_check_builtin.bound else 1".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn run_assert_le_felt_valid() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        ids.insert(String::from("small_inputs"), bigint!(2));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids), Ok(()));
        //Hint would return an error if the assertion fails
    }

    #[test]
    fn is_le_felt_hint_true() {
        let hint_code = "memory[ap] = 0 if (ids.a % PRIME) <= (ids.b % PRIME) else 1".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert!(execute_hint(&mut vm, hint_code, ids).is_ok());
    }

    #[test]
    fn run_is_le_felt_hint_no_range_check_builtin() {
        let hint_code = "memory[ap] = 0 if (ids.a % PRIME) <= (ids.b % PRIME) else 1".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);

        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, &hint_code, ids),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn run_is_le_felt_hint_inconsistent_memory() {
        let hint_code = "memory[ap] = 0 if (ids.a % PRIME) <= (ids.b % PRIME) else 1".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
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
        let hint_code = "memory[ap] = 0 if (ids.a % PRIME) <= (ids.b % PRIME) else 1".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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

        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("c"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);

        // Since the ids are a map, the order might not always match and so the error returned
        // sometimes might be different
        assert!(matches!(
            execute_hint(&mut vm, &hint_code, ids),
            Err(VirtualMachineError::IncorrectIds(_, _))
        ));
    }

    #[test]
    fn run_assert_nn_valid() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );

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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -4,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids), Ok(()));
        //Hint would return an error if the assertion fails
    }

    #[test]
    fn run_assert_nn_invalid() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -4,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::ValueOutOfRange(bigint!(-1)))
        );
    }

    #[test]
    fn run_assert_nn_incorrect_ids() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );

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
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -4,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::IncorrectIds(
                vec![String::from("a")],
                vec![String::from("incorrect_id")],
            ))
        );
    }

    #[test]
    fn run_assert_nn_incorrect_reference() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );

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
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: 10,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_assert_nn_a_is_not_integer() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );

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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -4,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn run_assert_nn_no_range_check_builtin() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![],
        );

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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -4,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn run_assert_nn_reference_is_not_in_memory() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert 0 <= ids.a % PRIME < range_check_builtin.bound, f'a = {ids.a} is out of range.'"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );

        vm.segments.add(&mut vm.memory, None);

        //Initialize fp
        vm.run_context.fp = MaybeRelocatable::from((0, 4));
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -4,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_is_assert_le_felt_invalid() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        ids.insert(String::from("small_inputs"), bigint!(2));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::NonLeFelt(bigint!(2), bigint!(1)))
        );
    }

    #[test]
    fn run_is_assert_le_felt_small_inputs_not_local() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        //ids.small_inputs (insert into memory, instead of leaving a gap for it (local var))
        vm.memory
            .insert(
                &MaybeRelocatable::from((0, 2)),
                &MaybeRelocatable::from(bigint!(4)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        ids.insert(String::from("small_inputs"), bigint!(2));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_is_assert_le_felt_a_is_not_integer() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        ids.insert(String::from("small_inputs"), bigint!(2));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn run_is_assert_le_felt_b_is_not_integer() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\na = ids.a % PRIME\nb = ids.b % PRIME\nassert a <= b, f'a = {a} is not less than or equal to b = {b}.'\n\nids.small_inputs = int(\n    a < range_check_builtin.bound and (b - a) < range_check_builtin.bound)"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        ids.insert(String::from("small_inputs"), bigint!(2));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 1))
            ))
        );
    }

    #[test]
    fn run_is_nn_hint_out_of_range_false() {
        let hint_code =
            "memory[ap] = 0 if 0 <= ((-ids.a - 1) % PRIME) < range_check_builtin.bound else 1"
                .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
        //Execute the hint
        execute_hint(&mut vm, hint_code, ids).expect("Error while executing hint");
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(1))))
        );
    }

    #[test]
    fn run_is_nn_hint_out_of_range_true() {
        let hint_code =
            "memory[ap] = 0 if 0 <= ((-ids.a - 1) % PRIME) < range_check_builtin.bound else 1"
                .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
        //Execute the hint
        execute_hint(&mut vm, hint_code, ids).expect("Error while executing hint");
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((1, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(0))))
        );
    }
    #[test]
    fn run_assert_not_equal_int_false() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::AssertNotEqualFail(
                MaybeRelocatable::from(bigint!(1)),
                MaybeRelocatable::from(bigint!(1))
            ))
        );
    }

    #[test]
    fn run_assert_not_equal_int_true() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids), Ok(()));
    }

    #[test]
    fn run_assert_not_equal_int_false_mod() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
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
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::AssertNotEqualFail(
                MaybeRelocatable::from((0, 0)),
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn run_assert_not_equal_relocatable_true() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids), Ok(()));
    }

    #[test]
    fn run_assert_non_equal_relocatable_diff_index() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::DiffIndexComp(
                relocatable!(1, 0),
                relocatable!(0, 0)
            ))
        );
    }

    #[test]
    fn run_assert_not_equal_relocatable_and_integer() {
        let hint_code = "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::DiffTypeComparison(
                MaybeRelocatable::from((1, 0)),
                MaybeRelocatable::from(bigint!(1))
            ))
        );
    }

    #[test]
    fn run_assert_not_zero_true() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
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

        assert_eq!(execute_hint(&mut vm, hint_code, ids), Ok(()));
    }

    #[test]
    fn run_assert_not_zero_false() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
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
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::AssertNotZero(bigint!(0), vm.prime))
        );
    }

    #[test]
    fn run_assert_not_zero_false_with_prime() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
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
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::AssertNotZero(
                vm.prime.clone(),
                vm.prime
            ))
        );
    }

    #[test]
    fn run_assert_not_zero_failed_to_get_reference() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
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
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::FailedToGetReference(bigint!(10)))
        );
    }

    #[test]
    fn run_assert_not_zero_incorrect_id() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
        //Create references
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
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
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::IncorrectIds(
                vec![String::from("value")],
                vec![String::from("incorrect_id")],
            ))
        );
    }

    #[test]
    fn run_assert_not_zero_expected_integer_error() {
        let hint_code =
    "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
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
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((0, 0))
            ))
        );
    }

    #[test]
    fn run_split_int_assertion_invalid() {
        let hint_code = "assert ids.value == 0, 'split_int(): value is out of range.'".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::SplitIntNotZero)
        );
    }

    #[test]
    fn run_split_int_assertion_valid() {
        let hint_code = "assert ids.value == 0, 'split_int(): value is out of range.'".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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
        vm.references = HashMap::from([(
            0,
            HintReference {
                register: Register::FP,
                offset1: -1,
                offset2: 0,
                inner_dereference: false,
            },
        )]);
        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids), Ok(()));
    }

    #[test]
    fn run_split_int_valid() {
        let hint_code = "memory[ids.output] = res = (int(ids.value) % PRIME) % ids.base\nassert res < ids.bound, f'split_int(): Limb {res} is out of range.'".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("output"), bigint!(0));
        ids.insert(String::from("value"), bigint!(1));
        ids.insert(String::from("base"), bigint!(2));
        ids.insert(String::from("bound"), bigint!(3));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids), Ok(()));
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((2, 0))),
            Ok(Some(&MaybeRelocatable::from(bigint!(2))))
        );
    }

    #[test]
    fn run_split_int_invalid() {
        let hint_code = "memory[ids.output] = res = (int(ids.value) % PRIME) % ids.base\nassert res < ids.bound, f'split_int(): Limb {res} is out of range.'".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("output"), bigint!(0));
        ids.insert(String::from("value"), bigint!(1));
        ids.insert(String::from("base"), bigint!(2));
        ids.insert(String::from("bound"), bigint!(3));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::SplitIntLimbOutOfRange(bigint!(100)))
        );
    }

    #[test]
    fn run_is_positive_hint_true() {
        let hint_code =
        "from starkware.cairo.common.math_utils import is_positive\nids.is_positive = 1 if is_positive(\n    value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0"
        .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        execute_hint(&mut vm, hint_code, ids).expect("Error while executing hint");
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
        .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        execute_hint(&mut vm, hint_code, ids).expect("Error while executing hint");
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
        .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::ValueOutsideValidRange(as_int(
                &BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217727]),
                &vm.prime
            )))
        );
    }

    #[test]
    fn run_is_positive_hint_is_positive_not_empty() {
        let hint_code ="from starkware.cairo.common.math_utils import is_positive\nids.is_positive = 1 if is_positive(\n    value=ids.value, prime=PRIME, rc_bound=range_check_builtin.bound) else 0"
        .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
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
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids), Ok(()));
        //Check that root (0,1) has the square root of 81
        assert_eq!(
            vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Ok(Some(&MaybeRelocatable::from(bigint!(9))))
        );
    }

    #[test]
    fn run_sqrt_invalid_negative_number() {
        let hint_code = "from starkware.python.math_utils import isqrt\nvalue = ids.value % PRIME\nassert value < 2 ** 250, f\"value={value} is outside of the range [0, 2**250).\"\nassert 2 ** 250 < PRIME\nids.root = isqrt(value)"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::ValueOutside250BitRange(bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020400"
            )))
        );
    }

    #[test]
    fn run_sqrt_invalid_mismatched_root() {
        let hint_code = "from starkware.python.math_utils import isqrt\nvalue = ids.value % PRIME\nassert value < 2 ** 250, f\"value={value} is outside of the range [0, 2**250).\"\nassert 2 ** 250 < PRIME\nids.root = isqrt(value)"
            .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
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
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\nids.q, ids.r = divmod(ids.value, ids.div)".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert!(execute_hint(&mut vm, hint_code, ids).is_ok());
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
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\nids.q, ids.r = divmod(ids.value, ids.div)".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::OutOfValidRange(
                bigint!(-5),
                bigint_str!(b"10633823966279327296825105735305134080")
            ))
        )
    }

    #[test]
    fn unsigned_div_rem_no_range_check_builtin() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\nids.q, ids.r = divmod(ids.value, ids.div)".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);

        assert_eq!(
            execute_hint(&mut vm, &hint_code, ids),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn unsigned_div_rem_inconsitent_memory() {
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\nids.q, ids.r = divmod(ids.value, ids.div)".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
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
        let hint_code = "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\nids.q, ids.r = divmod(ids.value, ids.div)".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));
        ids.insert(String::from("iv"), bigint!(2));
        ids.insert(String::from("vlue"), bigint!(3));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert!(matches!(
            execute_hint(&mut vm, &hint_code, ids),
            Err(VirtualMachineError::IncorrectIds(_, _))
        ))
    }

    #[test]
    fn signed_div_rem_success() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        ids.insert(String::from("biased_q"), bigint!(1));
        ids.insert(String::from("range_check_ptr"), bigint!(2));
        ids.insert(String::from("div"), bigint!(3));
        ids.insert(String::from("value"), bigint!(4));
        ids.insert(String::from("bound"), bigint!(5));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -6,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                4,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                5,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert!(execute_hint(&mut vm, hint_code, ids).is_ok());
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
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("r"), bigint!(0));
        ids.insert(String::from("biased_q"), bigint!(1));
        ids.insert(String::from("range_check_ptr"), bigint!(2));
        ids.insert(String::from("div"), bigint!(3));
        ids.insert(String::from("value"), bigint!(4));
        ids.insert(String::from("bound"), bigint!(5));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -6,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                4,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                5,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert!(execute_hint(&mut vm, hint_code, ids).is_ok());
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
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("r"), bigint!(0));
        ids.insert(String::from("biased_q"), bigint!(1));
        ids.insert(String::from("range_check_ptr"), bigint!(2));
        ids.insert(String::from("div"), bigint!(3));
        ids.insert(String::from("value"), bigint!(4));
        ids.insert(String::from("bound"), bigint!(5));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -6,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                4,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                5,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::OutOfValidRange(
                bigint!(-5),
                bigint_str!(b"10633823966279327296825105735305134080")
            ))
        )
    }

    #[test]
    fn signed_div_rem_no_range_check_builtin() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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
        ids.insert(String::from("biased_q"), bigint!(1));
        ids.insert(String::from("range_check_ptr"), bigint!(2));
        ids.insert(String::from("div"), bigint!(3));
        ids.insert(String::from("value"), bigint!(4));
        ids.insert(String::from("bound"), bigint!(5));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -6,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                4,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                5,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);

        assert_eq!(
            execute_hint(&mut vm, &hint_code, ids),
            Err(VirtualMachineError::NoRangeCheckBuiltin)
        );
    }

    #[test]
    fn signed_div_rem_inconsitent_memory() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("r"), bigint!(0));
        ids.insert(String::from("biased_q"), bigint!(1));
        ids.insert(String::from("range_check_ptr"), bigint!(2));
        ids.insert(String::from("div"), bigint!(3));
        ids.insert(String::from("value"), bigint!(4));
        ids.insert(String::from("bound"), bigint!(5));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -6,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                4,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                5,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
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
        let hint_code = "from starkware.cairo.common.math_utils import as_int, assert_integer\n\nassert_integer(ids.div)\nassert 0 < ids.div <= PRIME // range_check_builtin.bound, \\\n    f'div={hex(ids.div)} is out of the valid range.'\n\nassert_integer(ids.bound)\nassert ids.bound <= range_check_builtin.bound // 2, \\\n    f'bound={hex(ids.bound)} is out of the valid range.'\n\nint_value = as_int(ids.value, PRIME)\nq, ids.r = divmod(int_value, ids.div)\n\nassert -ids.bound <= q < ids.bound, \\\n    f'{int_value} / {ids.div} = {q} is out of the range [{-ids.bound}, {ids.bound}).'\n\nids.biased_q = q + ids.bound".as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -6,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -5,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                3,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                4,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                5,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert!(matches!(
            execute_hint(&mut vm, &hint_code, ids),
            Err(VirtualMachineError::IncorrectIds(_, _))
        ))
    }
    #[test]
    fn run_assert_250_bit_valid() {
        let hint_code = "from starkware.cairo.common.math_utils import as_int\n\n# Correctness check.\nvalue = as_int(ids.value, PRIME) % PRIME\nassert value < ids.UPPER_BOUND, f'{value} is outside of the range [0, 2**250).'\n\n# Calculation for the assertion.\nids.high, ids.low = divmod(ids.value, ids.SHIFT)"
             .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids), Ok(()));
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
             .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            Vec::new(),
        );
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
                &MaybeRelocatable::from(bigint!(1).shl(251)),
            )
            .unwrap();
        //Create ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("value"), bigint!(0));
        ids.insert(String::from("high"), bigint!(1));
        ids.insert(String::from("low"), bigint!(2));
        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::ValueOutside250BitRange(
                bigint!(1).shl(251)
            ))
        );
    }

    #[test]
    fn run_split_felt_ok() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128"
        .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: true,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 1,
                    inner_dereference: true,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids), Ok(()));

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
        .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: true,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 1,
                    inner_dereference: true,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, incomplete_ids),
            Err(VirtualMachineError::IncorrectIds(
                vec![
                    String::from("high"),
                    String::from("low"),
                    String::from("value"),
                ],
                vec![String::from("value"),],
            ))
        );
    }
    #[test]
    fn run_split_felt_failed_to_get_ids() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128"
        .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: true,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 1,
                    inner_dereference: true,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_split_felt_fails_first_insert() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert ids.MAX_HIGH < 2**128 and ids.MAX_LOW < 2**128\nassert PRIME - 1 == ids.MAX_HIGH * 2**128 + ids.MAX_LOW\nassert_integer(ids.value)\nids.low = ids.value & ((1 << 128) - 1)\nids.high = ids.value >> 128"
        .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: true,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 1,
                    inner_dereference: true,
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
            execute_hint(&mut vm, hint_code, ids),
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
        .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: true,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 1,
                    inner_dereference: true,
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
            execute_hint(&mut vm, hint_code, ids),
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
        .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -4,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 0,
                    inner_dereference: true,
                },
            ),
            (
                2,
                HintReference {
                    register: Register::FP,
                    offset1: -3,
                    offset2: 1,
                    inner_dereference: true,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 3))
            ))
        );
    }

    #[test]
    fn run_assert_lt_felt_ok() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"
        .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(execute_hint(&mut vm, hint_code, ids), Ok(()));
    }

    #[test]
    fn run_assert_lt_felt_assert_fails() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"
        .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::AssertLtFelt(bigint!(3), bigint!(2)))
        );
    }

    #[test]
    fn run_assert_lt_felt_incorrect_ids() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"
        .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::IncorrectIds(
                vec![String::from("a"), String::from("b"),],
                vec![String::from("a"),],
            ))
        );
    }

    #[test]
    fn run_assert_lt_felt_incorrect_references() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"
        .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        // vm.memory
        //     .insert(
        //         &MaybeRelocatable::from((1, 2)),
        //         &MaybeRelocatable::from(bigint!(2)),
        //     )
        //     .unwrap();

        //Create incorrects ids
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));

        //Create incorrect references
        vm.references = HashMap::from([
            // Incorrect reference
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: 0,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }

    #[test]
    fn run_assert_lt_felt_a_is_not_integer() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"
        .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 1))
            ))
        );
    }

    #[test]
    fn run_assert_lt_felt_b_is_not_integer() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"
        .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::ExpectedInteger(
                MaybeRelocatable::from((1, 2))
            ))
        );
    }

    #[test]
    fn run_assert_lt_felt_ok_failed_to_get_ids() {
        let hint_code =
        "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.a)\nassert_integer(ids.b)\nassert (ids.a % PRIME) < (ids.b % PRIME), \\\n    f'a = {ids.a % PRIME} is not less than b = {ids.b % PRIME}.'"
        .as_bytes();
        let mut vm = VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            vec![(
                "range_check".to_string(),
                Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
            )],
        );
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
        let mut ids = HashMap::<String, BigInt>::new();
        ids.insert(String::from("a"), bigint!(0));
        ids.insert(String::from("b"), bigint!(1));

        //Create references
        vm.references = HashMap::from([
            (
                0,
                HintReference {
                    register: Register::FP,
                    offset1: -2,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
            (
                1,
                HintReference {
                    register: Register::FP,
                    offset1: -1,
                    offset2: 0,
                    inner_dereference: false,
                },
            ),
        ]);
        //Execute the hint
        assert_eq!(
            execute_hint(&mut vm, hint_code, ids),
            Err(VirtualMachineError::FailedToGetIds)
        );
    }
}
