use super::{
    hint_utils::get_relocatable_from_var_name,
    uint256_utils::{u256_pack, Uint256},
    uint_utils::{pack, split},
};
use crate::{
    hint_processor::hint_processor_definition::HintReference,
    serde::deserialize_program::ApTracking,
    vm::{errors::hint_errors::HintError, vm_core::VirtualMachine},
};
use crate::{stdlib::borrow::Cow, types::relocatable::Relocatable};
use felt::Felt252;
use num_bigint::BigUint;
use std::collections::HashMap;

pub(crate) struct Uint512<'a> {
    pub d0: Cow<'a, Felt252>,
    pub d1: Cow<'a, Felt252>,
    pub d2: Cow<'a, Felt252>,
    pub d3: Cow<'a, Felt252>,
}

impl<'a> Uint512<'a> {
    pub(crate) fn from_base_addr(
        addr: Relocatable,
        name: &str,
        vm: &'a VirtualMachine,
    ) -> Result<Self, HintError> {
        Ok(Self {
            d0: vm.get_integer(addr).map_err(|_| {
                HintError::IdentifierHasNoMember(name.to_string(), "d0".to_string())
            })?,
            d1: vm.get_integer((addr + 1)?).map_err(|_| {
                HintError::IdentifierHasNoMember(name.to_string(), "d1".to_string())
            })?,
            d2: vm.get_integer((addr + 1)?).map_err(|_| {
                HintError::IdentifierHasNoMember(name.to_string(), "d2".to_string())
            })?,
            d3: vm.get_integer((addr + 1)?).map_err(|_| {
                HintError::IdentifierHasNoMember(name.to_string(), "d3".to_string())
            })?,
        })
    }

    pub(crate) fn from_var_name(
        name: &str,
        vm: &'a VirtualMachine,
        ids_data: &HashMap<String, HintReference>,
        ap_tracking: &ApTracking,
    ) -> Result<Self, HintError> {
        let base_addr = get_relocatable_from_var_name(name, vm, ids_data, ap_tracking)?;
        Self::from_base_addr(base_addr, name, vm)
    }

    // pub(crate) fn from_values(low: Felt252, high: Felt252) -> Self {
    //     let low = Cow::Owned(low);
    //     let high = Cow::Owned(high);
    //     Self { low, high }
    // }

    // pub(crate) fn insert_from_var_name(
    //     self,
    //     var_name: &str,
    //     vm: &mut VirtualMachine,
    //     ids_data: &HashMap<String, HintReference>,
    //     ap_tracking: &ApTracking,
    // ) -> Result<(), HintError> {
    //     let addr = get_relocatable_from_var_name(var_name, vm, ids_data, ap_tracking)?;

    //     vm.insert_value(addr, self.low.into_owned())?;
    //     vm.insert_value((addr + 1)?, self.high.into_owned())?;

    //     Ok(())
    // }
}

pub fn split_u512(num: &BigUint) -> [BigUint; 4] {
    split::<4>(num, 128)
}

pub(crate) fn u512_pack(num: Uint512) -> BigUint {
    pack([num.d0, num.d1, num.d2, num.d3], 128)
}

#[allow(unused)]
/// Implements hint:
/// ```python
/// def split(num: int, num_bits_shift: int, length: int):
///     a = []
///     for _ in range(length):
///         a.append( num & ((1 << num_bits_shift) - 1) )
///         num = num >> num_bits_shift
///     return tuple(a)
///
/// def pack(z, num_bits_shift: int) -> int:
///     limbs = (z.low, z.high)
///     return sum(limb << (num_bits_shift * i) for i, limb in enumerate(limbs))
///
/// def pack_extended(z, num_bits_shift: int) -> int:
///     limbs = (z.d0, z.d1, z.d2, z.d3)
///     return sum(limb << (num_bits_shift * i) for i, limb in enumerate(limbs))
///
/// x = pack_extended(ids.x, num_bits_shift = 128)
/// div = pack(ids.div, num_bits_shift = 128)
///
/// quotient, remainder = divmod(x, div)
///
/// quotient_split = split(quotient, num_bits_shift=128, length=4)
///
/// ids.quotient.d0 = quotient_split[0]
/// ids.quotient.d1 = quotient_split[1]
/// ids.quotient.d2 = quotient_split[2]
/// ids.quotient.d3 = quotient_split[3]
///
/// remainder_split = split(remainder, num_bits_shift=128, length=2)
/// ids.remainder.low = remainder_split[0]
/// ids.remainder.high = remainder_split[1]
/// ```
pub fn uint512_unsigned_div_rem(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    let ids_x = Uint512::from_var_name("x", vm, ids_data, ap_tracking)?;
    let ids_div = Uint256::from_var_name("div", vm, ids_data, ap_tracking)?;

    let x = u512_pack(ids_x);
    let div = u256_pack(ids_div);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::any_box;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
    use crate::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData;
    use crate::hint_processor::hint_processor_definition::HintProcessor;
    use crate::types::exec_scope::ExecutionScopes;
    use crate::utils::test_utils::*;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_uint512_unsigned_div_rem_ok() {
        let hint_code = "def split(num: int, num_bits_shift: int, length: int):\n    a = []\n    for _ in range(length):\n        a.append( num & ((1 << num_bits_shift) - 1) )\n        num = num >> num_bits_shift \n    return tuple(a)\n\ndef pack(z, num_bits_shift: int) -> int:\n    limbs = (z.low, z.high)\n    return sum(limb << (num_bits_shift * i) for i, limb in enumerate(limbs))\n    \ndef pack_extended(z, num_bits_shift: int) -> int:\n    limbs = (z.d0, z.d1, z.d2, z.d3)\n    return sum(limb << (num_bits_shift * i) for i, limb in enumerate(limbs))\n\nx = pack_extended(ids.x, num_bits_shift = 128)\ndiv = pack(ids.div, num_bits_shift = 128)\n\nquotient, remainder = divmod(x, div)\n\nquotient_split = split(quotient, num_bits_shift=128, length=4)\n\nids.quotient.d0 = quotient_split[0]\nids.quotient.d1 = quotient_split[1]\nids.quotient.d2 = quotient_split[2]\nids.quotient.d3 = quotient_split[3]\n\nremainder_split = split(remainder, num_bits_shift=128, length=2)\nids.remainder.low = remainder_split[0]\nids.remainder.high = remainder_split[1]";
        let mut vm = vm_with_range_check!();

        vm.segments = segments![
            ((1, 0), 0),
            ((1, 1), 0),
            ((1, 2), 1),
            ((1, 3), 0),
            ((1, 4), 0),
            ((1, 5), 1)
        ];
        // Create hint_data
        let ids_data =
            non_continuous_ids_data![("x", 0), ("div", 4), ("quotient", 6), ("remainder", 10)];
        assert!(run_hint!(vm, ids_data, hint_code, exec_scopes_ref!()).is_ok());
        //Check hint memory inserts
        check_memory![
            vm.segments.memory,
            // quotient
            ((1, 6), 0),
            ((1, 7), 0),
            ((1, 8), 0),
            ((1, 9), 0),
            // remainder
            ((1, 10), 0),
            ((1, 11), 0),
        ];
    }
}
