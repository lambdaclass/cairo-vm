use crate::stdlib::{borrow::Cow, collections::HashMap, prelude::*};
use crate::{
    hint_processor::{
        builtin_hint_processor::hint_utils::get_relocatable_from_var_name,
        hint_processor_definition::HintReference,
    },
    serde::deserialize_program::ApTracking,
    types::relocatable::Relocatable,
    vm::{errors::hint_errors::HintError, vm_core::VirtualMachine},
};
use felt::Felt252;

#[derive(Debug, PartialEq)]
pub(crate) struct Uint768<'a> {
    pub d0: Cow<'a, Felt252>,
    pub d1: Cow<'a, Felt252>,
    pub d2: Cow<'a, Felt252>,
    pub d3: Cow<'a, Felt252>,
    pub d4: Cow<'a, Felt252>,
    pub d5: Cow<'a, Felt252>,
}

impl Uint768<'_> {
    pub(crate) fn from_base_addr<'a>(
        addr: Relocatable,
        name: &str,
        vm: &'a VirtualMachine,
    ) -> Result<Uint768<'a>, HintError> {
        Ok(Uint768 {
            d0: vm.get_integer(addr).map_err(|_| {
                HintError::IdentifierHasNoMember(name.to_string(), "d0".to_string())
            })?,
            d1: vm.get_integer((addr + 1)?).map_err(|_| {
                HintError::IdentifierHasNoMember(name.to_string(), "d1".to_string())
            })?,
            d2: vm.get_integer((addr + 2)?).map_err(|_| {
                HintError::IdentifierHasNoMember(name.to_string(), "d2".to_string())
            })?,
            d3: vm.get_integer((addr + 3)?).map_err(|_| {
                HintError::IdentifierHasNoMember(name.to_string(), "d3".to_string())
            })?,
            d4: vm.get_integer((addr + 4)?).map_err(|_| {
                HintError::IdentifierHasNoMember(name.to_string(), "d4".to_string())
            })?,
            d5: vm.get_integer((addr + 5)?).map_err(|_| {
                HintError::IdentifierHasNoMember(name.to_string(), "d5".to_string())
            })?,
        })
    }

    pub(crate) fn from_var_name<'a>(
        name: &str,
        vm: &'a VirtualMachine,
        ids_data: &HashMap<String, HintReference>,
        ap_tracking: &ApTracking,
    ) -> Result<Uint768<'a>, HintError> {
        let base_addr = get_relocatable_from_var_name(name, vm, ids_data, ap_tracking)?;
        Uint768::from_base_addr(base_addr, name, vm)
    }
}

/* Implements Hint:
       %{
           def split(num: int, num_bits_shift: int, length: int):
               a = []
               for _ in range(length):
                   a.append( num & ((1 << num_bits_shift) - 1) )
                   num = num >> num_bits_shift
               return tuple(a)

           def pack(z, num_bits_shift: int) -> int:
               limbs = (z.d0, z.d1, z.d2)
               return sum(limb << (num_bits_shift * i) for i, limb in enumerate(limbs))

           def pack_extended(z, num_bits_shift: int) -> int:
               limbs = (z.d0, z.d1, z.d2, z.d3, z.d4, z.d5)
               return sum(limb << (num_bits_shift * i) for i, limb in enumerate(limbs))

           a = pack_extended(ids.a, num_bits_shift = 128)
           div = pack(ids.div, num_bits_shift = 128)

           quotient, remainder = divmod(a, div)

           quotient_split = split(quotient, num_bits_shift=128, length=6)

           ids.quotient.d0 = quotient_split[0]
           ids.quotient.d1 = quotient_split[1]
           ids.quotient.d2 = quotient_split[2]
           ids.quotient.d3 = quotient_split[3]
           ids.quotient.d4 = quotient_split[4]
           ids.quotient.d5 = quotient_split[5]

           remainder_split = split(remainder, num_bits_shift=128, length=3)
           ids.remainder.d0 = remainder_split[0]
           ids.remainder.d1 = remainder_split[1]
           ids.remainder.d2 = remainder_split[2]
       %}
*/

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::relocatable::MaybeRelocatable;
    use crate::utils::test_utils::*;
    use crate::vm::vm_memory::memory::Memory;
    use crate::vm::vm_memory::memory_segments::MemorySegmentManager;
    use assert_matches::assert_matches;

    use num_traits::One;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    #[test]
    fn get_uint768_from_base_addr_ok() {
        //Uint768(1,2,3)
        let mut vm = vm!();
        vm.segments = segments![((0, 0), 1), ((0, 1), 2), ((0, 2), 3)];
        let x = Uint768::from_base_addr((0, 0).into(), "x", &vm).unwrap();
        assert_eq!(x.d0.as_ref(), &Felt252::one());
        assert_eq!(x.d1.as_ref(), &Felt252::from(2));
        assert_eq!(x.d2.as_ref(), &Felt252::from(3));
    }

    #[test]
    fn get_uint768_from_base_addr_missing_member() {
        //Uint768(1,2,x,x,x)
        let mut vm = vm!();
        vm.segments = segments![((0, 0), 1), ((0, 1), 2)];
        let r = Uint768::from_base_addr((0, 0).into(), "x", &vm);
        assert_matches!(r, Err(HintError::IdentifierHasNoMember(x, y)) if x == "x" && y == "d2")
    }

    #[test]
    fn get_uint768_from_var_name_ok() {
        //Uint768(1,2,3,4,5)
        let mut vm = vm!();
        vm.set_fp(1);
        vm.segments = segments![
            ((1, 0), 1),
            ((1, 1), 2),
            ((1, 2), 3),
            ((1, 3), 4),
            ((1, 4), 5)
        ];
        let ids_data = ids_data!["x"];
        let x = Uint768::from_var_name("x", &vm, &ids_data, &ApTracking::default()).unwrap();
        assert_eq!(x.d0.as_ref(), &Felt252::one());
        assert_eq!(x.d1.as_ref(), &Felt252::from(2));
        assert_eq!(x.d2.as_ref(), &Felt252::from(3));
    }

    #[test]
    fn get_uint768_from_var_name_missing_member() {
        //Uint768(1,2,x,x,x)
        let mut vm = vm!();
        vm.set_fp(1);
        vm.segments = segments![((1, 0), 1), ((1, 1), 2)];
        let ids_data = ids_data!["x"];
        let r = Uint768::from_var_name("x", &vm, &ids_data, &ApTracking::default());
        assert_matches!(r, Err(HintError::IdentifierHasNoMember(x, y)) if x == "x" && y == "d2")
    }

    #[test]
    fn get_uint768_from_var_name_invalid_reference() {
        let mut vm = vm!();
        vm.segments = segments![((1, 0), 1), ((1, 1), 2), ((1, 2), 3)];
        let ids_data = ids_data!["x"];
        let r = Uint768::from_var_name("x", &vm, &ids_data, &ApTracking::default());
        assert_matches!(r, Err(HintError::UnknownIdentifier(x)) if x == "x")
    }
}
