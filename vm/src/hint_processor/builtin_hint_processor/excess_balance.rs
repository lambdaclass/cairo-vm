use rust_decimal::Decimal;
use starknet_types_core::felt::Felt as Felt252;
use num_traits::Pow;

use crate::{math_utils::signed_felt, types::relocatable::Relocatable, vm::{errors::vm_errors::VirtualMachineError, vm_memory::memory::Memory}};

#[derive(Default, Debug, PartialEq)]
struct Position {
    market: String,
    amount: Decimal,
    cost: Decimal,
    cached_funding: Decimal,
}

impl Position {
    fn read_from_memory(memory: &Memory, read_ptr: Relocatable) -> Result<Self, VirtualMachineError> {
        let felt_to_scaled_decimal = |f: Felt252| -> Decimal {
            let d = Decimal::from_str_radix(&signed_felt(f).to_string(), 10).unwrap();
            d * Decimal::from(10).pow(-8_i64)
        };
        Ok(Position {
            market: core::str::from_utf8(&memory.get_integer(read_ptr)?.to_bytes_be()).unwrap().trim_start_matches("\0").to_string(),
            amount: felt_to_scaled_decimal(memory.get_integer((read_ptr + 1)?)?.into_owned()),
            cost: felt_to_scaled_decimal(memory.get_integer((read_ptr + 2)?)?.into_owned()),
            cached_funding: felt_to_scaled_decimal(memory.get_integer((read_ptr + 3)?)?.into_owned()),
        })
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;
    use crate::utils::test_utils::*;

    #[test]
    fn test_read_position() {
        let memory = memory![
           ((0, 0), ("5176525270854594879110454268496", 10)),
           ((0, 1), 1000000000),
           ((0, 2), 20000),
           ((0, 3), 0)
        ];
        let expected_position = Position {
            market: String::from("AVAX-USD-PERP"),
            amount: Decimal::from_str("10.00000000").unwrap(),
            cost: Decimal::from_str("0.00020000").unwrap(),
            cached_funding: Decimal::from_scientific("0e-8").unwrap()
        };
        assert_eq!(expected_position, Position::read_from_memory(&memory, (0, 0).into()).unwrap())
    }
}

