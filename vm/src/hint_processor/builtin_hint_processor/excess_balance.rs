use core::{cmp::max, str::FromStr};

use num_bigint::BigUint;
use rust_decimal::{Decimal, MathematicalOps};
use starknet_types_core::felt::Felt as Felt252;
use num_traits::{Pow, Zero};

use crate::{math_utils::{isqrt, signed_felt}, types::relocatable::Relocatable, vm::{errors::vm_errors::VirtualMachineError, vm_memory::memory::Memory}};
use lazy_static::lazy_static;

#[derive(Debug, PartialEq)]
struct Position {
    market: String,
    amount: Decimal,
    cost: Decimal,
    cached_funding: Decimal,
}

#[derive(Debug, PartialEq)]
struct MarginParams {
    market: String,
    imf_base: Decimal,
    imf_factor: Decimal,
    mmf_factor: Decimal,
    imf_shift: Decimal,
}

impl Position {
    fn read_from_memory(memory: &Memory, read_ptr: Relocatable) -> Result<Self, VirtualMachineError> {
        let felt_to_scaled_decimal = |f: Felt252| -> Decimal {
            let mut d = Decimal::from_str_radix(&signed_felt(f).to_string(), 10).unwrap();
            d.set_scale(8);
            d
        };
        Ok(Position {
            market: core::str::from_utf8(&memory.get_integer(read_ptr)?.to_bytes_be()).unwrap_or_default().trim_start_matches("\0").to_string(),
            amount: felt_to_scaled_decimal(memory.get_integer((read_ptr + 1)?)?.into_owned()),
            cost: felt_to_scaled_decimal(memory.get_integer((read_ptr + 2)?)?.into_owned()),
            cached_funding: felt_to_scaled_decimal(memory.get_integer((read_ptr + 3)?)?.into_owned()),
        })
    }
}

impl MarginParams {
    fn read_from_memory(memory: &Memory, read_ptr: Relocatable) -> Result<Self, VirtualMachineError> {
        let felt_to_scaled_decimal = |f: Felt252| -> Decimal {
            let mut d = Decimal::from_str_radix(&signed_felt(f).to_string(), 10).unwrap_or_default();
            d.rescale(8);
            d
        };
        Ok(MarginParams {
            market: core::str::from_utf8(&memory.get_integer(read_ptr)?.to_bytes_be()).unwrap_or_default().trim_start_matches("\0").to_string(),
            imf_base: felt_to_scaled_decimal(memory.get_integer((read_ptr + 4)?)?.into_owned()),
            imf_factor: felt_to_scaled_decimal(memory.get_integer((read_ptr + 5)?)?.into_owned()),
            mmf_factor: felt_to_scaled_decimal(memory.get_integer((read_ptr + 6)?)?.into_owned()),
            imf_shift: felt_to_scaled_decimal(memory.get_integer((read_ptr + 7)?)?.into_owned()),
        })
    }

    fn imf(&self, abs_value: Decimal) -> Decimal {
        let mut diff = (abs_value - self.imf_shift).trunc_with_scale(8);
        diff.set_scale(8);
        diff = diff.trunc();
        let max = BigUint::from_str(&Decimal::ZERO.max(diff).to_string()).unwrap();
        let part_sqrt = isqrt(&max).unwrap();
        let mut part_sqrt = Decimal::from_str(&part_sqrt.to_string()).unwrap();
        part_sqrt.set_scale(4);
        self.imf_base.max(self.imf_factor * part_sqrt)
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

    #[test]
    fn test_read_margin_params() {
        let memory = memory![
           ((0, 0), ("20527877651862571847371805264", 10)),
           ((0, 4), 5000000),
           ((0, 5), 20000),
           ((0, 6), 50000000),
           ((0, 7), 20000000000000)
        ];
        let expected_position = MarginParams {
            market: String::from("BTC-USD-PERP"),
            imf_base: Decimal::from_str("0.05000000").unwrap(),
            imf_factor: Decimal::from_str("0.00020000").unwrap(),
            mmf_factor: Decimal::from_str("0.50000000").unwrap(),
            imf_shift: Decimal::from_str("200000.00000000").unwrap()
        };
        assert_eq!(expected_position, MarginParams::read_from_memory(&memory, (0, 0).into()).unwrap())
    }

    #[test]
    fn test_imf() {
        let abs_value = Decimal::from_str("459000.0000000000000000").unwrap();
        let margin_params = MarginParams {
            market: String::from("BTC-USD-PERP"),
            imf_base: Decimal::from_str("0.05000000").unwrap(),
            imf_factor: Decimal::from_str("0.00020000").unwrap(),
            mmf_factor: Decimal::from_str("0.50000000").unwrap(),
            imf_shift: Decimal::from_str("200000.00000000").unwrap(),
        };
        let expected_res = Decimal::from_str("0.101784080000").unwrap();
        assert_eq!(expected_res, margin_params.imf(abs_value));

    }
}

