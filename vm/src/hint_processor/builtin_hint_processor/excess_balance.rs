use crate::{
    hint_processor::hint_processor_definition::HintReference,
    serde::deserialize_program::ApTracking,
    stdlib::collections::HashMap,
    vm::{errors::hint_errors::HintError, vm_core::VirtualMachine},
};
use core::{cmp::max, str::FromStr};

use num_bigint::BigUint;
use num_traits::{Pow, Zero};
use rust_decimal::{Decimal, MathematicalOps};
use starknet_types_core::felt::Felt as Felt252;

use crate::{
    math_utils::{isqrt, signed_felt},
    types::relocatable::Relocatable,
    vm::{errors::vm_errors::VirtualMachineError, vm_memory::memory::Memory},
};
use lazy_static::lazy_static;

use super::{dict_manager::DictManager, hint_utils::get_ptr_from_var_name};

#[derive(Debug, PartialEq, Eq, Hash)]
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
    fn read_from_memory(
        memory: &Memory,
        read_ptr: Relocatable,
    ) -> Result<Self, VirtualMachineError> {
        Ok(Position {
            market: core::str::from_utf8(&memory.get_integer(read_ptr)?.to_bytes_be())
                .unwrap_or_default()
                .trim_start_matches("\0")
                .to_string(),
            amount: felt_to_scaled_decimal(memory.get_integer((read_ptr + 1)?)?.as_ref()),
            cost: felt_to_scaled_decimal(memory.get_integer((read_ptr + 2)?)?.as_ref()),
            cached_funding: felt_to_scaled_decimal(memory.get_integer((read_ptr + 3)?)?.as_ref()),
        })
    }
}

impl MarginParams {
    fn read_from_memory(
        memory: &Memory,
        read_ptr: Relocatable,
    ) -> Result<Self, VirtualMachineError> {
        Ok(MarginParams {
            market: felt_to_trimmed_str(memory.get_integer(read_ptr)?.as_ref()),
            imf_base: felt_to_scaled_decimal(memory.get_integer((read_ptr + 4)?)?.as_ref()),
            imf_factor: felt_to_scaled_decimal(memory.get_integer((read_ptr + 5)?)?.as_ref()),
            mmf_factor: felt_to_scaled_decimal(memory.get_integer((read_ptr + 6)?)?.as_ref()),
            imf_shift: felt_to_scaled_decimal(memory.get_integer((read_ptr + 7)?)?.as_ref()),
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

    fn mmf(self, abs_value: Decimal) -> Decimal {
        self.mmf_factor * self.imf(abs_value)
    }
}

fn felt_to_scaled_decimal(f: &Felt252) -> Decimal {
    let mut d = Decimal::from_str_radix(&signed_felt(*f).to_string(), 10).unwrap_or_default();
    d.rescale(8);
    d
}

fn felt_to_trimmed_str(f: &Felt252) -> String {
    core::str::from_utf8(&f.to_bytes_be())
        .unwrap_or_default()
        .trim_start_matches("\0")
        .to_string()
}

fn excess_balance_func(
    vm: &VirtualMachine,
    dict_manager: DictManager,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<(), HintError> {
    // Fetch dictionaries from memory
    let prices_cache_ptr = get_ptr_from_var_name("prices_cache_ptr", vm, ids_data, ap_tracking)?;
    let indices_cache_ptr = get_ptr_from_var_name("indices_cache_ptr", vm, ids_data, ap_tracking)?;
    let perps_cache_ptr = get_ptr_from_var_name("perps_cache_ptr", vm, ids_data, ap_tracking)?;
    let fees_cache_ptr = get_ptr_from_var_name("fees_cache_ptr", vm, ids_data, ap_tracking)?;
    let balances_cache_ptr =
        get_ptr_from_var_name("balances_cache_ptr", vm, ids_data, ap_tracking)?;

    let prices = dict_manager
        .get_tracker(prices_cache_ptr)?
        .get_dictionary_ref();
    let indices = dict_manager
        .get_tracker(indices_cache_ptr)?
        .get_dictionary_ref();
    let perps = dict_manager
        .get_tracker(perps_cache_ptr)?
        .get_dictionary_ref();
    let fees = dict_manager
        .get_tracker(fees_cache_ptr)?
        .get_dictionary_ref();
    let balances = dict_manager
        .get_tracker(balances_cache_ptr)?
        .get_dictionary_ref();

    // Convert dictionaries to the representation used by the this algorithm
    let prices: HashMap<String, Decimal> = prices
        .iter()
        .map(|(k, v)| {
            (k.get_int_ref()
                .zip(v.get_int_ref())
                .map(|(k, v)| (felt_to_trimmed_str(k), felt_to_scaled_decimal(v))))
        })
        .collect::<Option<_>>()
        .ok_or_else(|| HintError::ExcessBalanceUnexpectedTypeInDict("prices".into()))?;

    let indices: HashMap<String, Decimal> = indices
        .iter()
        .map(|(k, v)| {
            (k.get_int_ref()
                .zip(v.get_int_ref())
                .map(|(k, v)| (felt_to_trimmed_str(k), felt_to_scaled_decimal(v))))
        })
        .collect::<Option<_>>()
        .ok_or_else(|| HintError::ExcessBalanceUnexpectedTypeInDict("indices".into()))?;

    let perps: HashMap<String, MarginParams> = perps
        .iter()
        .map(|(k, v)| {
            (k.get_int_ref().zip(v.get_relocatable()).and_then(|(k, v)| {
                MarginParams::read_from_memory(&vm.segments.memory, v)
                    .ok()
                    .map(|v| (felt_to_trimmed_str(k), v))
            }))
        })
        .collect::<Option<_>>()
        .ok_or_else(|| HintError::ExcessBalanceUnexpectedTypeInDict("fees".into()))?;

    let fees: HashMap<Decimal, Decimal> = fees
        .iter()
        .map(|(k, v)| {
            (k.get_int_ref()
                .zip(v.get_int_ref())
                .map(|(k, v)| (felt_to_scaled_decimal(k), felt_to_scaled_decimal(v))))
        })
        .collect::<Option<_>>()
        .ok_or_else(|| HintError::ExcessBalanceUnexpectedTypeInDict("fees".into()))?;

    let balances: HashMap<Position, Position> = balances
        .iter()
        .map(|(k, v)| {
            (k.get_relocatable()
                .zip(v.get_relocatable())
                .and_then(|(k, v)| {
                    Position::read_from_memory(&vm.segments.memory, k)
                        .ok()
                        .zip(Position::read_from_memory(&vm.segments.memory, v).ok())
                }))
        })
        .collect::<Option<_>>()
        .ok_or_else(|| HintError::ExcessBalanceUnexpectedTypeInDict("balances".into()))?;

    // Fetch settelement price
    let settlement_asset = String::from("USDC-USD");
    let settlement_price = prices[&settlement_asset];

    Ok(())
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
            cached_funding: Decimal::from_scientific("0e-8").unwrap(),
        };
        assert_eq!(
            expected_position,
            Position::read_from_memory(&memory, (0, 0).into()).unwrap()
        )
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
            imf_shift: Decimal::from_str("200000.00000000").unwrap(),
        };
        assert_eq!(
            expected_position,
            MarginParams::read_from_memory(&memory, (0, 0).into()).unwrap()
        )
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
