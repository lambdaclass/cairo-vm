use crate::{
    hint_processor::hint_processor_definition::HintReference,
    serde::deserialize_program::ApTracking,
    stdlib::collections::HashMap,
    types::{
        exec_scope::{self, ExecutionScopes},
        relocatable::MaybeRelocatable,
    },
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

use super::{
    dict_manager::DictManager,
    hint_utils::{
        get_constant_from_var_name, get_integer_from_var_name, get_ptr_from_var_name,
        insert_value_from_var_name,
    },
};

// General helper functions

fn felt_to_scaled_decimal(f: &Felt252) -> Option<Decimal> {
    let mut d = Decimal::from_str_radix(&signed_felt(*f).to_string(), 10).ok()?;
    d.set_scale(8).ok();
    Some(d)
}

fn felt_to_trimmed_str(f: &Felt252) -> Option<String> {
    Some(
        core::str::from_utf8(&f.to_bytes_be())
            .ok()?
            .trim_start_matches('\0')
            .to_string(),
    )
}

// Internal Data types

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
    fn read_from_memory(memory: &Memory, read_ptr: Relocatable) -> Option<Self> {
        Some(Position {
            market: felt_to_trimmed_str(memory.get_integer(read_ptr).ok()?.as_ref())?,
            amount: felt_to_scaled_decimal(
                memory.get_integer((read_ptr + 1_u32).ok()?).ok()?.as_ref(),
            )?,
            cost: felt_to_scaled_decimal(
                memory.get_integer((read_ptr + 2_u32).ok()?).ok()?.as_ref(),
            )?,
            cached_funding: felt_to_scaled_decimal(
                memory.get_integer((read_ptr + 3_u32).ok()?).ok()?.as_ref(),
            )?,
        })
    }
}

impl MarginParams {
    fn read_from_memory(memory: &Memory, read_ptr: Relocatable) -> Option<Self> {
        Some(MarginParams {
            market: felt_to_trimmed_str(memory.get_integer(read_ptr).ok()?.as_ref())?,
            imf_base: felt_to_scaled_decimal(
                memory.get_integer((read_ptr + 4_u32).ok()?).ok()?.as_ref(),
            )?,
            imf_factor: felt_to_scaled_decimal(
                memory.get_integer((read_ptr + 5_u32).ok()?).ok()?.as_ref(),
            )?,
            mmf_factor: felt_to_scaled_decimal(
                memory.get_integer((read_ptr + 6_u32).ok()?).ok()?.as_ref(),
            )?,
            imf_shift: felt_to_scaled_decimal(
                memory.get_integer((read_ptr + 7_u32).ok()?).ok()?.as_ref(),
            )?,
        })
    }

    fn imf(&self, abs_value: Decimal) -> Option<Decimal> {
        let mut diff = (abs_value - self.imf_shift);
        diff.set_scale(8).ok()?;
        let max = BigUint::from_str(&Decimal::ZERO.max(diff.trunc()).to_string()).ok()?;
        let part_sqrt = isqrt(&max).ok()?;
        let mut part_sqrt = Decimal::from_str(&part_sqrt.to_string()).ok()?;
        part_sqrt.set_scale(4).ok()?;
        Some(self.imf_base.max(self.imf_factor * part_sqrt))
    }

    fn mmf(&self, abs_value: Decimal) -> Option<Decimal> {
        Some(self.mmf_factor * self.imf(abs_value)?)
    }
}

// Excess Balance helpers

fn dict_ref_from_var_name<'a>(
    var_name: &'a str,
    vm: &'a VirtualMachine,
    dict_manager: &'a DictManager,
    ids_data: &'a HashMap<String, HintReference>,
    ap_tracking: &'a ApTracking,
) -> Option<&'a HashMap<MaybeRelocatable, MaybeRelocatable>> {
    let prices_cache_ptr = get_ptr_from_var_name(var_name, vm, ids_data, ap_tracking).ok()?;
    Some(
        dict_manager
            .get_tracker(prices_cache_ptr)
            .ok()?
            .get_dictionary_ref(),
    )
}

fn prices_dict(
    vm: &VirtualMachine,
    dict_manager: &DictManager,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Option<HashMap<String, Decimal>> {
    // Fetch dictionary
    let prices = dict_ref_from_var_name("prices_dict", vm, dict_manager, ids_data, ap_tracking)?;

    // Apply data type conversions
    let apply_conversion =
        |k: &MaybeRelocatable, v: &MaybeRelocatable| -> Option<(String, Decimal)> {
            Some((
                felt_to_trimmed_str(k.get_int_ref()?)?,
                felt_to_scaled_decimal(v.get_int_ref()?)?,
            ))
        };

    prices
        .iter()
        .map(|(k, v)| apply_conversion(k, v))
        .collect::<Option<_>>()
}

fn indices_dict(
    vm: &VirtualMachine,
    dict_manager: &DictManager,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Option<HashMap<String, Decimal>> {
    // Fetch dictionary
    let indices = dict_ref_from_var_name("indices_dict", vm, dict_manager, ids_data, ap_tracking)?;

    // Apply data type conversions
    let apply_conversion =
        |k: &MaybeRelocatable, v: &MaybeRelocatable| -> Option<(String, Decimal)> {
            Some((
                felt_to_trimmed_str(k.get_int_ref()?)?,
                felt_to_scaled_decimal(v.get_int_ref()?)?,
            ))
        };

    indices
        .iter()
        .map(|(k, v)| apply_conversion(k, v))
        .collect::<Option<_>>()
}

fn perps_dict(
    vm: &VirtualMachine,
    dict_manager: &DictManager,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Option<HashMap<String, MarginParams>> {
    // Fetch dictionary
    let perps = dict_ref_from_var_name("perps_cache_ptr", vm, dict_manager, ids_data, ap_tracking)?;

    // Apply data type conversions
    let apply_conversion =
        |k: &MaybeRelocatable, v: &MaybeRelocatable| -> Option<(String, MarginParams)> {
            Some((
                felt_to_trimmed_str(k.get_int_ref()?)?,
                MarginParams::read_from_memory(&vm.segments.memory, v.get_relocatable()?)?,
            ))
        };

    perps
        .iter()
        .map(|(k, v)| apply_conversion(k, v))
        .collect::<Option<_>>()
}

fn fees_dict(
    vm: &VirtualMachine,
    dict_manager: &DictManager,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Option<HashMap<Felt252, Decimal>> {
    // Fetch dictionary
    let fees = dict_ref_from_var_name("fees_dict", vm, dict_manager, ids_data, ap_tracking)?;

    // Apply data type conversions
    let apply_conversion =
        |k: &MaybeRelocatable, v: &MaybeRelocatable| -> Option<(Felt252, Decimal)> {
            Some((k.get_int()?, felt_to_scaled_decimal(v.get_int_ref()?)?))
        };

    fees.iter()
        .map(|(k, v)| apply_conversion(k, v))
        .collect::<Option<_>>()
}

fn balances_list(
    vm: &VirtualMachine,
    dict_manager: &DictManager,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Option<Vec<Position>> {
    // Fetch dictionary
    let balances =
        dict_ref_from_var_name("balances_dict", vm, dict_manager, ids_data, ap_tracking)?;

    // Apply data type conversions
    let apply_conversion = |k: &MaybeRelocatable, v: &MaybeRelocatable| -> Option<Position> {
        Position::read_from_memory(&vm.segments.memory, v.get_relocatable()?)
    };

    balances
        .iter()
        .map(|(k, v)| apply_conversion(k, v))
        .collect::<Option<_>>()
}

fn excess_balance_func(
    vm: &mut VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
    constants: &HashMap<String, Felt252>,
    exec_scopes: &ExecutionScopes,
) -> Result<(), HintError> {
    // Fetch constants & variables
    let margin_check_type =
        get_integer_from_var_name("margin_check_type", vm, ids_data, ap_tracking)?;
    let margin_check_initial = get_constant_from_var_name("MARGIN_CHECK_INITIAL", constants)?;
    let token_assets_value_d =
        get_integer_from_var_name("token_assets_value_d", vm, ids_data, ap_tracking)?;
    let account = get_integer_from_var_name("account", vm, ids_data, ap_tracking)?;
    // Fetch DictManager
    let dict_manager_rc = exec_scopes.get_dict_manager()?;
    let dict_manager = dict_manager_rc.borrow();
    // Fetch dictionaries
    let prices = prices_dict(vm, &dict_manager, ids_data, ap_tracking)
        .ok_or_else(|| HintError::ExcessBalanceFailedToFecthDict("prices".into()))?;
    let indices = indices_dict(vm, &dict_manager, ids_data, ap_tracking)
        .ok_or_else(|| HintError::ExcessBalanceFailedToFecthDict("indices".into()))?;
    let perps = perps_dict(vm, &dict_manager, ids_data, ap_tracking)
        .ok_or_else(|| HintError::ExcessBalanceFailedToFecthDict("perps".into()))?;
    let fees = fees_dict(vm, &dict_manager, ids_data, ap_tracking)
        .ok_or_else(|| HintError::ExcessBalanceFailedToFecthDict("fees".into()))?;
    let balances = balances_list(vm, &dict_manager, ids_data, ap_tracking)
        .ok_or_else(|| HintError::ExcessBalanceFailedToFecthDict("balances".into()))?;

    // Fetch settelement price
    let settlement_asset = String::from("USDC-USD");
    let settlement_price = prices.get(&settlement_asset).ok_or_else(|| HintError::ExcessBalanceKeyError("prices".into()))?;

    let mut unrealized_pnl = Decimal::ZERO;
    let mut unrealized_funding_pnl = Decimal::ZERO;
    let mut abs_balance_value = Decimal::ZERO;
    let mut position_margin = Decimal::ZERO;

    for position in balances {
        if position.market == settlement_asset {
            continue;
        }

        let price = prices
            .get(&position.market)
            .ok_or_else(|| HintError::ExcessBalanceKeyError("prices".into()))?;
        let funding_index = indices
            .get(&position.market)
            .ok_or_else(|| HintError::ExcessBalanceKeyError("indices".into()))?;
        let position_value = position.amount * price;
        let position_value_abs = position_value.abs();
        abs_balance_value += position_value_abs;

        let market_perps = perps
            .get(&position.market)
            .ok_or_else(|| HintError::ExcessBalanceKeyError("perps".into()))?;
        let margin_fraction = if &margin_check_type == margin_check_initial {
            market_perps.imf(position_value_abs)
        } else {
            market_perps.mmf(position_value_abs)
        }
        .ok_or_else(|| HintError::ExcessBalanceCalculationFailed("margin_fraction".into()))?;

        position_margin += margin_fraction * position_value_abs;
        unrealized_pnl += position_value - position.cost * settlement_price;
        unrealized_funding_pnl +=
            (position.cached_funding - funding_index) * position.amount * settlement_price;
    }

    // Calculate final results
    let account_value = unrealized_pnl
        + unrealized_funding_pnl
        + felt_to_scaled_decimal(&token_assets_value_d)
            .ok_or_else(|| HintError::ExcessBalanceCalculationFailed("account_value".into()))?;
    let fee_provision = abs_balance_value
        * fees
            .get(&account)
            .ok_or_else(|| HintError::ExcessBalanceKeyError("fees".into()))?;
    let margin_requirement = position_margin + fee_provision;
    let excess_balance = account_value - margin_requirement;

    let felt_from_decimal = |d: Decimal| -> Felt252 {
        let mut d = d;
        d.set_scale(8);
        // This shouldn't fail
        Felt252::from_dec_str(&d.trunc().to_string()).unwrap_or_default()
    };

    // Write results into memory
    insert_value_from_var_name(
        "check_account_value",
        felt_from_decimal(account_value),
        vm,
        ids_data,
        ap_tracking,
    )?;
    insert_value_from_var_name(
        "check_excess_balance",
        felt_from_decimal(excess_balance),
        vm,
        ids_data,
        ap_tracking,
    )?;
    insert_value_from_var_name(
        "check_margin_requirement_d",
        felt_from_decimal(margin_requirement),
        vm,
        ids_data,
        ap_tracking,
    )?;
    insert_value_from_var_name(
        "check_unrealized_pnl_d",
        felt_from_decimal(unrealized_pnl),
        vm,
        ids_data,
        ap_tracking,
    )
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
        assert_eq!(expected_res, margin_params.imf(abs_value).unwrap());
    }
}
