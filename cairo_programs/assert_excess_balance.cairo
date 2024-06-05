%builtins range_check

from starkware.cairo.common.default_dict import default_dict_new, default_dict_finalize
from starkware.cairo.common.dict import dict_write
from starkware.cairo.common.dict_access import DictAccess


struct MarginParams {
    imf_base: felt,
    imf_factor: felt,
    mmf_factor: felt,
    imf_shift: felt,
}

struct Position {
    market: felt,
    amount: felt,
    cost: felt,
    cached_funding: felt,
}


func new_cache{range_check_ptr: felt}() -> DictAccess* {
    alloc_locals;
    let (local dict_ptr) = default_dict_new(default_value=0);
    default_dict_finalize(
      dict_accesses_start=dict_ptr,
      dict_accesses_end=dict_ptr,
      default_value=0,
    );
    return dict_ptr;
}

func write_to_cache{
    cache_dict_ptr: DictAccess*, range_check_ptr
}(key: felt, new_value: felt) {
    alloc_locals;
    dict_write{dict_ptr=cache_dict_ptr}(key=key, new_value=new_value);
    return ();
}

func main{range_check_ptr: felt}() {
    alloc_locals;

    let margin_check_type = 1;
    const MARGIN_CHECK_INITIAL = 1;
    let token_assets_value_d = 0;
    let account = 100;

    let prices_cache_ptr = new_cache();
    let indices_cache_ptr = new_cache();
    let perps_cache_ptr = new_cache();
    let perps_balances_cache_ptr = new_cache();
    let fees_cache_ptr = new_cache();

    // str to felt conversion
    // str_to_felt("USDC-USD") = 6148332971604923204
    // str_to_felt("BTC-USD-PERP") = 20527877651862571847371805264
    // str_to_felt("ETH-USD-PERP") = 21456356293159021401772216912
    // str_to_felt("SOL-USD-PERP") = 25783120691025710696626475600

    /////
    // store perp assets and balances to memory
    /////

    %{
        memory[123] = 456
    %}

    /////
    // store prices to cache
    /////
    
    write_to_cache{cache_dict_ptr=prices_cache_ptr}(6148332971604923204, 100000000);
    write_to_cache{cache_dict_ptr=prices_cache_ptr}(20527877651862571847371805264, 5100000000000);
    write_to_cache{cache_dict_ptr=prices_cache_ptr}(21456356293159021401772216912, 5100000000000);
    write_to_cache{cache_dict_ptr=prices_cache_ptr}(25783120691025710696626475600, 5100000000000);

    /////
    // store indices to cache
    /////

    write_to_cache{cache_dict_ptr=indices_cache_ptr}(20527877651862571847371805264, 0);
    write_to_cache{cache_dict_ptr=indices_cache_ptr}(21456356293159021401772216912, 0);
    write_to_cache{cache_dict_ptr=indices_cache_ptr}(25783120691025710696626475600, 0);

    /////
    // store perp assets to cache
    /////

    write_to_cache{cache_dict_ptr=perps_cache_ptr}(20527877651862571847371805264, RelocatableValue(segment_index=1, offset=4592));
    write_to_cache{cache_dict_ptr=perps_cache_ptr}(21456356293159021401772216912, RelocatableValue(segment_index=1, offset=4217));
    write_to_cache{cache_dict_ptr=perps_cache_ptr}(25783120691025710696626475600, RelocatableValue(segment_index=1, offset=3467));

    /////
    // store perp assets balances to cache
    /////

    write_to_cache{cache_dict_ptr=perps_balances_cache_ptr}(20527877651862571847371805264, RelocatableValue(segment_index=1, offset=18230));
    write_to_cache{cache_dict_ptr=perps_balances_cache_ptr}(21456356293159021401772216912, RelocatableValue(segment_index=1, offset=7063));
    write_to_cache{cache_dict_ptr=perps_balances_cache_ptr}(25783120691025710696626475600, RelocatableValue(segment_index=1, offset=6625));

    /////
    // store fee percentages to cache
    /////

    write_to_cache{cache_dict_ptr=fees_cache_ptr}(account, 10000);
    write_to_cache{cache_dict_ptr=fees_cache_ptr}(200, 10000);

    %{
        from excess_balance import excess_balance_func

        res = excess_balance_func(ids, memory, __dict_manager)

        ids.check_account_value = res["account_value"]
        ids.check_excess_balance = res["excess_balance"]
        ids.check_margin_requirement_d = res["margin_requirement"]
        ids.check_unrealized_pnl_d = res["unrealized_pnl"]
    %}
    return ();
}
