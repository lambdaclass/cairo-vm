from starkware.cairo.common.uint256 import Uint256

func main () {
    let a = Uint256(low=2, high=1);
    let b = Uint256(low=3, high=4);
    let div = Uint256(low=3, high=4);
    hint_func(a, b, div);
    return ();
}

func hint_func(a: Uint256, b: Uint256, div: Uint256) -> (Uint256, Uint256, Uint256){
    alloc_locals;
    local quotient_low: Uint256;
    local quotient_high: Uint256;
    local remainder: Uint256;

    %{
        a = (ids.a.high << 128) + ids.a.low
        b = (ids.b.high << 128) + ids.b.low
        div = (ids.div.high << 128) + ids.div.low
        quotient, remainder = divmod(a * b, div)

        ids.quotient_low.low = quotient & ((1 << 128) - 1)
        ids.quotient_low.high = (quotient >> 128) & ((1 << 128) - 1)
        ids.quotient_high.low = (quotient >> 256) & ((1 << 128) - 1)
        ids.quotient_high.high = quotient >> 384
        ids.remainder.low = remainder & ((1 << 128) - 1)
        ids.remainder.high = (remainder >> 128) + 1
    %}
    return (quotient_low, quotient_high, remainder);
}
