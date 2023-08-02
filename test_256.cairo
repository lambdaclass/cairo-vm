%builtins output range_check

from starkware.cairo.common.uint256 import (
    Uint256,
    uint256_mul_div_mod
)
from starkware.cairo.common.serialize import serialize_word

func main{output_ptr: felt*, range_check_ptr: felt}() {
    let (c_quotient_low, c_quotient_high, c_remainder) = uint256_mul_div_mod(
        Uint256(340281070833283907490476236129005105804, 340282366920938463463374607431768311459),
        Uint256(2447157533618445569039523, 2),
        Uint256(1, 0),
    );

    serialize_word(c_quotient_low.low);
    serialize_word(c_quotient_low.high);
    serialize_word(c_quotient_high.low);
    serialize_word(c_quotient_high.high);
    serialize_word(c_remainder.low);
    serialize_word(c_remainder.high);

    return ();
}
