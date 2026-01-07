%builtins range_check

from starkware.cairo.common.secp256r1.field import assert_165_bit

func main{range_check_ptr: felt}() {
    let value = 10;
    assert_165_bit(value);
    return ();
}
