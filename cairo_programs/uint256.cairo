%builtins range_check

from starkware.cairo.common.uint256 import (uint256_add, Uint256)

func main{range_check_ptr: felt}():
    let x :Uint256 = Uint256(5,2)
    let y = Uint256(3,7)
    let (res, carry_high) = uint256_add(x,y)
    assert res.low = 8
    assert res.high = 9
    assert carry_high = 0
    return()
end