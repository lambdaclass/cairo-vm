%builtins range_check

from starkware.cairo.common.uint256 import (Uint256, uint256_add, split_64)

func main{range_check_ptr: felt}():
    let x :Uint256 = Uint256(5,2)
    let y = Uint256(3,7)
    let (res, carry_high) = uint256_add(x,y)
    assert res.low = 8
    assert res.high = 9
    assert carry_high = 0

    let (low, high) = split_64(850981239023189021389081239089023)
    assert low = 7249717543555297151
    assert high = 46131785404667
    return()
end
