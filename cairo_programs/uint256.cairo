%builtins range_check

from starkware.cairo.common.uint256 import (Uint256, uint256_add, split_64, uint256_sqrt, uint256_signed_nn, uint256_unsigned_div_rem)

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
    
    let (root) = uint256_sqrt(Uint256(17,7))
    assert root = Uint256(48805497317890012913,0)

    let (signed_nn) = uint256_signed_nn(Uint256(5,2))
    assert signed_nn = 1
    let (p) = uint256_signed_nn(Uint256(1,170141183460469231731687303715884105728))
    assert p = 0
    let (q) = uint256_signed_nn(Uint256(1,170141183460469231731687303715884105727))
    assert q = 1

    let (a_quotient, a_remainder) = uint256_unsigned_div_rem(Uint256(89,72), Uint256(3,7))
    assert a_quotient = Uint256(10,0)
    assert a_remainder = Uint256(59,2)

    let (b_quotient, b_remainder) = uint256_unsigned_div_rem(Uint256(-3618502788666131213697322783095070105282824848410658236509717448704103809099,2), Uint256(5,2))
    assert b_quotient = Uint256(1,0)
    assert b_remainder = Uint256(340282366920938463463374607431768211377,0)
    
    return()
end
