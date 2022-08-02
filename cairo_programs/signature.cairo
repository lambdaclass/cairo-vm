%builtins range_check

from starkware.cairo.common.cairo_secp.signature import div_mod_n
from starkware.cairo.common.cairo_secp.bigint import BigInt3

func main{range_check_ptr: felt} ():
    let a: BigInt3 = BigInt3(100,99,98)
    let b: BigInt3 = BigInt3(10,9,8)
    let (res) = div_mod_n(a, b)
    assert res.d0 = 3413472211745629263979533
    assert res.d1 = 17305268010345238170172332
    assert res.d2 = 11991751872105858217578135
    return()
end
