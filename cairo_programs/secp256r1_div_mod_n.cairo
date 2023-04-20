%builtins range_check

// Sources: https://github.com/myBraavos/efficient-secp256r1/blob/main/src/secp256r1/signature.cairo#L48
// Sources: https://github.com/myBraavos/efficient-secp256r1/blob/main/src/secp256r1/ec.cairo#L32

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.bitwise import bitwise_and
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.cairo_secp.bigint import (
    BASE,
    BigInt3,
    UnreducedBigInt3,
    bigint_mul,
    nondet_bigint3,
)
from starkware.cairo.common.cairo_secp.ec import EcPoint
from starkware.cairo.common.math import assert_nn, assert_nn_le, assert_not_zero, unsigned_div_rem
from starkware.cairo.common.math_cmp import RC_BOUND
from starkware.cairo.common.uint256 import Uint256

func div_mod_n{range_check_ptr}(a: BigInt3, b: BigInt3) -> (res: BigInt3) {
    %{ from starkware.cairo.common.cairo_secp.secp256r1_utils import SECP256R1_N as N %}
    %{
        from starkware.cairo.common.cairo_secp.secp_utils import pack
        from starkware.python.math_utils import div_mod, safe_div

        a = pack(ids.a, PRIME)
        b = pack(ids.b, PRIME)
        value = res = div_mod(a, b, N)
    %}
    let (res) = nondet_bigint3();

    return (res=res);
}

func main{range_check_ptr}(){
    let x = BigInt3(235, 522, 111);
    let y = BigInt3(1323, 15124, 796759);

    let a = div_mod_n(x, y);
    assert a = a;
    return ();

}
