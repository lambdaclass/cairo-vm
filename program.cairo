%builtins range_check

from starkware.cairo.common.cairo_secp.bigint3 import BigInt3
from starkware.cairo.common.secp256r1.ec import (
     EcPoint,
     compute_doubling_slope,
)

func main{range_check_ptr: felt}() {
    let test_point = EcPoint(
        BigInt3(-1, -5, -10),
        BigInt3(2, 4, 20)
    );

    let (slope_k) = compute_doubling_slope(test_point);
    return ();
}
