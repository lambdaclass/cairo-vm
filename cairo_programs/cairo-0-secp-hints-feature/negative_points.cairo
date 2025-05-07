%builtins range_check

from starkware.cairo.common.secp256r1.ec import (
    EcPoint,
)
from starkware.cairo.common.secp256r1.bigint import nondet_bigint3
from starkware.cairo.common.cairo_secp.bigint3 import BigInt3

func main{range_check_ptr: felt}() {
    let point = EcPoint(
        BigInt3(1, 2, 3),
        BigInt3(-1, -2, -3),
    );

    let slope = compute_doubling_slope_prime(point);
    assert slope = BigInt3(
        15487438216801236710343013, 27596288489803578791625491, 8178446608657045587339469
    );

    let slope = compute_doubling_slope_secp256r1(point);
    assert slope = BigInt3(
        56511396263956479754791421, 38561311687768998103117219, 2015104701319196654781984
    );

    return ();
}

func compute_doubling_slope_prime{range_check_ptr}(point: EcPoint) -> BigInt3 {
    %{
        from starkware.cairo.common.cairo_secp.secp256r1_utils import SECP256R1_ALPHA, SECP256R1_P
        from starkware.cairo.common.cairo_secp.secp_utils import pack
        from starkware.python.math_utils import ec_double_slope

        # Compute the slope.
        x = pack(ids.point.x, PRIME)
        y = pack(ids.point.y, PRIME)
        value = slope = ec_double_slope(point=(x, y), alpha=SECP256R1_ALPHA, p=SECP256R1_P)
    %}
    let (slope: BigInt3) = nondet_bigint3();
    return slope;
}

func compute_doubling_slope_secp256r1{range_check_ptr}(point: EcPoint) -> BigInt3 {
    %{
        from starkware.cairo.common.cairo_secp.secp256r1_utils import SECP256R1_ALPHA, SECP256R1_P
        from starkware.cairo.common.cairo_secp.secp_utils import pack
        from starkware.python.math_utils import ec_double_slope

        # Compute the slope.
        x = pack(ids.point.x, SECP256R1_P)
        y = pack(ids.point.y, SECP256R1_P)
        value = slope = ec_double_slope(point=(x, y), alpha=SECP256R1_ALPHA, p=SECP256R1_P)
    %}
    let (slope: BigInt3) = nondet_bigint3();
    return slope;
}
