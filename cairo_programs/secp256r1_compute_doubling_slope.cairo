%builtins range_check

// Source: https://github.com/myBraavos/efficient-secp256r1/blob/main/src/secp256r1/ec.cairo#L32

func compute_doubling_slope{range_check_ptr}(point: EcPoint) -> (slope: BigInt3) {
    // Note that y cannot be zero: assume that it is, then point = -point, so 2 * point = 0, which
    // contradicts the fact that the size of the curve is odd.
    %{  from starkware.cairo.common.cairo_secp.secp256r1_utils import SECP256R1_P as SECP_P %}
    %{  from starkware.cairo.common.cairo_secp.secp256r1_utils import SECP256R1_ALPHA as ALPHA %}
    // Hint #19
    %{
        from starkware.cairo.common.cairo_secp.secp_utils import pack
        from starkware.python.math_utils import ec_double_slope

        # Compute the slope.
        x = pack(ids.point.x, PRIME)
        y = pack(ids.point.y, PRIME)
        value = slope = ec_double_slope(point=(x, y), alpha=ALPHA, p=SECP_P)
    %}
    let (slope: BigInt3) = nondet_bigint3();

    let (x_sqr: UnreducedBigInt3) = unreduced_sqr(point.x);
    let (slope_y: UnreducedBigInt3) = unreduced_mul(slope, point.y);
    verify_zero(
        UnreducedBigInt3(
            d0=3 * x_sqr.d0 + A0 - 2 * slope_y.d0,
            d1=3 * x_sqr.d1 + A1 - 2 * slope_y.d1,
            d2=3 * x_sqr.d2 + A2 - 2 * slope_y.d2,
        ),
    );

    return (slope=slope);
}
