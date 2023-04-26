%builtins range_check
from starkware.cairo.common.cairo_secp.bigint import BigInt3, nondet_bigint3, UnreducedBigInt3
from starkware.cairo.common.cairo_secp.field import (
    is_zero,
    unreduced_sqr,
    unreduced_mul
)
from starkware.cairo.common.cairo_secp.ec import EcPoint, compute_doubling_slope, verify_zero

// Computes the addition of a given point to itself.
//
// Arguments:
//   point - the point to operate on.
//
// Returns:
//   res - a point representing point + point.
func ec_double{range_check_ptr}(point: EcPoint) -> (res: EcPoint) {
    // The zero point.
    if (point.x.d0 == 0) {
        if (point.x.d1 == 0) {
            if (point.x.d2 == 0) {
                return (res=point);
            }
        }
    }

    let (slope: BigInt3) = compute_doubling_slope(point);
    let (slope_sqr: UnreducedBigInt3) = unreduced_sqr(slope);

    %{
        from starkware.cairo.common.cairo_secp.secp_utils import pack
        SECP_P = 2**255-19

        slope = pack(ids.slope, PRIME)
        x = pack(ids.point.x, PRIME)
        y = pack(ids.point.y, PRIME)

        value = new_x = (pow(slope, 2, SECP_P) - 2 * x) % SECP_P
    %}

    let (new_x: BigInt3) = nondet_bigint3();

    %{ value = new_y = (slope * (x - new_x) - y) % SECP_P %}
    let (new_y: BigInt3) = nondet_bigint3();

    verify_zero(
        UnreducedBigInt3(
            d0=slope_sqr.d0 - new_x.d0 - 2 * point.x.d0,
            d1=slope_sqr.d1 - new_x.d1 - 2 * point.x.d1,
            d2=slope_sqr.d2 - new_x.d2 - 2 * point.x.d2,
        ),
    );

    let (x_diff_slope: UnreducedBigInt3) = unreduced_mul(
        BigInt3(d0=point.x.d0 - new_x.d0, d1=point.x.d1 - new_x.d1, d2=point.x.d2 - new_x.d2), slope
    );

    verify_zero(
        UnreducedBigInt3(
            d0=x_diff_slope.d0 - point.y.d0 - new_y.d0,
            d1=x_diff_slope.d1 - point.y.d1 - new_y.d1,
            d2=x_diff_slope.d2 - point.y.d2 - new_y.d2,
        ),
    );

    return (res=EcPoint(new_x, new_y));
}

func main{range_check_ptr}() {
    let x = BigInt3(1,2,3);
    let y = BigInt3(4,5,6);
    let p = EcPoint(x, y);

    let (r) = ec_double(p);

    assert r.x.d0 = 57832968898037685942927716;
    assert r.x.d1 = 27957507593122495312333579;
    assert r.x.d2 = 876486538158111111042155;

    assert r.y.d0 = 76653617457582133477854326;
    assert r.y.d1 = 906421522066442687720656;
    assert r.y.d2 = 11165193544924531831122323;

    return ();
}
