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

    let x = BigInt3(-1,-2,-3);
    let y = try_get_point_from_x_prime(x, 0);
    assert y = BigInt3(
        39197606747300743094893670, 38008389934708701866119639, 2071781356858789560884686
    );

    let x = BigInt3(-1,-2,-3);
    let y = try_get_point_from_x_secp256r1(x, 0);
    assert y = BigInt3(
        56004882917990234964232380, 17943756516348761157632108, 3811440313376405071875160
    );

    let slope = BigInt3(-1,-2,-3);
    let x = ec_double_x_prime(point, slope);
    assert x = BigInt3(
        648518346341351470, 77370588372549613637288996, 18662792551970020321619971
    );

    let slope = BigInt3(-1,-2,-3);
    let x = ec_double_x_secp256r1(point, slope);
    assert x = BigInt3(
        21299552074028835321108137, 50187220174510023990904347, 2291813387120727975022296
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

func try_get_point_from_x_prime{range_check_ptr}(x: BigInt3, v: felt) -> BigInt3 {
    %{
        from starkware.cairo.common.cairo_secp.secp_utils import SECP256R1, pack
        from starkware.python.math_utils import y_squared_from_x

        y_square_int = y_squared_from_x(
            x=pack(ids.x, PRIME),
            alpha=SECP256R1.alpha,
            beta=SECP256R1.beta,
            field_prime=SECP256R1.prime,
        )

        # Note that (y_square_int ** ((SECP256R1.prime + 1) / 4)) ** 2 =
        #   = y_square_int ** ((SECP256R1.prime + 1) / 2) =
        #   = y_square_int ** ((SECP256R1.prime - 1) / 2 + 1) =
        #   = y_square_int * y_square_int ** ((SECP256R1.prime - 1) / 2) = y_square_int * {+/-}1.
        y = pow(y_square_int, (SECP256R1.prime + 1) // 4, SECP256R1.prime)

        # We need to decide whether to take y or prime - y.
        if ids.v % 2 == y % 2:
            value = y
        else:
            value = (-y) % SECP256R1.prime
    %}
    let (y: BigInt3) = nondet_bigint3();
    return y;
}

func try_get_point_from_x_secp256r1{range_check_ptr}(x: BigInt3, v: felt) -> BigInt3 {
    %{
        from starkware.cairo.common.cairo_secp.secp_utils import SECP256R1, pack
        from starkware.python.math_utils import y_squared_from_x

        y_square_int = y_squared_from_x(
            x=pack(ids.x, SECP256R1.prime),
            alpha=SECP256R1.alpha,
            beta=SECP256R1.beta,
            field_prime=SECP256R1.prime,
        )

        # Note that (y_square_int ** ((SECP256R1.prime + 1) / 4)) ** 2 =
        #   = y_square_int ** ((SECP256R1.prime + 1) / 2) =
        #   = y_square_int ** ((SECP256R1.prime - 1) / 2 + 1) =
        #   = y_square_int * y_square_int ** ((SECP256R1.prime - 1) / 2) = y_square_int * {+/-}1.
        y = pow(y_square_int, (SECP256R1.prime + 1) // 4, SECP256R1.prime)

        # We need to decide whether to take y or prime - y.
        if ids.v % 2 == y % 2:
            value = y
        else:
            value = (-y) % SECP256R1.prime
    %}
    let (y: BigInt3) = nondet_bigint3();
    return y;
}


func ec_double_x_prime{range_check_ptr}(point: EcPoint, slope: BigInt3) -> BigInt3 {
    %{
        from starkware.cairo.common.cairo_secp.secp256r1_utils import SECP256R1_P
        from starkware.cairo.common.cairo_secp.secp_utils import pack

        slope = pack(ids.slope, PRIME)
        x = pack(ids.point.x, PRIME)
        y = pack(ids.point.y, PRIME)

        value = new_x = (pow(slope, 2, SECP256R1_P) - 2 * x) % SECP256R1_P
    %}
    let (new_x: BigInt3) = nondet_bigint3();
    return new_x;
}

func ec_double_x_secp256r1{range_check_ptr}(point: EcPoint, slope: BigInt3) -> BigInt3 {
    %{
        from starkware.cairo.common.cairo_secp.secp256r1_utils import SECP256R1_P
        from starkware.cairo.common.cairo_secp.secp_utils import pack

        slope = pack(ids.slope, SECP256R1_P)
        x = pack(ids.point.x, SECP256R1_P)
        y = pack(ids.point.y, SECP256R1_P)

        value = new_x = (pow(slope, 2, SECP256R1_P) - 2 * x) % SECP256R1_P
    %}
    let (new_x: BigInt3) = nondet_bigint3();
    return new_x;
}
