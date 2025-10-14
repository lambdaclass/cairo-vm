%builtins range_check

from starkware.cairo.common.secp256r1.ec import (
    EcPoint,
)
from starkware.cairo.common.secp256r1.bigint import nondet_bigint3
from starkware.cairo.common.cairo_secp.bigint3 import BigInt3

func main{range_check_ptr: felt}() {
    recursive_hint(0);

    return ();
}

func recursive_hint{range_check_ptr}(n: felt) {
    if (n == 100000) {
        return ();
    }

    let y = BigInt3(-1,-2,-3);
    let z = try_get_point_from_x_prime(y, 0);

    return recursive_hint(n + 1);
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
