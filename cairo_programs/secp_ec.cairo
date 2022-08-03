%builtins range_check

from starkware.cairo.common.cairo_secp.ec import (
        EcPoint,
        ec_negate,
        compute_doubling_slope,
)
from starkware.cairo.common.cairo_secp.bigint import BigInt3

func main{range_check_ptr: felt}():

    let x = BigInt3(1, 5, 10)
    let y = BigInt3(2, 4, 20)

    #ec_negate
    let point_a = EcPoint(x, y)
    let (point_b) = ec_negate(point_a)

    assert point_b = EcPoint(BigInt3(1, 5, 10), BigInt3(77371252455336262886226989, 77371252455336267181195259, 19342813113834066795298795))

    let (point_c) = ec_negate(EcPoint(BigInt3(156, 6545, 100010), BigInt3(1123, -1325, 910)))
    assert point_c = EcPoint(BigInt3(156, 6545, 100010), BigInt3(77371252455336262886225868, 1324, 19342813113834066795297906))

    #compute_doubling_slope
    let (slope_a) = compute_doubling_slope(point_b)
    assert slope_a = BigInt3(64662730981121038053136098,32845645948216066767036314, 8201186782676455849150319)

    let (slope_b) = compute_doubling_slope(EcPoint(BigInt3(-1231, -51235643, -100000), BigInt3(77371252455, 7737125245, 19342813113)))
    assert slope_b = BigInt3(33416489251043008849460372,4045868738249434151710245, 18495428769257823271538303)

    return()
end
