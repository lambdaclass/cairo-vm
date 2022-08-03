%builtins range_check

from starkware.cairo.common.cairo_secp.ec import (
        EcPoint,
        ec_negate,
        compute_doubling_slope,
        compute_slope,
        ec_double
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

    #compute_slope
    let (slope_c) = compute_slope(point_a, point_c)
    assert slope_c = BigInt3(71370520431055565073514403,50503780757454603164423474, 8638166971146679236895064)

    let (slope_d) = compute_slope(point_c, point_b)
    assert slope_d = BigInt3(58119528729789858876194497,64998517253171473791555897, 16525667392681120436481221)

    #ec_double
    let (point_d) = ec_double(point_a)
    assert point_d = EcPoint(BigInt3(74427550641062819382893486, 40869730155367266160799328, 5674783931833640986577252), BigInt3(30795856170124638149720790, 54408100978340609265106444, 13350501717657408140240292))

    let (point_e) = ec_double(EcPoint(BigInt3(156, 6545, 100010), BigInt3(-5336262886225868, 1324, -113834066795297906)))
    assert point_e = EcPoint(BigInt3(55117564152931927789817182, 33048130247267262167865975, 14533608608654363688616034), BigInt3(54056253314096377704781816, 68158355584365770862343034, 3052322168655618600739346))

    return()
end
