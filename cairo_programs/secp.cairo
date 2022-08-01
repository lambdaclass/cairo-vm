%builtins range_check
from starkware.cairo.common.cairo_secp.bigint import (
    nondet_bigint3,
    BigInt3,
)
from starkware.cairo.common.cairo_secp.field import (
    verify_zero,
    UnreducedBigInt3,
    reduce,
    is_zero
)
func main{range_check_ptr: felt}():
    #verify_zero
    let zero: UnreducedBigInt3 = UnreducedBigInt3(0,0,0)
    verify_zero(zero)

    let x: UnreducedBigInt3 = UnreducedBigInt3(132181232131231239112312312313213083892150,10,10)

    #reduce
    let (y: BigInt3) = reduce(x)
    assert y = BigInt3(48537904510172037887998390,1708402383786350,10)

    let m: BigInt3 = nondet_bigint3()
    #Since the scope variable 'value' remains the same, m == y
    assert m = y

    let n: BigInt3 = reduce(UnreducedBigInt3(1321812083892150,11230,103321))
    assert n = BigInt3(1321812083892150,11230,103321)

    let p: BigInt3 = reduce(UnreducedBigInt3(0,0,0))
    assert p = BigInt3(0,0,0)

    let q: BigInt3 = reduce(UnreducedBigInt3(-10,0,0))
    assert q = BigInt3(77371252455336262886226981,77371252455336267181195263, 19342813113834066795298815)

    let r: BigInt3 = reduce(UnreducedBigInt3(-10,-56,-111))
    assert r = BigInt3(77371252455336262886226981,77371252455336267181195207, 19342813113834066795298704)

    # is_zero
    let (u) = is_zero(BigInt3(0,0,0))
    assert u = 1
    let (v) = is_zero(BigInt3(232113757366008801543585,232113757366008801543585,232113757366008801543585))
    assert v = 0

    return()
end
