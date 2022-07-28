%builtins range_check
from starkware.cairo.common.cairo_secp.bigint import (
    nondet_bigint3,
    BigInt3,
)
from starkware.cairo.common.cairo_secp.field import (
    verify_zero,
    UnreducedBigInt3,
    reduce
)
func main{range_check_ptr: felt}():
    let x: UnreducedBigInt3 = UnreducedBigInt3(0,0,0)
    verify_zero(x)
    let y: UnreducedBigInt3 = UnreducedBigInt3(132181232131231239112312312313213083892150,10,10)
    let (z: BigInt3) = reduce(y)
    assert z = BigInt3(48537904510172037887998390,1708402383786350,10)

    return()
end
