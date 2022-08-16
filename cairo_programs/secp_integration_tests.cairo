%builtins range_check

from starkware.cairo.common.cairo_secp.bigint import BigInt3, bigint_mul, nondet_bigint3, bigint_to_uint256 
from starkware.cairo.common.cairo_secp.signature import validate_signature_entry
from starkware.cairo.common.cairo_secp.constants import N0, N1, N2, BASE
from starkware.cairo.common.cairo_secp.ec import EcPoint, ec_add, ec_mul, ec_negate, ec_double, fast_ec_add, compute_doubling_slope, compute_slope
from starkware.cairo.common.math import assert_nn_le, assert_not_zero
from starkware.cairo.common.uint256 import Uint256

# Computes x * s^(-1) modulo the size of the elliptic curve (N).
func mul_s_inv{range_check_ptr}(a : BigInt3, b : BigInt3) -> (res : BigInt3):
    %{
        from starkware.cairo.common.cairo_secp.secp_utils import N, pack
        from starkware.python.math_utils import div_mod, safe_div

        a = pack(ids.a, PRIME)
        b = pack(ids.b, PRIME)
        value = res = div_mod(a, b, N)
    %}
    let (res) = nondet_bigint3()

    %{ value = k = safe_div(res * b - a, N) %}
    let (k) = nondet_bigint3()
    let (res_s) = bigint_mul(res, b)
    let n = BigInt3(N0, N1, N2)
    let (k_n) = bigint_mul(k, n)

    # We should now have res_s = k_n + x. Since the numbers are in unreduced form,
    # we should handle the carry.

    tempvar carry1 = (res_s.d0 - k_n.d0 - a.d0) / BASE
    assert [range_check_ptr + 0] = carry1 + 2 ** 127

    tempvar carry2 = (res_s.d1 - k_n.d1 - a.d1 + carry1) / BASE
    assert [range_check_ptr + 1] = carry2 + 2 ** 127

    tempvar carry3 = (res_s.d2 - k_n.d2 - a.d2 + carry2) / BASE
    assert [range_check_ptr + 2] = carry3 + 2 ** 127

    tempvar carry4 = (res_s.d3 - k_n.d3 + carry3) / BASE
    assert [range_check_ptr + 3] = carry4 + 2 ** 127

    assert res_s.d4 - k_n.d4 + carry4 = 0

    let range_check_ptr = range_check_ptr + 4

    return (res=res)
end

# Verifies a Secp256k1 ECDSA signature.
# Soundness assumptions:
# * public_key_pt is on the curve.
# * All the limbs of public_key_pt.x, public_key_pt.y, msg_hash are in the range [0, 3 * BASE).
func verify_ecdsa{range_check_ptr}(
        public_key_pt : EcPoint, msg_hash : BigInt3, r : BigInt3, s : BigInt3) -> (res:EcPoint):
    alloc_locals

    validate_signature_entry(r)
    validate_signature_entry(s)

    let gen_pt = EcPoint(
        BigInt3(0xe28d959f2815b16f81798, 0xa573a1c2c1c0a6ff36cb7, 0x79be667ef9dcbbac55a06),
        BigInt3(0x554199c47d08ffb10d4b8, 0x2ff0384422a3f45ed1229a, 0x483ada7726a3c4655da4f))

    # Compute u1 and u2.
    let (u1 : BigInt3) = mul_s_inv(msg_hash, s)
    let (u2 : BigInt3) = mul_s_inv(r, s)

    let (gen_u1) = ec_mul(gen_pt, u1)
    let (pub_u2) = ec_mul(public_key_pt, u2)
    let (res) = ec_add(gen_u1, pub_u2)

    # The following assert also implies that res is not the zero point.
    assert res.x = r
    return (res)
end

func test_operations{range_check_ptr}(point: EcPoint):
    alloc_locals
    let (negated) = ec_negate(point)
    let (double_negated) = ec_double(negated)
    let (expect_negated) = fast_ec_add(double_negated, point)

    assert negated = expect_negated
    
    let (doubling_slope) = compute_doubling_slope(expect_negated)
    let (x) = bigint_to_uint256(doubling_slope)
    assert x = Uint256(210595298772321355190833442581741248192, 
        240982623677159887741301864838314149180)

    let (slope) = compute_slope(expect_negated, double_negated)
    let (y) = bigint_to_uint256(slope)
    assert y = Uint256(44107115930684365493932432911938496167, 
        320252758622657325248330383435820962345)

    return()
end

func run_tests{range_check_ptr}(index:felt, stop:felt):
    alloc_locals
    if index == stop:
        return()
    end

    let public_key_pt = EcPoint(
        BigInt3(0x35dec240d9f76e20b48b41, 0x27fcb378b533f57a6b585, 0xbff381888b165f92dd33d),
        BigInt3(0x1711d8fb6fbbf53986b57f, 0x2e56f964d38cb8dbdeb30b, 0xe4be2a8547d802dc42041))
    let r = BigInt3(0x2e6c77fee73f3ac9be1217, 0x3f0c0b121ac1dc3e5c03c6, 0xeee3e6f50c576c07d7e4a)
    let s = BigInt3(0x20a4b46d3c5e24cda81f22, 0x967bf895824330d4273d0, 0x541e10c21560da25ada4c)
    let msg_hash = BigInt3(
        0x38a23ca66202c8c2a72277, 0x6730e765376ff17ea8385, 0xca1ad489ab60ea581e6c1)
    let (point) = verify_ecdsa(public_key_pt=public_key_pt, msg_hash=msg_hash, r=r, s=s)
    test_operations(point)
    return run_tests(index + 1, stop)
end

func main{range_check_ptr}():
    run_tests(0, 5)
    return()
end
