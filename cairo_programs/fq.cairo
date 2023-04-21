from starkware.cairo.common.uint256 import Uint256, split_64
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.cairo_secp.constants import BASE
from starkware.cairo.common.cairo_secp.bigint import (
    BigInt3,
    uint256_to_bigint,
    bigint_to_uint256,
    UnreducedBigInt5,
    bigint_mul,
    nondet_bigint3,
)

from cairo_programs.uint384_extension import Uint384, Uint768, u384

// src: https://github.com/rdubois-crypto/garaga/blob/48a5b1d7d530baba2338698ffebf988ed3d19e6d/src/curve.cairo
const P0 = 60193888514187762220203335;
const P1 = 27625954992973055882053025;
const P2 = 3656382694611191768777988;

const P_low = 201385395114098847380338600778089168199;
const P_high = 64323764613183177041862057485226039389;
// ------------------

struct Uint512 {
    d0: felt,
    d1: felt,
    d2: felt,
    d3: felt,
}

const SHIFT = 2 ** 128;
const ALL_ONES = 2 ** 128 - 1;
const HALF_SHIFT = 2 ** 64;

// src: https://github.com/rdubois-crypto/garaga/blob/48a5b1d7d530baba2338698ffebf988ed3d19e6d/src/fq.cairo
namespace u512 {
    func add_u512_and_u256{range_check_ptr}(a: Uint512, b: Uint256) -> Uint512 {
        alloc_locals;

        let a_low = Uint256(low=a.d0, high=a.d1);
        let a_high = Uint256(low=a.d2, high=a.d3);

        let (sum_low, carry0) = add_carry(a_low, b);

        local res: Uint512;

        res.d0 = sum_low.low;
        res.d1 = sum_low.high;
        // res.d2 = sum_low.d2;

        // TODO : create add_one (high bits not needed)
        let a_high_plus_carry = add(a_high, Uint256(carry0, 0));

        res.d2 = a_high_plus_carry.low;
        res.d3 = a_high_plus_carry.high;

        return res;
    }

    func mul_u512_by_u256{range_check_ptr}(a: Uint512, b: Uint256) -> Uint768 {
        alloc_locals;
        let (a0, a1) = split_64(a.d0);
        let (a2, a3) = split_64(a.d1);
        let (a4, a5) = split_64(a.d2);
        let (a6, a7) = split_64(a.d3);

        let (b0, b1) = split_64(b.low);
        let (b2, b3) = split_64(b.high);

        local B0 = b0 * HALF_SHIFT;
        local b12 = b1 + b2 * HALF_SHIFT;

        let (res0, carry) = u384.split_128(a1 * B0 + a0 * b.low);
        let (res2, carry) = u384.split_128(a3 * B0 + a2 * b.low + a1 * b12 + a0 * b.high + carry);
        let (res4, carry) = u384.split_128(
            a5 * B0 + a4 * b.low + a3 * b12 + a2 * b.high + a1 * b3 + carry
        );
        let (res6, carry) = u384.split_128(
            a7 * B0 + a6 * b.low + a5 * b12 + a4 * b.high + a3 * b3 + carry
        );
        let (res8, carry) = u384.split_128(a7 * b12 + a6 * b.high + a5 * b3 + carry);
        let (res10, carry) = u384.split_128(a7 * b3 + carry);
        let res = Uint768(d0=res0, d1=res2, d2=res4, d3=res6, d4=res8, d5=res10);
        return res;
    }

    func u512_unsigned_div_rem{range_check_ptr}(x: Uint512, div: Uint256) -> (
        q: Uint512, r: Uint256
    ) {
        alloc_locals;
        local quotient: Uint512;
        local remainder: Uint256;

        %{
            def split(num: int, num_bits_shift: int, length: int):
                a = []
                for _ in range(length):
                    a.append( num & ((1 << num_bits_shift) - 1) )
                    num = num >> num_bits_shift
                return tuple(a)

            def pack(z, num_bits_shift: int) -> int:
                limbs = (z.low, z.high)
                return sum(limb << (num_bits_shift * i) for i, limb in enumerate(limbs))

            def pack_extended(z, num_bits_shift: int) -> int:
                limbs = (z.d0, z.d1, z.d2, z.d3)
                return sum(limb << (num_bits_shift * i) for i, limb in enumerate(limbs))

            x = pack_extended(ids.x, num_bits_shift = 128)
            div = pack(ids.div, num_bits_shift = 128)

            quotient, remainder = divmod(x, div)

            quotient_split = split(quotient, num_bits_shift=128, length=4)

            ids.quotient.d0 = quotient_split[0]
            ids.quotient.d1 = quotient_split[1]
            ids.quotient.d2 = quotient_split[2]
            ids.quotient.d3 = quotient_split[3]

            remainder_split = split(remainder, num_bits_shift=128, length=2)
            ids.remainder.low = remainder_split[0]
            ids.remainder.high = remainder_split[1]
        %}

        let res_mul: Uint768 = mul_u512_by_u256(quotient, div);

        assert res_mul.d4 = 0;
        assert res_mul.d5 = 0;

        let check_val: Uint512 = add_u512_and_u256(
            Uint512(res_mul.d0, res_mul.d1, res_mul.d2, res_mul.d3), remainder
        );

        // assert add_carry = 0;
        assert check_val = x;

        let is_valid = lt(remainder, div);
        assert is_valid = 1;

        return (quotient, remainder);
    }

    // Verifies that the given integer is valid.
    func check{range_check_ptr}(a: Uint256) {
        // tempvar h = a.high - 2 ** 127;
        [range_check_ptr] = a.low;
        [range_check_ptr + 1] = a.high;
        let range_check_ptr = range_check_ptr + 2;
        return ();
    }

    // Assume a and b are lower than 2**255-19
    func add{range_check_ptr}(a: Uint256, b: Uint256) -> Uint256 {
        alloc_locals;
        local res: Uint256;
        local carry_low: felt;
        // unused. added to use UINT256_ADD
        local carry_high: felt;
        // this hint is not implemented:
        // %{
        //     sum_low = ids.a.low + ids.b.low
        //     ids.carry_low = 1 if sum_low >= ids.SHIFT else 0
        // %}
        %{
            sum_low = ids.a.low + ids.b.low
            ids.carry_low = 1 if sum_low >= ids.SHIFT else 0
            sum_high = ids.a.high + ids.b.high + ids.carry_low
            ids.carry_high = 1 if sum_high >= ids.SHIFT else 0
        %}
        // changed hint, no carry_high
        assert carry_low * carry_low = carry_low;

        assert res.low = a.low + b.low - carry_low * SHIFT;
        assert res.high = a.high + b.high + carry_low;
        // check(res);

        return res;
    }

    func add_carry{range_check_ptr}(a: Uint256, b: Uint256) -> (res: Uint256, carry: felt) {
        alloc_locals;
        local res: Uint256;
        local carry_low: felt;
        local carry_high: felt;
        %{
            sum_low = ids.a.low + ids.b.low
            ids.carry_low = 1 if sum_low >= ids.SHIFT else 0
            sum_high = ids.a.high + ids.b.high + ids.carry_low
            ids.carry_high = 1 if sum_high >= ids.SHIFT else 0
        %}

        assert carry_low * carry_low = carry_low;
        assert carry_high * carry_high = carry_high;

        assert res.low = a.low + b.low - carry_low * SHIFT;
        assert res.high = a.high + b.high + carry_low - carry_high * SHIFT;
        check(res);

        return (res, carry_high);
    }

    func lt{range_check_ptr}(a: Uint256, b: Uint256) -> felt {
        if (a.high == b.high) {
            return is_le(a.low + 1, b.low);
        }
        return is_le(a.high + 1, b.high);
    }

    // Computes a * b^{-1} modulo p
    // NOTE: The modular inverse of b modulo p is computed in a hint and verified outside the hind with a multiplicaiton
    func div{range_check_ptr}(a: Uint256, b: Uint256) -> Uint256 {
        alloc_locals;
        local p: Uint256 = Uint256(P_low, P_high);
        local b_inverse_mod_p: Uint256;
        // To whitelist
        %{
            from starkware.python.math_utils import div_mod

            def split(a: int):
                return (a & ((1 << 128) - 1), a >> 128)

            def pack(z, num_bits_shift: int) -> int:
                limbs = (z.low, z.high)
                return sum(limb << (num_bits_shift * i) for i, limb in enumerate(limbs))

            a = pack(ids.a, 128)
            b = pack(ids.b, 128)
            p = pack(ids.p, 128)
            # For python3.8 and above the modular inverse can be computed as follows:
            # b_inverse_mod_p = pow(b, -1, p)
            # Instead we use the python3.7-friendly function div_mod from starkware.python.math_utils
            b_inverse_mod_p = div_mod(1, b, p)

            b_inverse_mod_p_split = split(b_inverse_mod_p)

            ids.b_inverse_mod_p.low = b_inverse_mod_p_split[0]
            ids.b_inverse_mod_p.high = b_inverse_mod_p_split[1]
        %}
        let b_times_b_inverse = mul(b, b_inverse_mod_p);
        assert b_times_b_inverse = Uint256(1, 0);

        let res: Uint256 = mul(a, b_inverse_mod_p);
        return res;
    }

    func mul{range_check_ptr}(a: BigInt3, b: BigInt3) -> BigInt3 {
        let mul: UnreducedBigInt5 = bigint_mul(a, b);
        %{
            p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
            mul = ids.mul.d0 + ids.mul.d1*2**86 + ids.mul.d2*2**172 + ids.mul.d3*2**258 + ids.mul.d4*2**344
            value = mul%p
        %}
        let (result: BigInt3) = nondet_bigint3();
        utils.verify_zero5(
            UnreducedBigInt5(
                d0=mul.d0 - result.d0,
                d1=mul.d1 - result.d1,
                d2=mul.d2 - result.d2,
                d3=mul.d3,
                d4=mul.d4,
            ),
        );
        return result;
    }
}

// src: https://github.com/rdubois-crypto/garaga/blob/48a5b1d7d530baba2338698ffebf988ed3d19e6d/src/utils.cairo
namespace utils {
    func verify_zero5{range_check_ptr}(val: UnreducedBigInt5) {
        alloc_locals;
        local flag;
        local q1;
        %{
            from starkware.cairo.common.cairo_secp.secp_utils import pack
            from starkware.cairo.common.math_utils import as_int

            P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47

            v3 = as_int(ids.val.d3, PRIME)
            v4 = as_int(ids.val.d4, PRIME)
            v = pack(ids.val, PRIME) + v3*2**258 + v4*2**344

            q, r = divmod(v, P)
            assert r == 0, f"verify_zero: Invalid input {ids.val.d0, ids.val.d1, ids.val.d2, ids.val.d3, ids.val.d4}."

            # Since q usually doesn't fit BigInt3, divide it again
            ids.flag = 1 if q > 0 else 0
            q = q if q > 0 else 0-q
            q1, q2 = divmod(q, P)
            ids.q1 = q1
            value = k = q2
        %}
        let (k) = nondet_bigint3();
        let fullk = BigInt3(q1 * P0 + k.d0, q1 * P1 + k.d1, q1 * P2 + k.d2);
        let P = BigInt3(P0, P1, P2);
        let (k_n) = bigint_mul(fullk, P);

        // val mod n = 0, so val = k_n
        tempvar carry1 = ((2 * flag - 1) * k_n.d0 - val.d0) / BASE;
        assert [range_check_ptr + 0] = carry1 + 2 ** 127;

        tempvar carry2 = ((2 * flag - 1) * k_n.d1 - val.d1 + carry1) / BASE;
        assert [range_check_ptr + 1] = carry2 + 2 ** 127;

        tempvar carry3 = ((2 * flag - 1) * k_n.d2 - val.d2 + carry2) / BASE;
        assert [range_check_ptr + 2] = carry3 + 2 ** 127;

        tempvar carry4 = ((2 * flag - 1) * k_n.d3 - val.d3 + carry3) / BASE;
        assert [range_check_ptr + 3] = carry4 + 2 ** 127;

        assert (2 * flag - 1) * k_n.d4 - val.d4 + carry4 = 0;

        let range_check_ptr = range_check_ptr + 4;

        return ();
    }
}

func main() {
    return ();
}
