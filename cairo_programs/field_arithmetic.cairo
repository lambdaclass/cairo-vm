// Code taken from https://github.com/NethermindEth/research-basic-Cairo-operations-big-integers/blob/fbf532651959f27037d70cd70ec6dbaf987f535c/lib/field_arithmetic_new.cairo
from starkware.cairo.common.bitwise import bitwise_and, bitwise_or, bitwise_xor
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math import assert_in_range, assert_le, assert_nn_le, assert_not_zero
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.pow import pow
from starkware.cairo.common.registers import get_ap, get_fp_and_pc
from cairo_programs.uint384 import uint384_lib, Uint384, Uint384_expand, SHIFT, HALF_SHIFT
from cairo_programs.uint384_extension import uint384_extension_lib, Uint768

// Functions for operating elements in a finite field F_p (i.e. modulo a prime p), with p of at most 384 bits
namespace field_arithmetic {
    // Computes a * b modulo p
    func mul{range_check_ptr}(a: Uint384, b: Uint384, p: Uint384_expand) -> (res: Uint384) {
        let (low: Uint384, high: Uint384) = uint384_lib.mul_d(a, b);
        let full_mul_result: Uint768 = Uint768(low.d0, low.d1, low.d2, high.d0, high.d1, high.d2);
        let (
            quotient: Uint768, remainder: Uint384
        ) = uint384_extension_lib.unsigned_div_rem_uint768_by_uint384_expand(full_mul_result, p);
        return (remainder,);
    }

    // Computes a**2 modulo p
    func square{range_check_ptr}(a: Uint384, p: Uint384_expand) -> (res: Uint384) {
        let (low: Uint384, high: Uint384) = uint384_lib.square_e(a);
        let full_mul_result: Uint768 = Uint768(low.d0, low.d1, low.d2, high.d0, high.d1, high.d2);
        let (
            quotient: Uint768, remainder: Uint384
        ) = uint384_extension_lib.unsigned_div_rem_uint768_by_uint384_expand(full_mul_result, p);
        return (remainder,);
    }

    // Finds a square of x in F_p, i.e. x ≅ y**2 (mod p) for some y
    // To do so, the following is done in a hint:
    // 0. Assume x is not  0 mod p
    // 1. Check if x is a square, if yes, find a square root r of it
    // 2. If (and only if not), then gx *is* a square (for g a generator of F_p^*), so find a square root r of it
    // 3. Check in Cairo that r**2 = x (mod p) or r**2 = gx (mod p), respectively
    // NOTE: The function assumes that 0 <= x < p
    func get_square_root{range_check_ptr}(x: Uint384, p: Uint384_expand, generator: Uint384) -> (
        success: felt, res: Uint384
    ) {
        alloc_locals;

        // TODO: Create an equality function within field_arithmetic to avoid overflow bugs
        let (is_zero) = uint384_lib.eq(x, Uint384(0, 0, 0));
        if (is_zero == 1) {
            return (1, Uint384(0, 0, 0));
        }

        local success_x: felt;
        local sqrt_x: Uint384;
        local sqrt_gx: Uint384;

        // Compute square roots in a hint
        %{
            from starkware.python.math_utils import is_quad_residue, sqrt

            def split(num: int, num_bits_shift: int = 128, length: int = 3):
                a = []
                for _ in range(length):
                    a.append( num & ((1 << num_bits_shift) - 1) )
                    num = num >> num_bits_shift
                return tuple(a)

            def pack(z, num_bits_shift: int = 128) -> int:
                limbs = (z.d0, z.d1, z.d2)
                return sum(limb << (num_bits_shift * i) for i, limb in enumerate(limbs))

            def pack2(z, num_bits_shift: int = 128) -> int:
                limbs = (z.b01, z.b23, z.b45)
                return sum(limb << (num_bits_shift * i) for i, limb in enumerate(limbs))


            generator = pack(ids.generator)
            x = pack(ids.x)
            p = pack2(ids.p)

            success_x = is_quad_residue(x, p)
            root_x = sqrt(x, p) if success_x else None

            success_gx = is_quad_residue(generator*x, p)
            root_gx = sqrt(generator*x, p) if success_gx else None

            # Check that one is 0 and the other is 1
            if x != 0:
                assert success_x + success_gx ==1

            # `None` means that no root was found, but we need to transform these into a felt no matter what
            if root_x == None:
                root_x = 0
            if root_gx == None:
                root_gx = 0
            ids.success_x = int(success_x)
            split_root_x = split(root_x)
            split_root_gx = split(root_gx)
            ids.sqrt_x.d0 = split_root_x[0]
            ids.sqrt_x.d1 = split_root_x[1]
            ids.sqrt_x.d2 = split_root_x[2]
            ids.sqrt_gx.d0 = split_root_gx[0]
            ids.sqrt_gx.d1 = split_root_gx[1]
            ids.sqrt_gx.d2 = split_root_gx[2]
        %}

        // Verify that the values computed in the hint are what they are supposed to be
        let (gx: Uint384) = mul(generator, x, p);
        if (success_x == 1) {
            uint384_lib.check(sqrt_x);
            let (is_valid) = uint384_lib.lt(sqrt_x, Uint384(p.b01, p.b23, p.b45));
            assert is_valid = 1;
            let (sqrt_x_squared: Uint384) = square(sqrt_x, p);
            // Note these checks may fail if the input x does not satisfy 0<= x < p
            // TODO: Create a equality function within field_arithmetic to avoid overflow bugs
            assert x = sqrt_x_squared;
            return (1, sqrt_x);
        } else {
            // In this case success_gx = 1
            uint384_lib.check(sqrt_gx);
            let (is_valid) = uint384_lib.lt(sqrt_gx, Uint384(p.b01, p.b23, p.b45));
            assert is_valid = 1;
            let (sqrt_gx_squared: Uint384) = square(sqrt_gx, p);
            assert gx = sqrt_gx_squared;
            // No square roots were found
            // Note that Uint384(0, 0, 0) is not a square root here, but something needs to be returned
            return (0, Uint384(0, 0, 0));
        }
    }
}

func test_field_arithmetics_extension_operations{range_check_ptr}() {
    // Test unsigned_div_rem_uint768_by_uint384
    // Test unsigned_div_rem_uint768_by_uint384
    let p = Uint384_expand(0, 7, 0, 0, 0, 0, 0);
    let x = Uint384(2, 0, 0);
    let generator = Uint384(3, 0, 0);
    let (s, r) = field_arithmetic.get_square_root(x, p, generator);
    assert s = 1;

    assert r.d0 = 3;
    assert r.d1 = 0;
    assert r.d2 = 0;
    return ();
}

func main{range_check_ptr: felt}() {
    test_field_arithmetics_extension_operations();
    return ();
}
