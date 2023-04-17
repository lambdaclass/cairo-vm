%builtins range_check

from cairo_programs.garaba_programs.u255 import u255, Uint256, Uint512, Uint768, P_low, P_high


func inv_mod_p_uint512{range_check_ptr}(x: Uint512) -> Uint256 {
    alloc_locals;
    local x_inverse_mod_p: Uint256;
    local p: Uint256 = Uint256(P_low, P_high);
    // To whitelist
    %{
        def pack_512(u, num_bits_shift: int) -> int:
            limbs = (u.d0, u.d1, u.d2, u.d3)
            return sum(limb << (num_bits_shift * i) for i, limb in enumerate(limbs))

def pack_512(d0, d1,d2,d3, num_bits_shift: int) -> int:
    limbs = (d0, d1, d2, d3)
    return sum(limb << (num_bits_shift * i) for i, limb in enumerate(limbs))


        x = pack_512(ids.x, num_bits_shift = 128)
        p = ids.p.low + (ids.p.high << 128)
        x_inverse_mod_p = pow(x,-1, p) 

        x_inverse_mod_p_split = (x_inverse_mod_p & ((1 << 128) - 1), x_inverse_mod_p >> 128)

        ids.x_inverse_mod_p.low = x_inverse_mod_p_split[0]
        ids.x_inverse_mod_p.high = x_inverse_mod_p_split[1]
    %}

    let x_times_x_inverse: Uint768 = u255.mul_u512_by_u256(
        x, Uint256(x_inverse_mod_p.low, x_inverse_mod_p.high)
    );
    let x_times_x_inverse_mod_p = u255.u768_modulo_p(x_times_x_inverse);
    assert x_times_x_inverse_mod_p = Uint256(1, 0);

    return x_inverse_mod_p;
}

func main{range_check_ptr: felt}() {
    let x = Uint512(101, 2, 15, 61);
    let y = inv_mod_p_uint512(x);
    assert y = Uint256(80275402838848031859800366538378848249, 5810892639608724280512701676461676039);
    return ();
}
