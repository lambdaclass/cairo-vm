%builtins range_check

from starkware.cairo.common.uint256 import Uint256

const P_low = 201385395114098847380338600778089168199;
const P_high = 64323764613183177041862057485226039389;

struct Uint512 {
    d0: felt,
    d1: felt,
    d2: felt,
    d3: felt,
}

func inv_mod_p_uint512{range_check_ptr}(x: Uint512) -> Uint256 {
    alloc_locals;
    local x_inverse_mod_p: Uint256;
    local p: Uint256 = Uint256(P_low, P_high);
    // To whitelist
    %{
        def pack_512(u, num_bits_shift: int) -> int:
            limbs = (u.d0, u.d1, u.d2, u.d3)
            return sum(limb << (num_bits_shift * i) for i, limb in enumerate(limbs))

        x = pack_512(ids.x, num_bits_shift = 128)
        p = ids.p.low + (ids.p.high << 128)
        x_inverse_mod_p = pow(x,-1, p)

        x_inverse_mod_p_split = (x_inverse_mod_p & ((1 << 128) - 1), x_inverse_mod_p >> 128)

        ids.x_inverse_mod_p.low = x_inverse_mod_p_split[0]
        ids.x_inverse_mod_p.high = x_inverse_mod_p_split[1]
    %}

    return x_inverse_mod_p;
}

func recursive_hint{range_check_ptr: felt}(n: felt) {
    if (n == 1000000) {
        return ();
    }
    let x = Uint512(101, 2, 15, 61);
    let y = inv_mod_p_uint512(x);

    return recursive_hint(n + 1);
}

func main{range_check_ptr: felt}() {
    recursive_hint(0);
    return ();
}
