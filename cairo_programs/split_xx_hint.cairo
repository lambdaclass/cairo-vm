from starkware.cairo.common.uint256 import Uint256

func main() {
    alloc_locals;

    local xx: Uint256 = Uint256(7, 17);
    local x: Uint256;
    %{
        PRIME = 2**255 - 19
        II = pow(2, (PRIME - 1) // 4, PRIME)

        xx = ids.xx.low + (ids.xx.high<<128)
        x = pow(xx, (PRIME + 3) // 8, PRIME)
        if (x * x - xx) % PRIME != 0:
            x = (x * II) % PRIME
        if x % 2 != 0:
            x = PRIME - x
        ids.x.low = x & ((1<<128)-1)
        ids.x.high = x >> 128
    %}

    assert x.low = 316161011683971866381321160306766491472;
    assert x.high = 30265492890921847871084892076606437231;

    return ();
}
