%builtins range_check

from starkware.cairo.common.uint256 import Uint256

func main{range_check_ptr: felt}() {
    tempvar val = new Uint256(1, 2);
    %{
        low = ids.val.low
        high = ids.val.high
        print(f"Uint256(low={low}, high={high}) = {2 ** 128 * high + low}")
    %}
    return();
}
