%builtins poseidon
from starkware.cairo.common.cairo_builtins import PoseidonBuiltin
from starkware.cairo.common.poseidon_state import PoseidonBuiltinState

func main{poseidon_ptr: PoseidonBuiltin*}() {
    assert poseidon_ptr[0].input = PoseidonBuiltinState(1, 2, 3);
    let result = poseidon_ptr[0].output;
    let poseidon_ptr = poseidon_ptr + PoseidonBuiltin.SIZE;
    // Note that we are not accesing result.s1.
    assert result.s0 = 442682200349489646213731521593476982257703159825582578145778919623645026501;
    assert result.s2 = 2512222140811166287287541003826449032093371832913959128171347018667852712082;
    return ();
}
