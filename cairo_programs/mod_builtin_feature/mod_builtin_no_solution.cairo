%builtins range_check add_mod mul_mod

from cairo_programs.mod_builtin_feature.common.modulo import ModBuiltin, UInt384, run_mod_p_circuit
from starkware.cairo.common.registers import get_label_location
from starkware.cairo.common.alloc import alloc

func main{range_check_ptr, add_mod_ptr: ModBuiltin*, mul_mod_ptr: ModBuiltin*}() {
    alloc_locals;


    // The circuit definition can be described as:
    //
    // x1 (input)
    // x2 (input)
    // a1 = x1 + x2
    // a2 = ??
    // a3 = a1 * a2
    //
    // As the first mul gate tries to compute a3 when a2 is unkown, it will fail.

    let p = UInt384(d0=1, d1=1, d2=0, d3=0);
    let x1 = UInt384(d0=1, d1=0, d2=0, d3=0);
    let x2 = UInt384(d0=2, d1=1, d2=0, d3=0);

    let (local values_arr: UInt384*) = alloc();
    assert values_arr[0] = x1;
    assert values_arr[1] = x2;

    let (local add_mod_offsets_arr: felt*) = alloc();
    assert add_mod_offsets_arr[0] = 0;  // x1
    assert add_mod_offsets_arr[1] = 4;  // x2
    assert add_mod_offsets_arr[2] = 8;  // a1 = x1 + x2

    let (local mul_mod_offsets_arr: felt*) = alloc();
    assert mul_mod_offsets_arr[0] = 8;  // a1
    assert mul_mod_offsets_arr[1] = 12; // a2 (unknown)
    assert mul_mod_offsets_arr[2] = 16; // a1 * a2 (impossible)

    run_mod_p_circuit(
        p=p,
        values_ptr=values_arr,
        add_mod_offsets_ptr=add_mod_offsets_arr,
        add_mod_n=1,
        mul_mod_offsets_ptr=mul_mod_offsets_arr,
        mul_mod_n=1,
    );

    return ();
}
