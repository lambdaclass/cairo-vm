%builtins range_check

from starkware.cairo.common.registers import get_label_location
from cairo_programs.bn254_towers_e12 import E12, e12
from cairo_programs.bn254_towers_e6 import E6
from cairo_programs.bn254_towers_e2 import E2

from cairo_programs.bn254_fq import BigInt3

func final_exponentiation{range_check_ptr}(z: E12*) -> E12* {
    alloc_locals;
    let (__fp__, _) = get_fp_and_pc();

    // Easy part
    // (p⁶-1)(p²+1)

    let result = z;
    let t0 = e12.conjugate(z);
    let result = e12.inverse(result);
    let t0 = e12.mul(t0, result);
    let result = e12.frobenius_square(t0);
    let result = e12.mul(result, t0);

    // Hard part (up to permutation)
    // 2x₀(6x₀²+3x₀+1)(p⁴-p²+1)/r
    // Duquesne and Ghammam
    // https://eprint.iacr.org/2015/192.pdf
    // Fuentes et al. variant (alg. 10)

    let t0 = e12.expt(result);
    let t0 = e12.conjugate(t0);
    let t0 = e12.cyclotomic_square(t0);
    let t2 = e12.expt(t0);
    let t2 = e12.conjugate(t2);
    let t1 = e12.cyclotomic_square(t2);
    let t2 = e12.mul(t2, t1);
    let t2 = e12.mul(t2, result);
    let t1 = e12.expt(t2);
    let t1 = e12.cyclotomic_square(t1);
    let t1 = e12.mul(t1, t2);
    let t1 = e12.conjugate(t1);
    let t3 = e12.conjugate(t1);
    let t1 = e12.cyclotomic_square(t0);
    let t1 = e12.mul(t1, result);
    let t1 = e12.conjugate(t1);
    let t1 = e12.mul(t1, t3);
    let t0 = e12.mul(t0, t1);
    let t2 = e12.mul(t2, t1);
    let t3 = e12.frobenius_square(t1);
    let t2 = e12.mul(t2, t3);
    let t3 = e12.conjugate(result);
    let t3 = e12.mul(t3, t0);
    let t1 = e12.frobenius_cube(t3);
    let t2 = e12.mul(t2, t1);
    let t1 = e12.frobenius(t0);
    let t1 = e12.mul(t1, t2);

    return t1;
}

func main{range_check_ptr}() {
    alloc_locals;
    let (__fp__, _) = get_fp_and_pc();

    local x0: BigInt3 = BigInt3(
        47179258806881839753834432, 73351232389874758267716386, 221230111651454481259944
    );
    local x1: BigInt3 = BigInt3(
        70305189324466218563244022, 70497353093498701909204246, 1859620529496052270201593
    );
    local x2: BigInt3 = BigInt3(
        31549205938449458293898197, 28363108023920043247158823, 2963776429478082002194476
    );
    local x3: BigInt3 = BigInt3(
        66686338175159365229343719, 55529342882177093289022412, 794182356658274811583746
    );
    local x4: BigInt3 = BigInt3(
        5219737444391444482575295, 17332791677112014750642906, 3496708921788187208653781
    );
    local x5: BigInt3 = BigInt3(
        4904148080862357475223082, 23706426689346075079838757, 325522515148816440156397
    );
    local x6: BigInt3 = BigInt3(
        18899998223672293288990464, 43118001735500548543804087, 618912707114061638124004
    );
    local x7: BigInt3 = BigInt3(
        58905762650148235406382062, 64428024468610254063310260, 528222872493652570380270
    );
    local x8: BigInt3 = BigInt3(
        58427133274286968684269402, 18701882253303795511647966, 672131593852471774989436
    );
    local x9: BigInt3 = BigInt3(
        41360928298598547902013605, 61856819731785967743014542, 1776212296981348003778195
    );
    local x10: BigInt3 = BigInt3(
        42288437197648338903872642, 9454971987528319713382431, 2460266149875019902514729
    );
    local x11: BigInt3 = BigInt3(
        46263957663890328137472694, 27637618252703151695767436, 570504160891095557667183
    );

    tempvar x = new E12(
        new E6(new E2(&x0, &x1), new E2(&x2, &x3), new E2(&x4, &x5)),
        new E6(new E2(&x6, &x7), new E2(&x8, &x9), new E2(&x10, &x11)),
    );

    let res = final_exponentiation(x);
}
