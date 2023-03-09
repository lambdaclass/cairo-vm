%builtins ec_op

from starkware.cairo.common.cairo_builtins import EcOpBuiltin
from starkware.cairo.common.ec_point import EcPoint
from starkware.cairo.common.ec import ec_op


func main{ec_op_ptr: EcOpBuiltin*}() {
    let p = EcPoint(3,0);
    let m = 34;
    let q = EcPoint(4,0);
    let (r) = ec_op(p, m, q);
    assert r.x = 3;
    assert r.y = 0;
    return ();
}
