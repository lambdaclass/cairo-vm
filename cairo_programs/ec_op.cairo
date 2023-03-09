%builtins ec_op

from starkware.cairo.common.cairo_builtins import EcOpBuiltin
from starkware.cairo.common.ec_point import EcPoint
from starkware.cairo.common.ec import ec_op


func main{ec_op_ptr: EcOpBuiltin*}() {
    let p = EcPoint(
        0x6a4beaef5a93425b973179cdba0c9d42f30e01a5f1e2db73da0884b8d6756fc,
        0x72565ec81bc09ff53fbfad99324a92aa5b39fb58267e395e8abe36290ebf24f,
    );
    let m = 34;
    let q = EcPoint(4,2);
    let (r) = ec_op(p, m, q);
    assert r.x = 3;
    assert r.y = 0;
    return ();
}
