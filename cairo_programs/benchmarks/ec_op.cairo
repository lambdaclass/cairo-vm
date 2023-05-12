from ec_op import run
from starkware.cairo.common.cairo_builtins import EcOpBuiltin

func main{ec_op_ptr: EcOpBuiltin*}() {
    run(1000);
    return ();
}
