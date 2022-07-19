%builtins range_check

from starkware.cairo.common.pow import pow

func main{range_check_ptr: felt}():
    let (y) = pow(2,3)
    assert y = 8
    return ()
end
