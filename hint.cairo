%builtins range_check
    from starkware.cairo.common.math_cmp import is_nn
    func main{range_check_ptr: felt}():
        let a = 1
        is_nn{range_check_ptr=range_check_ptr}(a)
        return()
    end