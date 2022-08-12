from blak2s_integration_tests import run_tests

func main{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}():
    run_tests(100)

    return ()
end