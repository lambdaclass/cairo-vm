from dict_integration_tests import test_integration 

func main{range_check_ptr : felt}():
    test_integration(10000)

    return ()
end
