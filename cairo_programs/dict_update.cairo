from starkware.cairo.common.dict import dict_read, dict_write, dict_update
from starkware.cairo.common.default_dict import default_dict_new
from starkware.cairo.common.dict_access import DictAccess

func main():
    alloc_locals
    let (local my_dict : DictAccess*) = default_dict_new(17)
    dict_write{dict_ptr=my_dict}(key=12, new_value=34)
    let (local val1 : felt) = dict_read{dict_ptr=my_dict}(key=12)
    assert val1 = 34
    dict_update{dict_ptr=my_dict}(key=12, prev_value=34, new_value=49)
    let (local val2 : felt) = dict_read{dict_ptr=my_dict}(key=12)
    assert val2 = 49
    return()
end
