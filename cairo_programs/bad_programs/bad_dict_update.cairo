from starkware.cairo.common.dict import dict_update
from starkware.cairo.common.default_dict import default_dict_new
from starkware.cairo.common.dict_access import DictAccess

func main():
    alloc_locals
    let (local my_dict : DictAccess*) = default_dict_new()
    #This call should fail as there is no key 2
    let (local val1 : felt) = dict_update{dict_ptr=my_dict}(key=2, val=3)
    return()
end
