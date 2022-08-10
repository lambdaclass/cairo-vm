from starkware.cairo.common.default_dict import default_dict_new
from starkware.cairo.common.dict_access import DictAccess
from starkware.cairo.common.dict import dict_read, dict_write, dict_update, dict_squash

func fill_dictionary{dict_start : DictAccess*}(base : felt, step : felt, iter : felt, last : felt):
    alloc_locals
    if iter == last:
        return ()
    end

    let new_val : felt = base + step * iter

    dict_write{dict_ptr=dict_start}(key=iter, new_value=new_val)
    let (local val : felt) = dict_read{dict_ptr=dict_start}(key=iter)
    assert val = new_val

    return fill_dictionary{dict_start=dict_start}(base, step, iter + 1, last)
end

func update_dictionary{dict_start : DictAccess*}(base : felt, step : felt, iter : felt, last : felt):
    alloc_locals
    if iter == last:
        return ()
    end

    let (local prev_val : felt) = dict_read{dict_ptr=dict_start}(key=iter)
    let new_val : felt = base + step * iter
    
    dict_update{dict_ptr=dict_start}(key=iter, prev_value=prev_val, new_value=new_val)
    let (local val : felt) = dict_read{dict_ptr=dict_start}(key=iter)
    assert val = new_val

    return update_dictionary{dict_start=dict_start}(base, step, iter + 1, last)
end

func test_integration(iters : felt) -> ():
    alloc_locals

    let (local my_dict : DictAccess*) = default_dict_new(0)
    fill_dictionary{dict_start=my_dict}(base=1, step=2, iter=0, last=iters)
    update_dictionary{dict_start=my_dict}(base=2, step=3, iter=0, last=iters)

    return ()
end

func main():
    test_integration(1000)

    return ()
end
