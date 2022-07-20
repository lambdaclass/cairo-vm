from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.memset import memset

func main():
    alloc_locals
    let (local strings : felt*) = alloc()
    memset(strings,'Lambda',20)
    assert strings[0] = 'Lambda'
    assert strings[19] = 'Lambda'
    assert strings[20] = 'can insert new value'

    let numbers : felt* = alloc()
    memset(numbers, 10, 100)
    assert numbers[0] = 10
    assert numbers[99] = 10
    assert numbers[100] = 11

return ()
end
