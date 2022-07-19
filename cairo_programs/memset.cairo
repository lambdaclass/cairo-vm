from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.memset import memset

func main():
    alloc_locals
    let (local string1 : felt*) = alloc()
    memset(string1,'I dont know why',20)
    let (local string2 : felt*) = alloc()
    memset(string2,'Do you know why',20)

    assert string1[19] = 'I dont know why'
    assert string2[1] = 'Do you know why'

return ()
end
