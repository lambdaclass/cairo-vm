struct MyStruct:
    member first_member : felt
    member second_member : felt
end

func main():
    let struct_instance = MyStruct(first_member=1, second_member=2)
    let struct_instance_2 = MyStruct(3,4)
    return()
end
