func main() {
    alloc_locals;
    local tmp = 3;
    let a = 17 - tmp;

    %{ print(ids.a) %}

    return ();
}
