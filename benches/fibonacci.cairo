func main():
    # Call fib(1, 1, 100).
    [ap] = 1; ap++
    [ap] = 1; ap++
    [ap] = 100; ap++
    call fib

    # Make sure the 100th Fibonacci number is 927372692193078999176.
    [ap - 1] = 927372692193078999176
    ret
end

func fib(first_element, second_element, n) -> (res : felt):
    jmp fib_body if n != 0
    [ap] = second_element; ap++
    ret

    fib_body:
    [ap] = second_element; ap++
    [ap] = first_element + second_element; ap++
    [ap] = n - 1; ap++
    call fib
    ret
end