# factorial(n) =  n!
func factorial(n) -> (result):
    if n == 1:
        return (n)
    end
    let (a) = factorial(n-1)
    return (n*a)
end

# factorial(n), t times
func factorial_wrapper(n, t):
    factorial(t)
    if n!=0:
        factorial_wrapper(n-1, t)
    end
    return ()
end

func main():
    # Make sure the factorial(10) == 3628800
    let (y) = factorial(10)
    y = 3628800

    # factorial(50), 100 times
    factorial_wrapper(50, 100)
    return ()
end
