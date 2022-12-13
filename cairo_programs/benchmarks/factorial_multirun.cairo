// factorial(n) =  n!
func factorial(n) -> (result: felt) {
    if (n == 1) {
        return (n,);
    }
    let (a) = factorial(n - 1);
    return (n * a,);
}

// factorial(n), t + 1 times
func factorial_wrapper(n, t) {
    factorial(n);
    if (t != 0) {
        factorial_wrapper(n, t - 1);
    }
    return ();
}

func main() {
    // Make sure the factorial(10) == 3628800
    let (y) = factorial(10);
    y = 3628800;

    // factorial(10000), 11 times
    factorial_wrapper(10000, 10);
    return ();
}
