use cleopatra_cairo::cairo_run;

#[test]
fn cairo_run_test() {
    cairo_run::cairo_run("tests/support/fibonacci_compiled.json");
}

#[test]
fn cairo_run_bitwise_output() {
    cairo_run::cairo_run("tests/support/bitwise_output.json");
}

#[test]
fn cairo_run_bitwise_recursion() {
    cairo_run::cairo_run("tests/support/bitwise_recursion.json");
}
