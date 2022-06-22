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

#[test]
fn cairo_run_integration() {
    cairo_run::cairo_run("tests/support/integration.json");
}

#[test]
fn cairo_run_integration_with_alloc_locals() {
    cairo_run::cairo_run("tests/support/integration_with_alloc_locals.json");
}
