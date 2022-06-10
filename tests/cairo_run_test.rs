use cleopatra_cairo::cairo_run;

#[test]
fn cairo_run_test() {
    cairo_run::cairo_run("tests/support/fibonacci_compiled.json");
}
