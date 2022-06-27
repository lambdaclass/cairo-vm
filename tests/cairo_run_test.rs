use std::path::Path;

use cleopatra_cairo::cairo_run;

#[test]
fn cairo_run_test() {
    cairo_run::cairo_run(Path::new("cairo_programs/fibonacci.json")).expect("Couldn't run program");
}

#[test]
fn cairo_run_bitwise_output() {
    cairo_run::cairo_run(Path::new("cairo_programs/bitwise_output.json"))
        .expect("Couldn't run program");
}

#[test]
fn cairo_run_bitwise_recursion() {
    cairo_run::cairo_run(Path::new("cairo_programs/bitwise_recursion.json"))
        .expect("Couldn't run program");
}

#[test]
fn cairo_run_integration() {
    cairo_run::cairo_run(Path::new("cairo_programs/integration.json"))
        .expect("Couldn't run program");
}

#[test]
fn cairo_run_integration_with_alloc_locals() {
    cairo_run::cairo_run(Path::new(
        "cairo_programs/integration_with_alloc_locals.json",
    ))
    .expect("Couldn't run program");
}
