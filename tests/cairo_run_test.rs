use std::path::Path;

use cleopatra_cairo::cairo_run;

#[test]
fn cairo_run_test() {
    cairo_run::cairo_run(Path::new("tests/support/fibonacci_compiled.json"), None)
        .expect("Couldn't run program");
}
