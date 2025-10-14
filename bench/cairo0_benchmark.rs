use cairo_vm::{
    cairo_run::{cairo_run, CairoRunConfig},
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    types::layout_name::LayoutName,
};
use criterion::{criterion_group, criterion_main, Criterion};

fn repeat_hint_cairo0(c: &mut Criterion) {
    let program = include_bytes!("../cairo_programs/benchmarks/repeated_hint_cairo0.json");
    let mut hint_processor = BuiltinHintProcessor::new_empty();
    c.bench_function("repeat hint cairo 0", |b| {
        b.iter(|| {
            let _ = cairo_run(
                program,
                &CairoRunConfig {
                    layout: LayoutName::all_cairo,
                    ..Default::default()
                },
                &mut hint_processor,
            );
        });
    });
}

fn repeat_hint(c: &mut Criterion) {
    let program = include_bytes!("../cairo_programs/benchmarks/repeated_hint.json");
    let mut hint_processor = BuiltinHintProcessor::new_empty();
    c.bench_function("repeat hint", |b| {
        b.iter(|| {
            let _ = cairo_run(
                program,
                &CairoRunConfig {
                    layout: LayoutName::all_cairo,
                    ..Default::default()
                },
                &mut hint_processor,
            );
        });
    });
}

criterion_group!(runner, repeat_hint_cairo0, repeat_hint);
criterion_main!(runner);
