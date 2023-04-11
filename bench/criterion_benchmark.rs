use std::path::Path;

use cairo_vm::{
    cairo_run,
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    types::program::Program,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[cfg(feature = "with_mimalloc")]
use mimalloc::MiMalloc;

#[cfg(feature = "with_mimalloc")]
#[global_allocator]
static ALLOC: MiMalloc = MiMalloc;

const BENCH_NAMES: &[&str] = &[
    "compare_arrays_200000",
    "factorial_multirun",
    "fibonacci_1000_multirun",
    "integration_builtins",
    "linear_search",
    "keccak_integration_benchmark",
    "secp_integration_benchmark",
    "blake2s_integration_benchmark",
    "dict_integration_benchmark",
    "math_integration_benchmark",
    "memory_integration_benchmark",
    "math_cmp_and_pow_integration_benchmark",
    "operations_with_data_structures_benchmarks",
    "uint256_integration_benchmark",
    "set_integration_benchmark",
    "poseidon_integration_benchmark",
    "pedersen",
];
const BENCH_PATH: &str = "cairo_programs/benchmarks/";

pub fn criterion_benchmarks(c: &mut Criterion) {
    let mut hint_executor = BuiltinHintProcessor::new_empty();
    let cairo_run_config = cairo_vm::cairo_run::CairoRunConfig {
        layout: "all_cairo",
        ..cairo_vm::cairo_run::CairoRunConfig::default()
    };
    for benchmark_name in build_bench_strings() {
        let file_content = std::fs::read(Path::new(&benchmark_name.1)).unwrap();
        let program =
            Program::from_bytes(file_content.as_slice(), Some(cairo_run_config.entrypoint))
                .unwrap();
        c.bench_function(&benchmark_name.0, |b| {
            b.iter(|| {
                cairo_run::cairo_run(black_box(&program), &cairo_run_config, &mut hint_executor)
            })
        });
    }
}

fn build_bench_strings() -> Vec<(String, String)> {
    let mut full_string = Vec::<(String, String)>::new();

    for filename in BENCH_NAMES {
        let file_no_extension = String::from(*filename);
        let file_extension = String::from(".json");
        let bench_path = String::from(BENCH_PATH);
        let full_file_path = bench_path + &file_no_extension + &file_extension;
        let cairo_call = format!("cairo_run({})", &full_file_path);
        full_string.push((cairo_call, full_file_path));
    }

    full_string
}

criterion_group!(benches, criterion_benchmarks);
criterion_main!(benches);
