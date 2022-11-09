use std::path::Path;

use cairo_rs::{
    cairo_run::cairo_run,
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    vm::errors::cairo_run_errors::CairoRunError, vm::runners::cairo_runner::CairoRunner,
};
use iai::{black_box, main};

// TODO: expand_benchmark_program! macro
fn iai_benchmark_cairo_run(path: &Path) -> Result<CairoRunner, CairoRunError> {
    let hint_executor = BuiltinHintProcessor::new_empty();
    cairo_run(
        black_box(path),
        "main",
        false,
        false,
        "all",
        false,
        &hint_executor,
    )
}

fn iai_benchmark_math() -> Result<CairoRunner, CairoRunError> {
    iai_benchmark_cairo_run(Path::new(
        "cairo_programs/benchmarks/math_integration_benchmark.json",
    ))
}

fn iai_benchmark_compare_arrays_200000() -> Result<CairoRunner, CairoRunError> {
    iai_benchmark_cairo_run(Path::new(
        "cairo_programs/benchmarks/compare_arrays_200000.json",
    ))
}

fn iai_benchmark_factorial_multirun() -> Result<CairoRunner, CairoRunError> {
    iai_benchmark_cairo_run(Path::new(
        "cairo_programs/benchmarks/factorial_multirun.json",
    ))
}

fn iai_benchmark_fibonacci_1000_multirun() -> Result<CairoRunner, CairoRunError> {
    iai_benchmark_cairo_run(Path::new(
        "cairo_programs/benchmarks/fibonacci_1000_multirun.json",
    ))
}

fn iai_benchmark_integration_builtins() -> Result<CairoRunner, CairoRunError> {
    iai_benchmark_cairo_run(Path::new(
        "cairo_programs/benchmarks/integration_builtins.json",
    ))
}

fn iai_benchmark_linear_search() -> Result<CairoRunner, CairoRunError> {
    iai_benchmark_cairo_run(Path::new("cairo_programs/benchmarks/linear_search.json"))
}

fn iai_benchmark_keccak_integration_benchmark() -> Result<CairoRunner, CairoRunError> {
    iai_benchmark_cairo_run(Path::new(
        "cairo_programs/benchmarks/keccak_integration_benchmark.json",
    ))
}

fn iai_benchmark_secp_integration_benchmark() -> Result<CairoRunner, CairoRunError> {
    iai_benchmark_cairo_run(Path::new(
        "cairo_programs/benchmarks/secp_integration_benchmark.json",
    ))
}

fn iai_benchmark_blake2s_integration_benchmark() -> Result<CairoRunner, CairoRunError> {
    iai_benchmark_cairo_run(Path::new(
        "cairo_programs/benchmarks/blake2s_integration_benchmark.json",
    ))
}

fn iai_benchmark_dict_integration_benchmark() -> Result<CairoRunner, CairoRunError> {
    iai_benchmark_cairo_run(Path::new(
        "cairo_programs/benchmarks/dict_integration_benchmark.json",
    ))
}

fn iai_benchmark_memory_integration_benchmark() -> Result<CairoRunner, CairoRunError> {
    iai_benchmark_cairo_run(Path::new(
        "cairo_programs/benchmarks/memory_integration_benchmark.json",
    ))
}

fn iai_benchmark_math_cmp_and_pow_integration_benchmark() -> Result<CairoRunner, CairoRunError> {
    iai_benchmark_cairo_run(Path::new(
        "cairo_programs/benchmarks/math_cmp_and_pow_integration_benchmark.json",
    ))
}

fn iai_benchmark_operations_with_data_structures_benchmarks() -> Result<CairoRunner, CairoRunError>
{
    iai_benchmark_cairo_run(Path::new(
        "cairo_programs/benchmarks/operations_with_data_structures_benchmarks.json",
    ))
}

fn iai_benchmark_uint256_integration_benchmark() -> Result<CairoRunner, CairoRunError> {
    iai_benchmark_cairo_run(Path::new(
        "cairo_programs/benchmarks/uint256_integration_benchmark.json",
    ))
}

fn iai_benchmark_set_integration_benchmark() -> Result<CairoRunner, CairoRunError> {
    iai_benchmark_cairo_run(Path::new(
        "cairo_programs/benchmarks/set_integration_benchmark.json",
    ))
}

main!(
    iai_benchmark_math,
    iai_benchmark_compare_arrays_200000,
    iai_benchmark_factorial_multirun,
    iai_benchmark_fibonacci_1000_multirun,
    iai_benchmark_integration_builtins,
    iai_benchmark_linear_search,
    iai_benchmark_keccak_integration_benchmark,
    iai_benchmark_secp_integration_benchmark,
    iai_benchmark_blake2s_integration_benchmark,
    iai_benchmark_dict_integration_benchmark,
    iai_benchmark_memory_integration_benchmark,
    iai_benchmark_math_cmp_and_pow_integration_benchmark,
    iai_benchmark_operations_with_data_structures_benchmarks,
    iai_benchmark_uint256_integration_benchmark,
    iai_benchmark_set_integration_benchmark,
);
