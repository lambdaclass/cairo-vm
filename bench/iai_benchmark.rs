use std::path::Path;

use cairo_vm::{
    cairo_run::cairo_run,
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    vm::errors::cairo_run_errors::CairoRunError, vm::runners::cairo_runner::CairoRunner,
    vm::vm_core::VirtualMachine,
};
use iai::{black_box, main};

macro_rules! iai_bench_expand_prog {
    ($val: ident) => {
        fn $val() -> Result<(CairoRunner, VirtualMachine), CairoRunError> {
            let cairo_run_config = cairo_vm::cairo_run::CairoRunConfig {
                layout: "all",
                ..cairo_vm::cairo_run::CairoRunConfig::default()
            };
            let mut hint_executor = BuiltinHintProcessor::new_empty();
            let path = Path::new(concat!(
                "cairo_programs/benchmarks/",
                stringify!($val),
                ".json"
            ));
            let program_content = std::fs::read(path).unwrap();
            cairo_run(
                black_box(&program_content),
                &cairo_run_config,
                &mut hint_executor,
            )
        }
    };
}

iai_bench_expand_prog! {math_integration_benchmark}
iai_bench_expand_prog! {compare_arrays_200000}
iai_bench_expand_prog! {factorial_multirun}
iai_bench_expand_prog! {fibonacci_1000_multirun}
iai_bench_expand_prog! {integration_builtins}
iai_bench_expand_prog! {linear_search}
iai_bench_expand_prog! {keccak_integration_benchmark}
iai_bench_expand_prog! {secp_integration_benchmark}
iai_bench_expand_prog! {blake2s_integration_benchmark}
iai_bench_expand_prog! {dict_integration_benchmark}
iai_bench_expand_prog! {memory_integration_benchmark}
iai_bench_expand_prog! {math_cmp_and_pow_integration_benchmark}
iai_bench_expand_prog! {operations_with_data_structures_benchmarks}
iai_bench_expand_prog! {uint256_integration_benchmark}
iai_bench_expand_prog! {set_integration_benchmark}

main!(
    math_integration_benchmark,
    compare_arrays_200000,
    factorial_multirun,
    fibonacci_1000_multirun,
    integration_builtins,
    linear_search,
    keccak_integration_benchmark,
    secp_integration_benchmark,
    blake2s_integration_benchmark,
    dict_integration_benchmark,
    memory_integration_benchmark,
    math_cmp_and_pow_integration_benchmark,
    operations_with_data_structures_benchmarks,
    uint256_integration_benchmark,
    set_integration_benchmark,
);
