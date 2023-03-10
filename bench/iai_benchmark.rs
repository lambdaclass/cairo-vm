use std::path::Path;

use cairo_vm::{
    cairo_run::*,
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
};
use iai::{black_box, main};

macro_rules! iai_bench_expand_prog {
    ($val: ident) => {
        fn $val() {
            let cairo_run_config = cairo_vm::cairo_run::CairoRunConfig {
                trace_enabled: true,
                layout: "all",
                print_output: true,
                //FIXME: we need to distinguish the proof compiled programs
                //proof_mode: true,
                secure_run: Some(true),
                ..cairo_vm::cairo_run::CairoRunConfig::default()
            };
            let mut hint_executor = BuiltinHintProcessor::new_empty();
            let program_path = Path::new(concat!(
                "cairo_programs/benchmarks/",
                stringify!($val),
                ".json"
            ));
            let trace_path = Path::new("/dev/null");
            let memory_path = Path::new("/dev/null");

            let runner = cairo_run(
                black_box(program_path),
                &cairo_run_config,
                &mut hint_executor,
            )
            .expect("cairo_run failed");

            let relocated_trace = runner.relocated_trace.as_ref().expect("relocation failed");

            write_binary_trace(black_box(relocated_trace), black_box(&trace_path))
                .expect("writing execution trace failed");

            write_binary_memory(black_box(&runner.relocated_memory), black_box(&memory_path))
                .expect("writing relocated memory failed");
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
