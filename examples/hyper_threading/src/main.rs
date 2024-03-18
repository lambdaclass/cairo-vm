use cairo_vm::{
    cairo_run::{cairo_run, CairoRunConfig},
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};

// Define a macro to prepend a relative path to the file names
macro_rules! include_bytes_relative {
    ($fname:expr) => {
        include_bytes!(concat!("../../../cairo_programs/benchmarks/", $fname))
    };
}

fn main() {
    let programs_bytes: [Vec<u8>; 18] = [
        include_bytes_relative!("big_factorial.json").to_vec(),
        include_bytes_relative!("big_fibonacci.json").to_vec(),
        include_bytes_relative!("blake2s_integration_benchmark.json").to_vec(),
        include_bytes_relative!("compare_arrays_200000.json").to_vec(),
        include_bytes_relative!("dict_integration_benchmark.json").to_vec(),
        include_bytes_relative!("field_arithmetic_get_square_benchmark.json").to_vec(),
        include_bytes_relative!("integration_builtins.json").to_vec(),
        include_bytes_relative!("keccak_integration_benchmark.json").to_vec(),
        include_bytes_relative!("linear_search.json").to_vec(),
        include_bytes_relative!("math_cmp_and_pow_integration_benchmark.json").to_vec(),
        include_bytes_relative!("math_integration_benchmark.json").to_vec(),
        include_bytes_relative!("memory_integration_benchmark.json").to_vec(),
        include_bytes_relative!("operations_with_data_structures_benchmarks.json").to_vec(),
        include_bytes_relative!("pedersen.json").to_vec(),
        include_bytes_relative!("poseidon_integration_benchmark.json").to_vec(),
        include_bytes_relative!("secp_integration_benchmark.json").to_vec(),
        include_bytes_relative!("set_integration_benchmark.json").to_vec(),
        include_bytes_relative!("uint256_integration_benchmark.json").to_vec(),
    ];

    let start_time = std::time::Instant::now();

    programs_bytes.into_par_iter().for_each(|program| {
        let cairo_run_config = CairoRunConfig {
            entrypoint: "main",
            trace_enabled: false,
            relocate_mem: false,
            layout: "all_cairo",
            proof_mode: true,
            secure_run: Some(false),
            ..Default::default()
        };
        let mut hint_executor = BuiltinHintProcessor::new_empty();

        let _result = cairo_run(&program, &cairo_run_config, &mut hint_executor)
            .expect("Couldn't run program");
    });
    let _elapsed = start_time.elapsed();
}
