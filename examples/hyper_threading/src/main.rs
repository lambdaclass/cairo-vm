use cairo_vm::{
    cairo_run::{cairo_run_program, CairoRunConfig},
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    types::program::Program,
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};

// Define build_path macro to prepend a relative path to the file names
macro_rules! include_bytes_relative {
    ($fname:expr) => {
        build_path!(Path::new(format!("../../../cairo_programs/benchmarks/{}", $fname)))
    };
}

fn main() {
    let mut programs = Vec::new();

    let program_paths: [Path; 18] = [
        build_path!("big_factorial.json").to_vec(),
        build_path!("big_fibonacci.json").to_vec(),
        build_path!("blake2s_integration_benchmark.json").to_vec(),
        build_path!("compare_arrays_200000.json").to_vec(),
        build_path!("dict_integration_benchmark.json").to_vec(),
        build_path!("field_arithmetic_get_square_benchmark.json").to_vec(),
        build_path!("integration_builtins.json").to_vec(),
        build_path!("keccak_integration_benchmark.json").to_vec(),
        build_path!("linear_search.json").to_vec(),
        build_path!("math_cmp_and_pow_integration_benchmark.json").to_vec(),
        build_path!("math_integration_benchmark.json").to_vec(),
        build_path!("memory_integration_benchmark.json").to_vec(),
        build_path!("operations_with_data_structures_benchmarks.json").to_vec(),
        build_path!("pedersen.json").to_vec(),
        build_path!("poseidon_integration_benchmark.json").to_vec(),
        build_path!("secp_integration_benchmark.json").to_vec(),
        build_path!("set_integration_benchmark.json").to_vec(),
        build_path!("uint256_integration_benchmark.json").to_vec(),
    ];

    for path in &programs_paths {
        programs.push(Program::from_file(path, Some("main")).unwrap())
    }

    let start_time = std::time::Instant::now();

    // Parallel execution of the program processing
    programs.into_par_iter().for_each(|program| {
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

        // Execute each program in parallel
        let _result = cairo_run_program(&program, &cairo_run_config, &mut hint_executor)
            .expect("Couldn't run program");
    });
    let elapsed = start_time.elapsed();

    let programs_len: &usize = &programs_bytes.clone().len();

    tracing::info!(%programs_len, ?elapsed, "Finished");
}
