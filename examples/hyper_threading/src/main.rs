use cairo_vm::{
    cairo_run::{cairo_run_program, CairoRunConfig},
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    types::program::Program,
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};

// #[derive(Debug, Error)]
// pub enum Error {
//     #[error("The cairo program execution failed")]
//     Runner(#[from] CairoRunError),
// }

// Define a macro to prepend a relative path to the file names
macro_rules! include_bytes_relative {
    ($fname:expr) => {
        include_bytes!(concat!("../../../cairo_programs/benchmarks/", $fname))
    };
}

fn main() {
    let _n_cpus = rayon::current_num_threads();

    let mut programs = Vec::new();
    // let program = include_bytes!("../cairo_programs/benchmarks/keccak_integration_benchmark.json");
    // let program = Program::from_bytes(program.as_slice(), Some("main")).unwrap();

    // dbg!(1);
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

    // dbg!(2);
    for bytes in &programs_bytes {
        programs.push(Program::from_bytes(bytes.as_slice(), Some("main")).unwrap())
    }
    // dbg!(3);
    let start_time = std::time::Instant::now();

    // for program in programs {
    //     let cairo_run_config = CairoRunConfig {
    //         entrypoint: "main",
    //         trace_enabled: false,
    //         relocate_mem: false,
    //         layout: "all_cairo",
    //         proof_mode: true,
    //         secure_run: Some(false),
    //         ..Default::default()
    //     };
    //     let mut hint_executor = BuiltinHintProcessor::new_empty();

    //     // TODO: Add error handling
    //     let _result = cairo_run_program(&program, &cairo_run_config, &mut hint_executor).expect("Couldn't run program");

    // }

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
        // dbg!(4);
        let _result = cairo_run_program(&program, &cairo_run_config, &mut hint_executor)
            .expect("Couldn't run program");
        // dbg!(5);
    });
    let elapsed = start_time.elapsed();
    let x = &programs_bytes.clone().len();

    // dbg!(6);
    // dbg!(elapsed);

    // TODO: Remove this tracing?
    tracing::info!(%x, ?elapsed, "Finished");
}
