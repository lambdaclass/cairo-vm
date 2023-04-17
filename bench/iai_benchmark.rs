use std::{
    fs::File,
    io,
    io::{BufWriter, Write},
};

use bincode::enc::write::Writer;
use iai::{black_box, main};

use cairo_vm::{
    cairo_run::*,
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    types::program::Program, vm::runners::cairo_runner::CairoRunner,
};

// Copied from the CLI
struct FileWriter {
    buf_writer: BufWriter<File>,
    bytes_written: usize,
}

impl Writer for FileWriter {
    fn write(&mut self, bytes: &[u8]) -> Result<(), bincode::error::EncodeError> {
        self.buf_writer
            .write_all(bytes)
            .map_err(|e| bincode::error::EncodeError::Io {
                inner: e,
                index: self.bytes_written,
            })?;

        self.bytes_written += bytes.len();

        Ok(())
    }
}

impl FileWriter {
    fn new(buf_writer: BufWriter<File>) -> Self {
        Self {
            buf_writer,
            bytes_written: 0,
        }
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.buf_writer.flush()
    }
}

#[cfg(feature = "with_mimalloc")]
use mimalloc::MiMalloc;

#[cfg(feature = "with_mimalloc")]
#[global_allocator]
static ALLOC: MiMalloc = MiMalloc;

macro_rules! iai_bench_expand_prog {
    ($val: ident) => {
        fn $val() {
            let cairo_run_config = cairo_vm::cairo_run::CairoRunConfig {
                trace_enabled: true,
                layout: "all_cairo",
                //FIXME: we need to distinguish the proof compiled programs
                //proof_mode: true,
                secure_run: Some(true),
                ..cairo_vm::cairo_run::CairoRunConfig::default()
            };
            let mut hint_executor = BuiltinHintProcessor::new_empty();

            let program = include_bytes!(concat!(
                "../cairo_programs/benchmarks/",
                stringify!($val),
                ".json"
            ));
            let (runner, mut vm) =
                cairo_run(black_box(program), &cairo_run_config, &mut hint_executor)
                    .expect("cairo_run failed");

            let trace_file = File::create("/dev/null").expect("open trace file");
            let mut trace_writer = FileWriter::new(BufWriter::new(trace_file));
            let relocated_trace = vm.get_relocated_trace().expect("relocation failed");
            write_encoded_trace(
                black_box(relocated_trace.as_slice()),
                black_box(&mut trace_writer),
            )
            .expect("writing execution trace failed");
            trace_writer.flush().expect("flush trace");

            let memory_file = File::create("/dev/null").expect("open memory file");
            let mut memory_writer = FileWriter::new(BufWriter::new(memory_file));
            write_encoded_memory(
                black_box(&runner.relocated_memory),
                black_box(&mut memory_writer),
            )
            .expect("writing relocated memory failed");
            memory_writer.flush().expect("flush memory");

            vm.write_output(black_box(&mut String::new()))
                .expect("writing output failed");
        }
    };
}

fn parse_program() {
    //Picked the biggest one at the time of writing
    let program = include_bytes!("../cairo_programs/benchmarks/keccak_integration_benchmark.json");
    let program =
        Program::from_bytes(black_box(program.as_slice()), black_box(Some("main"))).unwrap();
    let _ = black_box(program);
}

fn build_many_runners() {
    //Picked the biggest one at the time of writing
    let program = include_bytes!("../cairo_programs/benchmarks/keccak_integration_benchmark.json");
    let program =
        Program::from_bytes(black_box(program.as_slice()), black_box(Some("main"))).unwrap();
    for _ in 0..100 {
        let runner = CairoRunner::new(black_box(&program), "starknet_with_keccak", false).unwrap();
        let _ = black_box(runner);
    }
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
iai_bench_expand_prog! {poseidon_integration_benchmark}
iai_bench_expand_prog! {pedersen}

main!(
    parse_program,
    build_many_runners,
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
    poseidon_integration_benchmark,
    pedersen,
);
