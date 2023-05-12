use cairo_vm::{
    felt::Felt252,
    types::program::Program,
    utils::CAIRO_PRIME,
    vm::{
        runners::{builtin_runner::EcOpBuiltinRunner, cairo_runner::CairoRunner},
        vm_core::VirtualMachine,
    },
};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use num_bigint::BigInt;
use num_traits::One;

#[cfg(feature = "with_mimalloc")]
use mimalloc::MiMalloc;

#[cfg(feature = "with_mimalloc")]
#[global_allocator]
static ALLOC: MiMalloc = MiMalloc;

fn parse_program(c: &mut Criterion) {
    //Picked the biggest one at the time of writing
    let program = include_bytes!("../cairo_programs/benchmarks/keccak_integration_benchmark.json");
    c.bench_function("parse program", |b| {
        b.iter(|| {
            _ = Program::from_bytes(black_box(program.as_slice()), black_box(Some("main")))
                .unwrap();
        })
    });
}

fn build_many_runners(c: &mut Criterion) {
    //Picked the biggest one at the time of writing
    let program = include_bytes!("../cairo_programs/benchmarks/keccak_integration_benchmark.json");
    let program = Program::from_bytes(program.as_slice(), Some("main")).unwrap();
    c.bench_function("build runner", |b| {
        b.iter(|| {
            _ = black_box(
                CairoRunner::new(
                    black_box(&program),
                    black_box("starknet_with_keccak"),
                    black_box(false),
                )
                .unwrap(),
            );
        })
    });
}

fn load_program_data(c: &mut Criterion) {
    //Picked the biggest one at the time of writing
    let program = include_bytes!("../cairo_programs/benchmarks/keccak_integration_benchmark.json");
    let program = Program::from_bytes(program.as_slice(), Some("main")).unwrap();
    c.bench_function("initialize", |b| {
        b.iter_batched(
            || {
                (
                    CairoRunner::new(&program, "starknet_with_keccak", false).unwrap(),
                    VirtualMachine::new(false),
                )
            },
            |(mut runner, mut vm)| _ = black_box(runner.initialize(black_box(&mut vm)).unwrap()),
            BatchSize::SmallInput,
        )
    });
}

fn ec_op(c: &mut Criterion) {
    let partial_sum = (
        Felt252::parse_bytes(
            b"2962412995502985605007699495352191122971573493113767820301112397466445942584",
            10,
        )
        .unwrap(),
        Felt252::parse_bytes(
            b"214950771763870898744428659242275426967582168179217139798831865603966154129",
            10,
        )
        .unwrap(),
    );
    let doubled_point = (
        Felt252::parse_bytes(
            b"874739451078007766457464989774322083649278607533249481151382481072868806602",
            10,
        )
        .unwrap(),
        Felt252::parse_bytes(
            b"152666792071518830868575557812948353041420400780739481342941381225525861407",
            10,
        )
        .unwrap(),
    );
    let m = Felt252::new(34);
    let alpha = BigInt::one();
    let height = 256;
    let prime = (*CAIRO_PRIME).clone().into();
    c.bench_function("ec_op_impl", |b| {
        b.iter(|| {
            _ = black_box(EcOpBuiltinRunner::ec_op_impl(
                black_box(partial_sum.clone()),
                black_box(doubled_point.clone()),
                black_box(&m),
                black_box(&alpha),
                black_box(&prime),
                black_box(height),
            ));
        });
    });
}

criterion_group!(builtins, ec_op);
criterion_group!(runner, build_many_runners, load_program_data, parse_program);
criterion_main!(builtins, runner);
