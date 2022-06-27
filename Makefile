.PHONY: deps build run check test clippy coverage benchmark flamegraph compare_benchmarks_deps compare_benchmarks

deps:
	cargo install --version 1.1.0 cargo-criterion
	cargo install --version 0.6.1 flamegraph

build:
	cargo build --release

run: 
	cargo run

check:
	cargo check

test:
	cargo test

clippy:
	cargo clippy  -- -D warnings

coverage:
	docker run --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin

benchmark:
	cargo criterion --bench criterion_benchmark
	@echo 'Report: target/criterion/reports/index.html'

flamegraph:
	cargo flamegraph --root --bench criterion_benchmark -- --bench

compare_benchmarks_deps:
	pyenv install pypy3.7-7.3.9
	pyenv global pypy3.7-7.3.9
	pip install cairo_lang
	pyenv instal 3.7.12
	pyenv global 3.7.12
	pip install cairo_lang

compare_benchmarks:
	cd bench && ./run_benchmarks.sh

compare_traces:
	cd tests && ./compare_traces
