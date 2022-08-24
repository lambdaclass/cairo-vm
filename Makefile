.PHONY: deps build run check test clippy coverage benchmark flamegraph compare_benchmarks_deps compare_benchmarks docs clean compare_vm_output

TEST_DIR=cairo_programs
TEST_FILES:=$(wildcard $(TEST_DIR)/*.cairo)
COMPILED_TESTS:=$(patsubst $(TEST_DIR)/%.cairo, $(TEST_DIR)/%.json, $(TEST_FILES))
CAIRO_MEM:=$(patsubst $(TEST_DIR)/%.json, $(TEST_DIR)/%.memory, $(COMPILED_TESTS))
CAIRO_TRACE:=$(patsubst $(TEST_DIR)/%.json, $(TEST_DIR)/%.trace, $(COMPILED_TESTS))
CAIRO_RS_MEM:=$(patsubst $(TEST_DIR)/%.json, $(TEST_DIR)/%.rs.memory, $(COMPILED_TESTS))
CAIRO_RS_TRACE:=$(patsubst $(TEST_DIR)/%.json, $(TEST_DIR)/%.rs.trace, $(COMPILED_TESTS))

BENCH_DIR=cairo_programs/benchmarks
BENCH_FILES:=$(wildcard $(BENCH_DIR)/*.cairo)
COMPILED_BENCHES:=$(patsubst $(BENCH_DIR)/%.cairo, $(BENCH_DIR)/%.json, $(BENCH_FILES))

BAD_TEST_DIR=cairo_programs/bad_programs
BAD_TEST_FILES:=$(wildcard $(BAD_TEST_DIR)/*.cairo)
COMPILED_BAD_TESTS:=$(patsubst $(BAD_TEST_DIR)/%.cairo, $(BAD_TEST_DIR)/%.json, $(BAD_TEST_FILES))

$(TEST_DIR)/%.json: $(TEST_DIR)/%.cairo
	cairo-compile --cairo_path="$(TEST_DIR):$(BENCH_DIR)" $< --output $@

$(TEST_DIR)/%.rs.memory: $(TEST_DIR)/%.json build
	./target/release/cairo-rs-run $< --memory_file $@

$(TEST_DIR)/%.rs.trace: $(TEST_DIR)/%.json build
	./target/release/cairo-rs-run $< --trace_file $@

$(TEST_DIR)/%.memory: $(TEST_DIR)/%.json
	cairo-run --layout all --program $< --memory_file $@

$(TEST_DIR)/%.trace: $(TEST_DIR)/%.json
	cairo-run --layout all --program $< --trace_file $@

$(BENCH_DIR)/%.json: $(BENCH_DIR)/%.cairo
	cairo-compile --cairo_path="$(TEST_DIR):$(BENCH_DIR)" $< --output $@

$(BAD_TEST_DIR)/%.json: $(BAD_TEST_DIR)/%.cairo
	cairo-compile $< --output $@
deps:
	cargo install --version 1.1.0 cargo-criterion
	cargo install --version 0.6.1 flamegraph
	cargo install --version 1.14.0 hyperfine
	pyenv install pypy3.7-7.3.9
	pyenv global pypy3.7-7.3.9
	pip install cairo_lang
	pyenv install 3.7.12
	pyenv global 3.7.12
	pip install cairo_lang

build:
	cargo build --release

run:
	cargo run

check:
	cargo check

test: $(COMPILED_TESTS) $(CAIRO_TRACE) $(CAIRO_MEM) $(COMPILED_BAD_TESTS)
	cargo test

clippy:
	cargo clippy  -- -D warnings

coverage:
	docker run --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin

benchmark: $(COMPILED_BENCHES)
	cargo criterion --bench criterion_benchmark
	@echo 'Report: target/criterion/reports/index.html'

benchmark-action: $(COMPILED_BENCHES)
	cargo bench --bench criterion_benchmark -- --output-format bencher |sed 1d | tee output.txt

flamegraph:
	cargo flamegraph --root --bench criterion_benchmark -- --bench

compare_benchmarks: $(COMPILED_BENCHES)
	cd bench && ./run_benchmarks.sh
 
compare_trace_memory: $(CAIRO_RS_TRACE) $(CAIRO_TRACE) $(CAIRO_RS_MEM) $(CAIRO_MEM)
	cd tests; ./compare_vm_state.sh trace memory

compare_trace: $(CAIRO_RS_TRACE) $(CAIRO_TRACE)
	cd tests; ./compare_vm_state.sh trace

compare_memory: $(CAIRO_RS_MEM) $(CAIRO_MEM)
	cd tests; ./compare_vm_state.sh memory

docs:
	cargo doc --verbose --release --locked --no-deps

clean:
	rm -f $(TEST_DIR)/*.json
	rm -f $(TEST_DIR)/*.memory
	rm -f $(TEST_DIR)/*.trace
	rm -f $(BENCH_DIR)/*.json
	rm -f $(BAD_TEST_DIR)/*.json
