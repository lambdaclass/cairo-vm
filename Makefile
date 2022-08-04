# Comment to just trigger the workflow for timing
.PHONY: deps build run check test clippy coverage coverage-generic benchmark flamegraph compare_benchmarks_deps compare_benchmarks docs clean compare_vm_output

TEST_DIR=cairo_programs
TEST_FILES:=$(wildcard $(TEST_DIR)/*.cairo)
COMPILED_TESTS:=$(patsubst $(TEST_DIR)/%.cairo, $(TEST_DIR)/%.json, $(TEST_FILES))
CAIRO_MEM:=$(patsubst $(TEST_DIR)/%.json, $(TEST_DIR)/%.memory, $(COMPILED_TESTS))
CAIRO_TRACE:=$(patsubst $(TEST_DIR)/%.json, $(TEST_DIR)/%.trace, $(COMPILED_TESTS))
CLEO_MEM:=$(patsubst $(TEST_DIR)/%.json, $(TEST_DIR)/%.cleopatra.memory, $(COMPILED_TESTS))
CLEO_TRACE:=$(patsubst $(TEST_DIR)/%.json, $(TEST_DIR)/%.cleopatra.trace, $(COMPILED_TESTS))

BENCH_DIR=cairo_programs/benchmarks
BENCH_FILES:=$(wildcard $(BENCH_DIR)/*.cairo)
COMPILED_BENCHES:=$(patsubst $(BENCH_DIR)/%.cairo, $(BENCH_DIR)/%.json, $(BENCH_FILES))

BAD_TEST_DIR=cairo_programs/bad_programs
BAD_TEST_FILES:=$(wildcard $(BAD_TEST_DIR)/*.cairo)
COMPILED_BAD_TESTS:=$(patsubst $(BAD_TEST_DIR)/%.cairo, $(BAD_TEST_DIR)/%.json, $(BAD_TEST_FILES))

$(TEST_DIR)/%.json: $(TEST_DIR)/%.cairo
	PYENV_VERSION=pypy3.7-7.3.9 cairo-compile --cairo_path="$(TEST_DIR):$(BENCH_DIR)" $< --output $@

# NOTE: '<target1> <target2> &' syntax was introduced in GNU Make 4.3.
# It groups targets in a way that makes the recipe run exactly once if any or
# several of the targets need updating.
# The '$(@:OLD_SUFFIX=NEW_SUFFIX)' is needed because there's no way to
# distinguish which target triggered the rule.
$(TEST_DIR)/%.cleopatra.memory $(TEST_DIR)/%.cleopatra.trace &: $(TEST_DIR)/%.json
	cargo run $< --memory_file $(@:trace=memory) --trace_file $(@:memory=trace)

$(TEST_DIR)/%.memory $(TEST_DIR)/%.trace &: $(TEST_DIR)/%.json
	PYENV_VERSION=pypy3.7-7.3.9 cairo-run --layout all --program $< --memory_file $(@:trace=memory) --trace_file $(@:memory=trace)

$(BENCH_DIR)/%.json: $(BENCH_DIR)/%.cairo
	PYENV_VERSION=pypy3.7-7.3.9 cairo-compile --cairo_path="$(TEST_DIR):$(BENCH_DIR)" $< --output $@

$(BAD_TEST_DIR)/%.json: $(BAD_TEST_DIR)/%.cairo
	PYENV_VERSION=pypy3.7-7.3.9 cairo-compile --cairo_path="$(TEST_DIR):$(BENCH_DIR)" $< --output $@

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

# Because tarpaulin only supports Linux we need this for other platforms
coverage-generic:
	docker run --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin

coverage: $(COMPILED_TESTS) $(COMPILED_BAD_TESTS)
	cargo tarpaulin

benchmark: $(COMPILED_BENCHES)
	cargo criterion --bench criterion_benchmark
	@echo 'Report: target/criterion/reports/index.html'

benchmark-action: $(COMPILED_BENCHES)
	cargo +nightly bench --bench criterion_benchmark -- --output-format bencher |sed 1d | tee output.txt

flamegraph: $(COMPILED_BENCHES)
	cargo flamegraph --root --bench criterion_benchmark -- --bench

compare_benchmarks: $(COMPILED_BENCHES)
	cd bench && ./run_benchmarks.sh
 
compare_trace_memory: $(CLEO_TRACE) $(CAIRO_TRACE) $(CLEO_MEM) $(CAIRO_MEM)
	cd tests; ./compare_vm_state.sh trace memory

compare_trace: $(CLEO_TRACE) $(CAIRO_TRACE)
	cd tests; ./compare_vm_state.sh trace

compare_memory: $(CLEO_MEM) $(CAIRO_MEM)
	cd tests; ./compare_vm_state.sh memory

docs:
	cargo doc --verbose --release --locked --no-deps

clean:
	rm -f $(TEST_DIR)/*.json
	rm -f $(TEST_DIR)/*.memory
	rm -f $(TEST_DIR)/*.trace
	rm -f $(BENCH_DIR)/*.json
	rm -f $(BAD_TEST_DIR)/*.json
