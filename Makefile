.PHONY: deps build run check test clippy coverage benchmark flamegraph compare_benchmarks_deps compare_benchmarks clean
TEST_DIR=cairo_programs
TEST_FILES:=$(wildcard $(TEST_DIR)/*.cairo)
COMPILED_TESTS:=$(patsubst $(TEST_DIR)/%.cairo, $(TEST_DIR)/%.json, $(TEST_FILES))
CAIRO_MEM:=$(patsubst $(TEST_DIR)/%.json, $(TEST_DIR)/%.memory, $(COMPILED_TESTS))
CAIRO_TRACE:=$(patsubst $(TEST_DIR)/%.json, $(TEST_DIR)/%.trace, $(COMPILED_TESTS))
CLEO_MEM:=$(patsubst $(TEST_DIR)/%.json, $(TEST_DIR)/%.cleopatra.memory, $(COMPILED_TESTS))
CLEO_TRACE:=$(patsubst $(TEST_DIR)/%.json, $(TEST_DIR)/%.cleopatra.trace, $(COMPILED_TESTS))

$(TEST_DIR)/%.json: $(TEST_DIR)/%.cairo
	cairo-compile $< --output $@

$(TEST_DIR)/%.cleopatra.memory: $(TEST_DIR)/%.json build
	./target/release/cleopatra-run $< --memory_file $@

$(TEST_DIR)/%.cleopatra.trace: $(TEST_DIR)/%.json build
	./target/release/cleopatra-run $< --trace_file $@

$(TEST_DIR)/%.memory: $(TEST_DIR)/%.json
	cairo-run --layout all --program $< --memory_file $@

$(TEST_DIR)/%.trace: $(TEST_DIR)/%.json
	cairo-run --layout all --program $< --trace_file $@
deps:
	cargo install --version 1.1.0 cargo-criterion
	cargo install --version 0.6.1 flamegraph

build:
	cargo build --release

run: 
	cargo run

check:
	cargo check

test: $(COMPILED_TESTS) $(CAIRO_TRACE) $(CAIRO_MEM)
	cargo test

clippy:
	cargo clippy  -- -D warnings

coverage:
	docker run --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin

benchmark:
	cd bench/criterion; ./setup_benchmarks.sh
	cargo criterion --bench criterion_benchmark
	@echo 'Report: target/criterion/reports/index.html'

flamegraph:
	cargo flamegraph --root --bench criterion_benchmark -- --bench

compare_benchmarks_deps:
	pyenv install pypy3.7-7.3.9
	pyenv global pypy3.7-7.3.9
	pip install cairo_lang
	pyenv install 3.7.12
	pyenv global 3.7.12
	pip install cairo_lang

compare_benchmarks:
	cd bench && ./run_benchmarks.sh

compare_traces:
	cd tests; ./compare_traces.sh

clean:
	rm -f $(TEST_DIR)/*.json
	rm -f $(TEST_DIR)/*.memory
	rm -f $(TEST_DIR)/*.trace
