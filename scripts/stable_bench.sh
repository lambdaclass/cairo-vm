#!/bin/sh

set -e

ROOT_DIR=.
TARGET_DIR=${ROOT_DIR}/target/stable_bench
BENCHMARK_DIR=${ROOT_DIR}/cairo_programs/benchmarks
PROGRAM="$1"

mkdir -p ${TARGET_DIR}
find $TARGET_DIR -name 'cachegrind.out.*' -execdir mv '{}' '{}'.old ';'
find $BENCHMARK_DIR -name '*.json' -execdir basename -s .json '{}' '+' | \
	xargs -I '{input}' -P $(nproc) -n 1 \
	valgrind --tool=cachegrind --cachegrind-out-file=$TARGET_DIR/'cachegrind.out.{input}'\
	--D1=$((32*1024)),8,64 --I1=$((32*1024)),8,64 --LL=$((8*1024*1024)),16,64 \
	./target/release/cairo-rs-run --layout all --memory_file /dev/null --trace_file /dev/null $BENCHMARK_DIR/'{input}'.json > /dev/null
find $TARGET_DIR -name 'cachegrind.out.*' ! -name '*.old' -exec ${ROOT_DIR}/scripts/regression_check.py '{}' '{}'.old ';'
