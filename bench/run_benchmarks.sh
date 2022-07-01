#!/usr/bin/env bash
tests_path="../cairo_programs"

set -e
echo "Cleaning old results"
rm -f results
rm -f $tests_path/*.json

pyenv global 3.7.12

echo "Building cleopatra ..."
cargo build --release

# Fibonacci Benchmarks

echo -e "\n*** fibonacci.cairo times ***" >> results

echo "Compiling Fibonacci cairo program"
cairo-compile $tests_path/fibonacci_1000_multirun.cairo --output $tests_path/fibonacci_1000_multirun.json

cleo_fibonacci_time=$( (time ../target/release/cleopatra-run $tests_path/fibonacci_1000_multirun.json) 2>&1 &)
echo -e "\nRust Cleopatra VM fibonacci.cairo:" >> results
echo "$cleo_fibonacci_time" >> results

cairo_fibonacci_time=$( (time cairo-run --program $tests_path/fibonacci_1000_multirun.json) 2>&1 &)
echo -e "\nOriginal Cairo VM fibonacci.cairo:" >> results
echo "$cairo_fibonacci_time" >> results

# Factorial Benchmarks

echo -e "\n*** factorial.cairo times ***" >> results

echo "Compiling factorial cairo program"
cairo-compile $tests_path/factorial.cairo --output $tests_path/factorial.json

cleo_factorial_time=$( (time ../target/release/cleopatra-run $tests_path/factorial.json) 2>&1 &)
echo -e "\nRust Cleopatra VM  factorial.cairo time:" >> results
echo "$cleo_factorial_time" >> results

cairo_factorial_time=$( (time cairo-run --program $tests_path/factorial.json) 2>&1 &)
echo -e "\nOriginal Cairo VM  factorial.cairo time:" >> results
echo "$cairo_factorial_time" >> results

# Integration Benchamarks

echo -e "\n*** integration_builtins.cairo times ***" >> results

echo "Compiling builtins integration cairo program"
cairo-compile integration_builtins.cairo --output $tests_path/integration_builtins.json

cleo_builtins_time=$( (time ../target/release/cleopatra-run $tests_path/integration_builtins.json) 2>&1 &)
echo -e "\nRust Cleopatra VM integration_builtins.cairo time:" >> results
echo "$cleo_builtins_time" >> results

cairo_builtins_time=$( (time cairo-run --program $tests_path/integration_builtins.json --layout=all) 2>&1 &)
echo -e "\nOriginal Cairo VM integration_builtins.cairo time:" >> results
echo "$cairo_builtins_time" >> results

pyenv global pypy3.7-7.3.9

cairo_pypy_builtins_time=$( (time cairo-run --program $tests_path/integration_builtins.json --layout=all) 2>&1 &)
echo -e "\nPyPy Original Cairo VM integration_builtins.cairo time:" >> results
echo "$cairo_pypy_builtins_time" >> results

# Alloc() Benchamarks

echo -e "\n*** compare_arrays.cairo times ***" >> results

echo "Compiling compare arrays cairo program"
cairo-compile $tests_path/compare_arrays.cairo --output $tests_path/compare_arrays.json

cleo_compare_arrays_time=$( (time ../target/release/cleopatra-run $tests_path/compare_arrays.json) 2>&1 &)
echo -e "\nRust Cleopatra VM compare_arrays.cairo time:" >> results
echo "$cleo_compare_arrays_time" >> results

cairo_pypy_compare_arrays_time=$( (time cairo-run --program $tests_path/compare_arrays.json) 2>&1 &)
echo -e "\nPyPy Original Cairo VM compare_arrays.cairo time:" >> results
echo "$cairo_pypy_compare_arrays_time" >> results

# Search Benchamarks

echo "Compiling linear search cairo program"
cairo-compile $tests_path/linear-search.cairo --output $tests_path/linear-search.json

cleo_search_time=$( (time ../target/release/cleopatra-run $tests_path/linear-search.json) 2>&1 &)
echo -e "\nRust Cleopatra VM linear search time:" >> results
echo "$cleo_search_time" >> results

cairo_search_time=$( (time cairo-run --program $tests_path/linear-search.json) 2>&1 &)
echo -e "\nPython Original Cairo VM time:" >> results
echo "$cairo_search_time" >> results

pyenv global pypy3.7-7.3.9

cairo_pypy_search_time=$( (time cairo-run --program $tests_path/linear-search.json) 2>&1 &)
echo -e "\nPyPy Original Cairo VM lineal search time:" >> results
echo "$cairo_pypy_search_time" >> results

cat results

echo "Cleaning results"
rm results
rm -f $tests_path/*.json
