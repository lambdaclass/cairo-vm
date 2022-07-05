#!/bin/bash
set -e
echo "Cleaning old results"
rm -f results
rm -f *.json

pyenv global 3.7.12

echo "Building cleopatra ..."
cargo build --release

# Fibonacci Benchmarks

echo -e "\n*** fibonacci.cairo times ***" >> results

echo "Compiling fibonacci cairo program"
cairo-compile fibonacci.cairo --output fibonacci.json

pyenv global 3.7.12

cairo_fibonacci_time=$( (time cairo-run --program fibonacci.json) 2>&1 &)
echo -e "\nOriginal Cairo VM fibonacci.cairo:" >> results
echo "$cairo_fibonacci_time" >> results

pyenv global pypy3.7-7.3.9

cairo_pypy_fibonacci_time=$( (time cairo-run --program fibonacci.json) 2>&1 &)
echo -e "\nPyPy Cairo VM fibonacci.cairo:" >> results
echo "$cairo_pypy_fibonacci_time" >> results

pyenv global 3.7.12

cleo_fibonacci_time=$( (time ../target/release/cleopatra-run fibonacci.json) 2>&1 &)
echo -e "\nRust Cleopatra VM fibonacci.cairo:" >> results
echo "$cleo_fibonacci_time" >> results

# Factorial Benchmarks

echo -e "\n*** factorial.cairo times ***" >> results

echo "Compiling factorial cairo program"
cairo-compile factorial.cairo --output factorial.json

pyenv global 3.7.12

cairo_factorial_time=$( (time cairo-run --program factorial.json) 2>&1 &)
echo -e "\nPyPy Cairo VM  factorial.cairo time:" >> results
echo "$cairo_factorial_time" >> results

pyenv global pypy3.7-7.3.9

cairo_pypy_factorial_time=$( (time cairo-run --program factorial.json) 2>&1 &)
echo -e "\nOriginal Cairo VM  factorial.cairo time:" >> results
echo "$cairo_pypy_factorial_time" >> results

pyenv global 3.7.12

cleo_factorial_time=$( (time ../target/release/cleopatra-run factorial.json) 2>&1 &)
echo -e "\nRust Cleopatra VM  factorial.cairo time:" >> results
echo "$cleo_factorial_time" >> results

# Integration Benchamarks

echo -e "\n*** integration_builtins.cairo times ***" >> results

echo "Compiling builtins integration cairo program"
cairo-compile integration_builtins.cairo --output integration_builtins.json

pyenv global 3.7.12

cairo_builtins_time=$( (time cairo-run --program integration_builtins.json --layout=all) 2>&1 &)
echo -e "\nOriginal Cairo VM integration_builtins.cairo time:" >> results
echo "$cairo_builtins_time" >> results

pyenv global pypy3.7-7.3.9

cairo_pypy_builtins_time=$( (time cairo-run --program integration_builtins.json --layout=all) 2>&1 &)
echo -e "\nPyPy Original Cairo VM integration_builtins.cairo time:" >> results
echo "$cairo_pypy_builtins_time" >> results

pyenv global 3.7.12

cleo_builtins_time=$( (time ../target/release/cleopatra-run integration_builtins.json) 2>&1 &)
echo -e "\nRust Cleopatra VM integration_builtins.cairo time:" >> results
echo "$cleo_builtins_time" >> results

# Alloc() Benchamarks

echo -e "\n*** compare_arrays.cairo times ***" >> results

echo "Compiling compare arrays cairo program"
cairo-compile compare_arrays.cairo --output compare_arrays.json

pyenv global 3.7.12

cairo_compare_arrays_time=$( (time cairo-run --program compare_arrays.json) 2>&1 &)
echo -e "\nOriginal Cairo VM compare_arrays.cairo time:" >> results
echo "$cairo_compare_arrays_time" >> results

pyenv global pypy3.7-7.3.9

cairo_pypy_compare_arrays_time=$( (time cairo-run --program compare_arrays.json) 2>&1 &)
echo -e "\nPyPy Cairo VM compare_arrays.cairo time:" >> results
echo "$cairo_pypy_compare_arrays_time" >> results

pyenv global 3.7.12

cleo_compare_arrays_time=$( (time ../target/release/cleopatra-run compare_arrays.json) 2>&1 &)
echo -e "\nRust Cleopatra VM compare_arrays.cairo time:" >> results
echo "$cleo_compare_arrays_time" >> results

# Search Benchamarks

echo -e "\n*** linear-search.cairo times ***" >> results

echo "Compiling linear search cairo program"
cairo-compile ../cairo_programs/linear-search.cairo --output linear-search.json

pyenv global 3.7.12

cairo_search_time=$( (time cairo-run --program linear-search.json) 2>&1 &)
echo -e "\nPython Original Cairo VM time:" >> results
echo "$cairo_search_time" >> results

pyenv global pypy3.7-7.3.9

cairo_pypy_search_time=$( (time cairo-run --program linear-search.json) 2>&1 &)
echo -e "\nPyPy Original Cairo VM lineal search time:" >> results
echo "$cairo_pypy_search_time" >> results

pyenv global 3.7.12

cleo_search_time=$( (time ../target/release/cleopatra-run linear-search.json) 2>&1 &)
echo -e "\nRust Cleopatra VM linear search time:" >> results
echo "$cleo_search_time" >> results

cat results

echo "Cleaning results"

rm results
rm -f *.json
