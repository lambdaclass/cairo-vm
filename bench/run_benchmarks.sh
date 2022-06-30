#!/bin/bash
set -e
echo "Cleaning old results"
rm -f results
rm -f fibonacci.json
rm -f integration_builtins.json
rm -f compare_arrays.json

pyenv global 3.7.12

echo "Building cleopatra ..."
cargo build --release

# Fibonacci Benchmarks

echo -e "\n*** fibonacci.cairo times ***\n" >> results

echo "Compiling Fibonacci cairo program"
cairo-compile fibonacci.cairo --output fibonacci.json

cleo_fibonacci_time=$( (time ../target/release/cleopatra-run fibonacci.json) 2>&1 &)
echo -e "\nRust Cleopatra VM fibonacci.cairo:" >> results
echo "$cleo_fibonacci_time" >> results

cairo_fibonacci_time=$( (time cairo-run --program fibonacci.json) 2>&1 &)
echo -e "\nOriginal Cairo VM fibonacci.cairo:" >> results
echo "$cairo_fibonacci_time" >> results

# Integration Benchamarks

echo -e "\n*** integration_builtins.cairo times ***\n" >> results

echo "Compiling builtins integration cairo program"
cairo-compile integration_builtins.cairo --output integration_builtins.json

cleo_builtins_time=$( (time ../target/release/cleopatra-run integration_builtins.json) 2>&1 &)
echo -e "\nRust Cleopatra VM integration_builtins.cairo time:" >> results
echo "$cleo_builtins_time" >> results

cairo_builtins_time=$( (time cairo-run --program integration_builtins.json --layout=all) 2>&1 &)
echo -e "\nOriginal Cairo VM integration_builtins.cairo time:" >> results
echo "$cairo_builtins_time" >> results

pyenv global pypy3.7-7.3.9

cairo_pypy_builtins_time=$( (time cairo-run --program integration_builtins.json --layout=all) 2>&1 &)
echo -e "\nPyPy Original Cairo VM integration_builtins.cairo time:" >> results
echo "$cairo_pypy_builtins_time" >> results

# Alloc() Benchamarks

echo -e "\n*** compare_arrays.cairo times ***\n" >> results

echo "Compiling compare arrays cairo program"
cairo-compile compare_arrays.cairo --output compare_arrays.json

cleo_compare_arrays_time=$( (time ../target/release/cleopatra-run compare_arrays.json) 2>&1 &)
echo -e "\nRust Cleopatra VM compare_arrays.cairo time:" >> results
echo "$cleo_compare_arrays_time" >> results

cairo_pypy_compare_arrays_time=$( (time cairo-run --program compare_arrays.json) 2>&1 &)
echo -e "\nPyPy Original Cairo VM compare_arrays.cairo time:" >> results
echo "$cairo_pypy_compare_arrays_time" >> results

cat results

echo "Cleaning results"
rm results
rm -f fibonacci.json
rm -f compare_arrays.json
rm -f integration_builtins.json
