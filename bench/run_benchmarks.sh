#!/bin/bash
set -e
echo "Cleaning old results"
rm -f results
rm -f fibonacci.json
rm -f factorial.json
rm -f integration_builtins.json
rm -rf oriac
rm -f .python-version

pyenv global 3.7.12

echo "Building cleopatra ..."
cargo build --release

# Fibonacci Benchmarks

echo "Compiling Fibonacci cairo program"
cairo-compile fibonacci.cairo --output fibonacci.json

cleo_fibonacci_time=$( (time ../target/release/cleopatra-run fibonacci.json) 2>&1 &)
echo "Rust Cleopatra VM Fibonacci time:" >> results
echo "$cleo_fibonacci_time" >> results

echo "Building oriac ..."
git clone https://github.com/xJonathanLEI/oriac.git
cargo build --release --manifest-path oriac/Cargo.toml

oriac_fibonacci_time=$( (time oriac/target/release/oriac-run --program fibonacci.json) 2>&1 &)
echo -e "\nOriac VM Fibonacci time:" >> results
echo "$oriac_fibonacci_time" >> results

cairo_fibonacci_time=$( (time cairo-run --program fibonacci.json) 2>&1 &)
echo -e "\nOriginal Cairo VM Fibonacci time:" >> results
echo "$cairo_fibonacci_time" >> results

# Factorial Benchmarks

echo "Compiling factorial cairo program"
cairo-compile factorial.cairo --output factorial.json

cleo_factorial_time=$( (time ../target/release/cleopatra-run factorial.json) 2>&1 &)
echo -e "\nRust Cleopatra VM factorial time:" >> results
echo "$cleo_factorial_time" >> results

oriac_factorial_time=$( (time oriac/target/release/oriac-run --program factorial.json) 2>&1 &)
echo -e "\nOriac VM factorial time:" >> results
echo "$oriac_factorial_time" >> results

cairo_factorial_time=$( (time cairo-run --program factorial.json) 2>&1 &)
echo -e "\nOriginal Cairo VM factorial time:" >> results
echo "$cairo_factorial_time" >> results

# Integration Benchamarks

echo "Compiling builtins integration cairo program"
cairo-compile integration_builtins.cairo --output integration_builtins.json

cleo_builtins_time=$( (time ../target/release/cleopatra-run integration_builtins.json) 2>&1 &)
echo -e "\nRust Cleopatra VM builtins integration time:" >> results
echo "$cleo_builtins_time" >> results

pyenv global 3.7.12

cairo_factorial_time=$( (time cairo-run --program factorial.json) 2>&1 &)
echo -e "\nPython Original Cairo VM time:" >> results
echo "$cairo_factorial_time" >> results

pyenv global pypy3.7-7.3.9

cairo_pypy_factorial_time=$( (time cairo-run --program factorial.json) 2>&1 &)
echo -e "\nPyPy Original Cairo VM factorial time:" >> results
echo "$cairo_pypy_factorial_time" >> results

cat results

echo "Cleaning results"
rm results
rm -f fibonacci.json
rm -f factorial.json
rm -f integration_builtins.json
rm -rf oriac
rm -f .python-version
