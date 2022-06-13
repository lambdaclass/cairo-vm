#!/bin/bash
set -e

# Setup
echo "Cleaning old results"
rm -f results
rm -f fibonacci.json
rm -f factorial.json
rm -rf oriac

echo "Building Cleopatra"
cargo build --release

# Fibonacci
echo "Compiling Fibonacci cairo program"
cairo-compile fibonacci.cairo --output fibonacci.json

echo -e "* Fibonacci *\n" >> results
cleo_fibonacci_time=$( (time ../target/release/cleopatra-run fibonacci.json) 2>&1 &)
echo "Rust Cleopatra VM time:" >> results
echo "$cleo_fibonacci_time" >> results

echo "Building oriac ..."
git clone https://github.com/xJonathanLEI/oriac.git
cargo build --release --manifest-path oriac/Cargo.toml

oriac_fibonacci_time=$( (time oriac/target/release/oriac-run --program fibonacci.json) 2>&1 &)
echo -e "\nOriac VM Fibonacci time:" >> results
echo "$oriac_fibonacci_time" >> results

cairo_fibonacci_time=$( (time cairo-run --program fibonacci.json) 2>&1 &)
echo -e "\nPython Original VM time:" >> results
echo "$cairo_fibonacci_time" >> results

# Factorial
echo "Compiling Factorial cairo program"
cairo-compile factorial.cairo --output factorial.json

echo -e "* Factorial *\n" >> results
cleo_factorial_time=$( (time ../target/release/cleopatra-run factorial.json) 2>&1 &)
echo -e "\nRust Cleopatra VM time:" >> results
echo "$cleo_factorial_time" >> results

oriac_factorial_time=$( (time oriac/target/release/oriac-run --program factorial.json) 2>&1 &)
echo -e "\nOriac VM factorial time:" >> results
echo "$oriac_factorial_time" >> results

cairo_factorial_time=$( (time cairo-run --program factorial.json) 2>&1 &)
echo -e "\nOriginal Cairo VM time:" >> results
echo "$cairo_factorial_time" >> results

cat results

echo "Cleaning results"
rm results
rm -f fibonacci.json
rm -f factorial.json
rm -rf oriac
