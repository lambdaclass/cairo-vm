#!/bin/bash

rm -rf examples/hyper_threading/hyper_threading_*

#commits
PR_COMMIT="59840b36be82fb7d486939e01799251b3865b97a"
MAIN_COMMIT="c5839fd5b696a58486cde68c394b2f2ca54787d9"

git pull 

## PR
cargo clean
git checkout $PR_COMMIT
git status
cargo build --release -p hyper_threading
mv target/release/hyper_threading examples/hyper_threading/hyper_threading_pr

## MAIN
cargo clean
git checkout $MAIN_COMMIT
git status
cargo build --release -p hyper_threading
mv target/release/hyper_threading examples/hyper_threading/hyper_threading_main

# Define a list of RAYON_NUM_THREADS
thread_counts=(1 2 4 6 8 12 16 32)

# Define binary names
binaries=("examples/hyper_threading/hyper_threading_main" "examples/hyper_threading/hyper_threading_pr")

echo "**Hyper Thereading Benchmark results**"

# Iter over thread_counts
for threads in "${thread_counts[@]}"; do
    # Initialize hyperfine command
    cmd="hyperfine -r 1"
    
    # Add each binary to the command with the current threads value
    for binary in "${binaries[@]}"; do
        cmd+=" -n \"${binary} threads: ${threads}\" 'RAYON_NUM_THREADS=${threads} ./${binary}'"
    done
    
    # Execute 
    echo "Running benchmark for ${threads} threads"
    echo -e $cmd  
    eval $cmd 
done

