#!/bin/bash

# Define a list of RAYON_NUM_THREADS
thread_counts=(2 4)

# Define binary names
binaries=("hyper_threading_main" "hyper_threading_pr")

# Iter over thread_counts
for threads in "${thread_counts[@]}"; do
    # Initialize hyperfine command
    cmd="hyperfine -r 2"
    
    # Add each binary to the command with the current threads value
    for binary in "${binaries[@]}"; do
        cmd+=" -n \"${binary} threads: ${threads}\" 'RAYON_NUM_THREADS=${threads} ./${binary}'"
    done
    
    # Execute 
    echo "Running benchmark for ${threads} threads"
    echo Hyper Thereading Benchmark results >> result.md
    echo "///////// \n ///////// \n \n "
    echo $cmd >> result.md \n
    eval $cmd >> result.md
done
