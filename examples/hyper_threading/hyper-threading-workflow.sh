#!/bin/bash

# Define a list of RAYON_NUM_THREADS
thread_counts=(1 2 4 6 8 16 32)

# Define binary names
binaries=("hyper_threading_main" "hyper_threading_pr")

# Iter over thread_counts
for threads in "${thread_counts[@]}"; do
    # Initialize hyperfine command
    cmd="hyperfine"
    
    # Add each binary to the command with the current threads value
    for binary in "${binaries[@]}"; do
        cmd+=" -n \"${binary} threads: ${threads}\" 'RAYON_NUM_THREADS=${threads} ./${binary}'"
    done
    
    # Execute 
    echo "Running benchmark for ${threads} threads"
    echo $cmd
    eval $cmd
done
