#!/bin/bash

thread_counts=(1 2 4 6 8 10 12 14 16 )
binary="./target/release/hyper_threading"


cmd="hyperfine -r 1"

# Build the command string with all thread counts
for threads in "${thread_counts[@]}"; do
    # For hyperfine, wrap each command in 'sh -c' to correctly handle the environment variable
    cmd+=" -n \"threads: ${threads}\" 'sh -c \"RAYON_NUM_THREADS=${threads} ${binary}\"'"
done

# Execute the hyperfine command
echo "Executing benchmark for all thread counts"
eval $cmd