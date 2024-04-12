#!/bin/bash

thread_counts=(1 2 4 6 8 10 12 16 24 32 )
binary="target/release/hyper_threading"


cmd="hyperfine -r 1"

for threads in "${thread_counts[@]}"; do
    cmd+=" -n \"threads: ${threads}\" 'sh -c \"RAYON_NUM_THREADS=${threads} ${binary}\"'"
done

# Execute the hyperfine command
echo "Executing benchmark for all thread counts"
eval $cmd
